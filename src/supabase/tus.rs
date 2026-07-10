//! TUS 1.0.0 resumable-upload session registry and handlers for
//! `/storage/v1/upload/resumable`.
//!
//! Session state (the partial-upload byte buffer) is held **in memory only**,
//! keyed by an opaque upload id, never persisted through the document store.
//! A table-backed session would replicate every `PATCH` chunk's partial bytes
//! through the replicated store on every request, which is wasteful and
//! pointless: only the *finished* object matters cross-node, and that is
//! written through the same [`crate::supabase::storage::store_object`] path
//! every other upload uses once the transfer completes.
//!
//! Implements the `creation`, `creation-with-upload`, `expiration` and
//! `termination` TUS extensions (see [`TUS_EXTENSIONS`]); `checksum` and
//! `concatenation` are not implemented, and `Upload-Defer-Length` is
//! explicitly rejected rather than silently ignored.

use std::collections::HashMap;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::sql::RelationalStorage;
use crate::supabase::error::SupaError;
use crate::supabase::gateway::{AppState, AuthContext, header_str};
use crate::supabase::storage::{
    MAX_UPLOAD_BYTES, StoreOutcome, ensure_schema, fetch_bucket, mime_allowed,
    normalize_object_name, not_found, storage_error, storage_error_from, store_object,
};

/// The TUS protocol version this gateway implements.
pub const TUS_VERSION: &str = "1.0.0";
/// The TUS extensions this gateway implements. `checksum` / `concatenation`
/// are absent (truthfully — never advertised and never silently ignored).
pub const TUS_EXTENSIONS: &str = "creation,creation-with-upload,expiration,termination";
/// How long an idle resumable-upload session lives before it is swept.
pub const TUS_SESSION_TTL_SECS: i64 = 3600;
/// The maximum number of in-flight resumable-upload sessions held in memory
/// at once (a per-process cap, independent of `MAX_UPLOAD_BYTES`).
pub const MAX_TUS_SESSIONS: usize = 16;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// In-memory registry of in-flight resumable-upload sessions, shared across a
/// gateway process via [`crate::supabase::gateway::AppState`].
#[derive(Default)]
pub struct TusRegistry {
    sessions: Mutex<HashMap<Uuid, TusSession>>,
}

/// One in-flight resumable-upload session: everything needed to finalize the
/// upload once the last byte arrives, plus the principal that may resume it.
struct TusSession {
    bucket: String,
    name: String,
    content_type: String,
    cache_control: String,
    upsert: bool,
    length: usize,
    bytes: Vec<u8>,
    created_role: String,
    created_user: Option<String>,
    expires_at: DateTime<Utc>,
}

/// The outcome of applying a `PATCH` chunk to a session, decided under a
/// single lock acquisition (lookup, principal check, offset/size validation,
/// mutation and — if the upload just completed — removal all happen
/// atomically, so no two concurrent `PATCH`es can both believe they finished
/// the same session).
enum PatchOutcome {
    NotFound,
    WrongOffset(usize),
    TooLarge,
    Progress {
        offset: usize,
        expires_at: DateTime<Utc>,
    },
    Complete(TusSession),
}

impl TusRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove every session whose TTL has elapsed; returns the ids removed
    /// so a handler can tell "just expired" (410) apart from "never existed"
    /// (404) for the *specific* id it cares about, without an existence
    /// oracle for ids other requests never touched.
    fn sweep_expired(&self, now: DateTime<Utc>) -> Vec<Uuid> {
        let mut sessions = self.sessions.lock();
        let expired: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, s)| s.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            sessions.remove(id);
        }
        expired
    }

    /// Backdate a session's expiry so the next handler call observes it as
    /// expired. Test-only escape hatch to exercise the 410 path
    /// deterministically instead of waiting out [`TUS_SESSION_TTL_SECS`];
    /// harmless (and simply unused) outside tests.
    pub fn force_expire(&self, id: &Uuid) {
        if let Some(session) = self.sessions.lock().get_mut(id) {
            session.expires_at = Utc::now() - chrono::Duration::seconds(1);
        }
    }

    fn count(&self) -> usize {
        self.sessions.lock().len()
    }

    fn insert(&self, id: Uuid, session: TusSession) {
        self.sessions.lock().insert(id, session);
    }

    /// Remove a session iff it exists and `auth` is its owning principal
    /// (or `service_role`) — a single lock acquisition so a concurrent
    /// `PATCH`/`DELETE` can never race between checking and removing.
    /// Returns whether it was removed; a principal mismatch renders
    /// identically to "absent" (`false`), same as everywhere else in TUS.
    fn remove_if_matches(&self, id: &Uuid, auth: &AuthContext) -> bool {
        let mut sessions = self.sessions.lock();
        match sessions.get(id) {
            Some(session) if principal_matches(auth, session) => {
                sessions.remove(id);
                true
            }
            _ => false,
        }
    }

    /// Read-only snapshot of a session's externally-visible state, gated by
    /// the principal check (a mismatch renders identically to "not found").
    fn peek(&self, id: &Uuid, auth: &AuthContext) -> Option<HeadSnapshot> {
        let sessions = self.sessions.lock();
        let session = sessions.get(id)?;
        if !principal_matches(auth, session) {
            return None;
        }
        Some(HeadSnapshot {
            offset: session.bytes.len(),
            length: session.length,
            expires_at: session.expires_at,
        })
    }

    /// Validate and apply one `PATCH` chunk under a single lock acquisition.
    fn apply_patch(
        &self,
        id: &Uuid,
        auth: &AuthContext,
        offset: usize,
        chunk: &[u8],
    ) -> PatchOutcome {
        let mut sessions = self.sessions.lock();
        let Some(session) = sessions.get(id) else {
            return PatchOutcome::NotFound;
        };
        if !principal_matches(auth, session) {
            return PatchOutcome::NotFound;
        }
        let current_len = session.bytes.len();
        let target_len = session.length;
        if offset != current_len {
            return PatchOutcome::WrongOffset(current_len);
        }
        if offset + chunk.len() > target_len {
            return PatchOutcome::TooLarge;
        }
        let session_mut = sessions.get_mut(id).expect("looked up above");
        session_mut.bytes.extend_from_slice(chunk);
        let new_offset = session_mut.bytes.len();
        let expires_at = session_mut.expires_at;
        if new_offset == target_len {
            PatchOutcome::Complete(sessions.remove(id).expect("looked up above"))
        } else {
            PatchOutcome::Progress {
                offset: new_offset,
                expires_at,
            }
        }
    }
}

struct HeadSnapshot {
    offset: usize,
    length: usize,
    expires_at: DateTime<Utc>,
}

/// Does `auth` carry the same principal that created `session` (same role
/// and, if the creating request had one, the same user id)? `service_role`
/// always bypasses the check, matching every other storage RLS escape hatch.
fn principal_matches(auth: &AuthContext, session: &TusSession) -> bool {
    auth.is_service_role()
        || (auth.role == session.created_role && auth.user_id() == session.created_user.as_deref())
}

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

/// Every TUS response — success or error — carries `Tus-Resumable`.
fn with_tus_resumable(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert("tus-resumable", HeaderValue::from_static(TUS_VERSION));
    resp
}

/// Run a TUS handler body, converting infrastructure errors to the storage
/// error shape and stamping `Tus-Resumable` on the way out (success or
/// error alike).
async fn run_tus<F>(fut: F) -> Response
where
    F: Future<Output = Result<Response, SupaError>>,
{
    with_tus_resumable(fut.await.unwrap_or_else(storage_error_from))
}

/// A header value built from a value we generated ourselves (ASCII digits or
/// an RFC 7231 date), never from untrusted input — safe to `expect`.
fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).expect("internally generated TUS header value is a valid header value")
}

/// Format a UTC timestamp as an RFC 7231 HTTP-date (`Upload-Expires`).
fn http_date(dt: DateTime<Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn location_header<S: RelationalStorage + 'static>(state: &AppState<S>, id: Uuid) -> HeaderValue {
    let base = state.project.api_url.trim_end_matches('/');
    hv(&format!("{base}/storage/v1/upload/resumable/{id}"))
}

/// Finalize a completed session: hand its accumulated bytes to the same
/// write path every other upload uses. Shared by `create` (creation-with-
/// upload completing in one shot) and `patch` (the chunk that reaches the
/// target length).
async fn finalize<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    session: &TusSession,
) -> Result<StoreOutcome, SupaError> {
    store_object(
        state,
        auth,
        &session.bucket,
        &session.name,
        &session.content_type,
        &session.cache_control,
        session.upsert,
        &session.bytes,
    )
    .await
}

// ---------------------------------------------------------------------------
// Upload-Metadata parsing
// ---------------------------------------------------------------------------

/// Parse a TUS `Upload-Metadata` header: comma-separated `"key
/// base64value"` pairs (a bare key with no value is TUS-legal and parses to
/// an empty string). Values are base64-decoded with the STANDARD engine —
/// the same engine `src/relational/value.rs` uses, and what real
/// tus-js-client sends.
fn parse_upload_metadata(raw: &str) -> Result<HashMap<String, String>, String> {
    use base64::Engine;
    let mut map = HashMap::new();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(map);
    }
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, ' ');
        let key = it.next().unwrap_or("").trim();
        if key.is_empty() {
            return Err(format!("empty key in Upload-Metadata pair {pair:?}"));
        }
        let value = match it.next().map(str::trim).filter(|v| !v.is_empty()) {
            Some(encoded) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|e| format!("invalid base64 for Upload-Metadata key {key:?}: {e}"))?;
                String::from_utf8(decoded).map_err(|e| {
                    format!("Upload-Metadata value for key {key:?} is not valid UTF-8: {e}")
                })?
            }
            None => String::new(),
        };
        map.insert(key.to_string(), value);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `OPTIONS /storage/v1/upload/resumable[/{id}]` — capability discovery.
/// Stateless: no session lookup, no auth requirement beyond the apikey layer
/// already in front of the whole router.
pub async fn capabilities() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let headers = resp.headers_mut();
    headers.insert("tus-resumable", HeaderValue::from_static(TUS_VERSION));
    headers.insert("tus-version", HeaderValue::from_static(TUS_VERSION));
    headers.insert("tus-extension", HeaderValue::from_static(TUS_EXTENSIONS));
    headers.insert("tus-max-size", hv(&MAX_UPLOAD_BYTES.to_string()));
    resp
}

/// `POST /storage/v1/upload/resumable` — `creation` and
/// `creation-with-upload`.
pub async fn create<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_tus(async move {
        if header_str(&headers, "tus-resumable") != Some(TUS_VERSION) {
            let mut resp = storage_error(
                StatusCode::PRECONDITION_FAILED,
                "tus_precondition_failed",
                "the Tus-Resumable header must be 1.0.0",
            );
            resp.headers_mut()
                .insert("tus-version", HeaderValue::from_static(TUS_VERSION));
            return Ok(resp);
        }
        if header_str(&headers, "upload-defer-length") == Some("1") {
            return Ok(storage_error(
                StatusCode::NOT_IMPLEMENTED,
                "SUPA_COMPAT_STORAGE_TUS_DEFER_LENGTH_UNSUPPORTED",
                "the creation-defer-length TUS extension is not implemented; declare \
                 Upload-Length up front",
            ));
        }
        let Some(length) =
            header_str(&headers, "upload-length").and_then(|v| v.parse::<usize>().ok())
        else {
            return Ok(storage_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Upload-Length header is required and must be a non-negative integer",
            ));
        };
        if length > MAX_UPLOAD_BYTES {
            return Ok(storage_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "Upload-Length exceeds the maximum accepted upload size",
            ));
        }

        let metadata =
            match parse_upload_metadata(header_str(&headers, "upload-metadata").unwrap_or("")) {
                Ok(m) => m,
                Err(reason) => {
                    return Ok(storage_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_upload_metadata",
                        &reason,
                    ));
                }
            };
        let Some(bucket) = metadata.get("bucketName").filter(|s| !s.is_empty()) else {
            return Ok(storage_error(
                StatusCode::BAD_REQUEST,
                "invalid_upload_metadata",
                "Upload-Metadata must include a non-empty bucketName",
            ));
        };
        let bucket = bucket.clone();
        let Some(object_name_raw) = metadata.get("objectName").filter(|s| !s.is_empty()) else {
            return Ok(storage_error(
                StatusCode::BAD_REQUEST,
                "invalid_upload_metadata",
                "Upload-Metadata must include a non-empty objectName",
            ));
        };
        let name = normalize_object_name(object_name_raw)?;
        let content_type = metadata
            .get("contentType")
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let cache_control = metadata
            .get("cacheControl")
            .cloned()
            .unwrap_or_else(|| "no-cache".to_string());
        let upsert = header_str(&headers, "x-upsert")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        ensure_schema(&state).await?;
        let Some(bucket_row) = fetch_bucket(&state, &bucket).await? else {
            return Ok(not_found("Bucket not found"));
        };
        if let Some(allowed) = bucket_row
            .get("allowed_mime_types")
            .and_then(serde_json::Value::as_array)
            && !mime_allowed(&content_type, allowed)
        {
            return Ok(storage_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_mime_type",
                &format!("mime type {content_type} is not supported"),
            ));
        }
        if let Some(limit) = bucket_row
            .get("file_size_limit")
            .and_then(serde_json::Value::as_i64)
            && (length as i64) > limit
        {
            return Ok(storage_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "Upload-Length exceeds the bucket's file_size_limit",
            ));
        }

        let now = Utc::now();
        state.tus.sweep_expired(now);
        if state.tus.count() >= MAX_TUS_SESSIONS {
            return Ok(storage_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_uploads",
                "too many in-flight resumable uploads; retry later",
            ));
        }

        // `creation-with-upload`: an optional inline body seeds the buffer.
        let mut buffer = Vec::with_capacity(length.min(MAX_UPLOAD_BYTES));
        if !body.is_empty() {
            if header_str(&headers, "content-type") != Some("application/offset+octet-stream") {
                return Ok(storage_error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "invalid_content_type",
                    "creation-with-upload requires Content-Type: application/offset+octet-stream",
                ));
            }
            if body.len() > length {
                return Ok(storage_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Payload too large",
                    "the request body exceeds Upload-Length",
                ));
            }
            buffer.extend_from_slice(&body);
        }

        let id = Uuid::new_v4();
        let expires_at = now + chrono::Duration::seconds(TUS_SESSION_TTL_SECS);
        let session = TusSession {
            bucket,
            name,
            content_type,
            cache_control,
            upsert,
            length,
            bytes: buffer,
            created_role: auth.role.clone(),
            created_user: auth.user_id().map(str::to_string),
            expires_at,
        };

        // creation-with-upload completing in one shot.
        if session.bytes.len() == length {
            return match finalize(&state, &auth, &session).await? {
                StoreOutcome::Stored(_object_id) => {
                    let mut resp = StatusCode::CREATED.into_response();
                    let h = resp.headers_mut();
                    h.insert("location", location_header(&state, id));
                    h.insert("upload-expires", hv(&http_date(expires_at)));
                    h.insert("upload-offset", hv(&length.to_string()));
                    Ok(resp)
                }
                StoreOutcome::Refused(resp) => Ok(resp),
            };
        }

        let offset = session.bytes.len();
        state.tus.insert(id, session);
        let mut resp = StatusCode::CREATED.into_response();
        let h = resp.headers_mut();
        h.insert("location", location_header(&state, id));
        h.insert("upload-expires", hv(&http_date(expires_at)));
        if offset > 0 {
            h.insert("upload-offset", hv(&offset.to_string()));
        }
        Ok(resp)
    })
    .await
}

/// `HEAD /storage/v1/upload/resumable/{id}` — progress check.
pub async fn head<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    let now = Utc::now();
    let removed = state.tus.sweep_expired(now);
    let Ok(id) = Uuid::parse_str(&id) else {
        return with_tus_resumable(not_found("Upload not found"));
    };
    match state.tus.peek(&id, &auth) {
        Some(snapshot) => {
            let mut resp = StatusCode::OK.into_response();
            let h = resp.headers_mut();
            h.insert("upload-offset", hv(&snapshot.offset.to_string()));
            h.insert("upload-length", hv(&snapshot.length.to_string()));
            h.insert("cache-control", HeaderValue::from_static("no-store"));
            h.insert("upload-expires", hv(&http_date(snapshot.expires_at)));
            with_tus_resumable(resp)
        }
        None if removed.contains(&id) => with_tus_resumable(storage_error(
            StatusCode::GONE,
            "upload_expired",
            "the upload session has expired",
        )),
        None => with_tus_resumable(not_found("Upload not found")),
    }
}

/// `PATCH /storage/v1/upload/resumable/{id}` — append a chunk, finalizing
/// the object once the accumulated bytes reach `Upload-Length`.
pub async fn patch<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_tus(async move {
        if header_str(&headers, "content-type") != Some("application/offset+octet-stream") {
            return Ok(storage_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_content_type",
                "PATCH requires Content-Type: application/offset+octet-stream",
            ));
        }
        let Some(offset) =
            header_str(&headers, "upload-offset").and_then(|v| v.parse::<usize>().ok())
        else {
            return Ok(storage_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Upload-Offset header is required and must be a non-negative integer",
            ));
        };

        let now = Utc::now();
        let removed = state.tus.sweep_expired(now);
        let Ok(id) = Uuid::parse_str(&id) else {
            return Ok(not_found("Upload not found"));
        };

        match state.tus.apply_patch(&id, &auth, offset, &body) {
            PatchOutcome::NotFound if removed.contains(&id) => Ok(storage_error(
                StatusCode::GONE,
                "upload_expired",
                "the upload session has expired",
            )),
            PatchOutcome::NotFound => Ok(not_found("Upload not found")),
            PatchOutcome::WrongOffset(current) => {
                let mut resp = storage_error(
                    StatusCode::CONFLICT,
                    "offset_mismatch",
                    "Upload-Offset does not match the server's current offset",
                );
                resp.headers_mut()
                    .insert("upload-offset", hv(&current.to_string()));
                Ok(resp)
            }
            PatchOutcome::TooLarge => Ok(storage_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "the chunk would extend the upload past Upload-Length",
            )),
            PatchOutcome::Progress { offset, expires_at } => {
                let mut resp = StatusCode::NO_CONTENT.into_response();
                let h = resp.headers_mut();
                h.insert("upload-offset", hv(&offset.to_string()));
                h.insert("upload-expires", hv(&http_date(expires_at)));
                Ok(resp)
            }
            PatchOutcome::Complete(session) => {
                let length = session.length;
                match finalize(&state, &auth, &session).await? {
                    StoreOutcome::Stored(_object_id) => {
                        let mut resp = StatusCode::NO_CONTENT.into_response();
                        resp.headers_mut()
                            .insert("upload-offset", hv(&length.to_string()));
                        Ok(resp)
                    }
                    StoreOutcome::Refused(resp) => Ok(resp),
                }
            }
        }
    })
    .await
}

/// `DELETE /storage/v1/upload/resumable/{id}` — termination.
pub async fn terminate<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    let now = Utc::now();
    let removed = state.tus.sweep_expired(now);
    let Ok(id) = Uuid::parse_str(&id) else {
        return with_tus_resumable(not_found("Upload not found"));
    };
    if state.tus.remove_if_matches(&id, &auth) {
        return with_tus_resumable(StatusCode::NO_CONTENT.into_response());
    }
    if removed.contains(&id) {
        with_tus_resumable(storage_error(
            StatusCode::GONE,
            "upload_expired",
            "the upload session has expired",
        ))
    } else {
        with_tus_resumable(not_found("Upload not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upload_metadata_valid_pairs() {
        // "a.txt" and "bucket" base64-encoded with the STANDARD engine.
        let raw = "bucketName YnVja2V0,objectName YS50eHQ=";
        let m = parse_upload_metadata(raw).unwrap();
        assert_eq!(m.get("bucketName").unwrap(), "bucket");
        assert_eq!(m.get("objectName").unwrap(), "a.txt");
    }

    #[test]
    fn parse_upload_metadata_bare_key_is_empty_value() {
        let m = parse_upload_metadata("isPublic").unwrap();
        assert_eq!(m.get("isPublic").unwrap(), "");
    }

    #[test]
    fn parse_upload_metadata_bad_base64_is_err() {
        assert!(parse_upload_metadata("objectName not-base64!!!").is_err());
    }

    #[test]
    fn parse_upload_metadata_missing_required_keys_still_parses() {
        let m = parse_upload_metadata("objectName YS50eHQ=").unwrap();
        assert!(!m.contains_key("bucketName"));
        assert_eq!(m.get("objectName").unwrap(), "a.txt");
    }

    #[test]
    fn parse_upload_metadata_empty_header_is_empty_map() {
        assert!(parse_upload_metadata("").unwrap().is_empty());
    }

    #[test]
    fn http_date_format() {
        let dt = DateTime::parse_from_rfc3339("2026-07-10T15:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(http_date(dt), "Fri, 10 Jul 2026 15:04:05 GMT");
    }
}
