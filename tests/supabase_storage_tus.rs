//! Integration tests for TUS 1.0.0 resumable uploads and
//! `multipart/form-data` object uploads under `/storage/v1`.
//!
//! Follows the same in-process `tower::ServiceExt::oneshot` harness pattern
//! as `tests/supabase_storage_realtime.rs`.

#![cfg(feature = "supabase")]

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use serde_json::{Value, json};
use tower::ServiceExt;

use guardian_db::sql::MemoryStorage;
use guardian_db::sql::engine::{Database, Session};
use guardian_db::supabase::project::ProjectKeys;
use guardian_db::supabase::tus::TusRegistry;
use guardian_db::supabase::{AppState, ServiceConfig, SupabaseCompatProject, build_router};

const TEST_SECRET: &str = "integration-test-jwt-secret-value-0123456789";
const IAT: i64 = 1_700_000_000;
const UID_A: &str = "0b9fbc1e-6a34-4bff-8df5-6b9f7c4e3d21";

struct Harness {
    app: Router,
    anon: String,
    service: String,
    db: Arc<Database<MemoryStorage>>,
    tus: Arc<TusRegistry>,
}

async fn harness() -> Harness {
    let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "app"));
    let keys = ProjectKeys::from_secret(TEST_SECRET, IAT).unwrap();
    let anon = keys.anon_key.clone();
    let service = keys.service_role_key.clone();
    let project =
        SupabaseCompatProject::shell("app", "http://127.0.0.1:54321", keys, chrono::Utc::now());
    let state = AppState::new(db.clone(), project, ServiceConfig::default());
    let tus = state.tus.clone();
    let app = build_router(state);
    Harness {
        app,
        anon,
        service,
        db,
        tus,
    }
}

/// Mint a real user access token (`role: authenticated`, `sub: <uuid>`).
fn user_token(sub: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = guardian_db::supabase::Claims::api_key("authenticated", now, now + 3600);
    claims.sub = Some(sub.to_string());
    claims.aud = Some("authenticated".to_string());
    guardian_db::supabase::jwt::sign(&claims, TEST_SECRET).unwrap()
}

/// Send a request with arbitrary headers and a raw body; return
/// `(status, headers, body bytes)`.
async fn call_raw(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(body.map(Body::from).unwrap_or_else(Body::empty))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, resp_headers, bytes.to_vec())
}

/// JSON-bodied convenience wrapper around [`call_raw`].
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    apikey: Option<&str>,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(k) = apikey {
        headers.push(("apikey".into(), k.to_string()));
    }
    if let Some(b) = bearer {
        headers.push(("authorization".into(), format!("Bearer {b}")));
    }
    if body.is_some() {
        headers.push(("content-type".into(), "application/json".into()));
    }
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (status, _h, bytes) = call_raw(
        app,
        method,
        uri,
        &header_refs,
        body.map(|v| v.to_string().into_bytes()),
    )
    .await;
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn create_bucket(h: &Harness, key: &str, name: &str, body: Value) -> (StatusCode, Value) {
    let mut b = body;
    b["name"] = json!(name);
    call(
        &h.app,
        "POST",
        "/storage/v1/bucket",
        Some(key),
        None,
        Some(b),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn upload_raw(
    h: &Harness,
    key: &str,
    bearer: Option<&str>,
    bucket: &str,
    path: &str,
    content_type: &str,
    bytes: &[u8],
    upsert: bool,
) -> (StatusCode, Value) {
    let auth_header;
    let mut headers: Vec<(&str, &str)> = vec![("apikey", key), ("content-type", content_type)];
    if let Some(b) = bearer {
        auth_header = format!("Bearer {b}");
        headers.push(("authorization", auth_header.as_str()));
    }
    if upsert {
        headers.push(("x-upsert", "true"));
    }
    let (status, _h, body) = call_raw(
        &h.app,
        "POST",
        &format!("/storage/v1/object/{bucket}/{path}"),
        &headers,
        Some(bytes.to_vec()),
    )
    .await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// base64 (STANDARD engine) encode, matching what tus-js-client sends in
/// `Upload-Metadata`.
fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn upload_metadata(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k} {}", b64(v)))
        .collect::<Vec<_>>()
        .join(",")
}

/// TUS creation POST (no inline body). Returns `(status, headers)`.
async fn tus_create(
    h: &Harness,
    apikey: &str,
    bearer: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap) {
    let auth_header;
    let mut headers: Vec<(&str, &str)> = vec![("apikey", apikey), ("tus-resumable", "1.0.0")];
    if let Some(b) = bearer {
        auth_header = format!("Bearer {b}");
        headers.push(("authorization", auth_header.as_str()));
    }
    headers.extend_from_slice(extra_headers);
    let (status, h, _b) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/upload/resumable",
        &headers,
        None,
    )
    .await;
    (status, h)
}

fn location_id(headers: &HeaderMap) -> String {
    let loc = headers.get("location").unwrap().to_str().unwrap();
    loc.rsplit('/').next().unwrap().to_string()
}

// ===========================================================================
// TUS: capabilities
// ===========================================================================

#[tokio::test]
async fn tus_options_advertises_capabilities() {
    let h = harness().await;
    let (status, headers, _b) = call_raw(
        &h.app,
        "OPTIONS",
        "/storage/v1/upload/resumable",
        &[("apikey", h.anon.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers.get("tus-resumable").unwrap(), "1.0.0");
    assert_eq!(headers.get("tus-version").unwrap(), "1.0.0");
    assert_eq!(
        headers.get("tus-extension").unwrap(),
        "creation,creation-with-upload,expiration,termination"
    );
    assert_eq!(headers.get("tus-max-size").unwrap(), "52428800");
}

// ===========================================================================
// TUS: creation / head / patch roundtrip
// ===========================================================================

#[tokio::test]
async fn tus_create_head_patch_roundtrip() {
    let h = harness().await;
    create_bucket(&h, &h.service, "up", json!({})).await;

    let payload = b"0123456789ABCDEF"; // 16 bytes
    let metadata = upload_metadata(&[
        ("bucketName", "up"),
        ("objectName", "roundtrip.bin"),
        ("contentType", "application/octet-stream"),
    ]);
    let (status, headers) = tus_create(
        &h,
        &h.service,
        None,
        &[
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("tus-resumable").unwrap(), "1.0.0");
    assert!(headers.get("location").is_some());
    assert!(headers.get("upload-expires").is_some());
    assert!(headers.get("upload-offset").is_none()); // no creation-time bytes.
    let id = location_id(&headers);
    let upload_url = format!("/storage/v1/upload/resumable/{id}");

    // HEAD: offset 0.
    let (status, headers, _b) = call_raw(
        &h.app,
        "HEAD",
        &upload_url,
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("upload-offset").unwrap(), "0");
    assert_eq!(headers.get("upload-length").unwrap(), "16");
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");

    // PATCH chunk 1 (first 8 bytes) at offset 0 -> 204, new offset 8.
    let (status, headers, _b) = call_raw(
        &h.app,
        "PATCH",
        &upload_url,
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload[..8].to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers.get("upload-offset").unwrap(), "8");

    // PATCH with a STALE offset (0 again) -> 409 offset_mismatch, current offset in header.
    let (status, headers, bytes) = call_raw(
        &h.app,
        "PATCH",
        &upload_url,
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload[..8].to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(headers.get("upload-offset").unwrap(), "8");
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "offset_mismatch");

    // PATCH the remainder at the correct offset -> 204, offset == length.
    let (status, headers, _b) = call_raw(
        &h.app,
        "PATCH",
        &upload_url,
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "8"),
        ],
        Some(payload[8..].to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers.get("upload-offset").unwrap(), "16");

    // The finalized object is downloadable with the exact bytes + content-type.
    let (status, headers, bytes) = call_raw(
        &h.app,
        "GET",
        "/storage/v1/object/up/roundtrip.bin",
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, payload);
    assert_eq!(
        headers.get("content-type").unwrap().to_str().unwrap(),
        "application/octet-stream"
    );

    // The session is consumed: HEAD on the same id is now 404.
    let (status, _h2, _b) = call_raw(
        &h.app,
        "HEAD",
        &upload_url,
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ===========================================================================
// TUS: creation-with-upload
// ===========================================================================

#[tokio::test]
async fn tus_creation_with_upload_single_post() {
    let h = harness().await;
    create_bucket(&h, &h.service, "up", json!({})).await;
    let payload = b"all-in-one-shot";
    let metadata = upload_metadata(&[
        ("bucketName", "up"),
        ("objectName", "inline.bin"),
        ("contentType", "text/plain"),
    ]);
    let (status, headers, _b) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/upload/resumable",
        &[
            ("apikey", h.service.as_str()),
            ("tus-resumable", "1.0.0"),
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
            ("content-type", "application/offset+octet-stream"),
        ],
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers.get("upload-offset").unwrap().to_str().unwrap(),
        payload.len().to_string()
    );
    assert!(headers.get("location").is_some());

    let (status, _h2, bytes) = call_raw(
        &h.app,
        "GET",
        "/storage/v1/object/up/inline.bin",
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, payload);
}

// ===========================================================================
// TUS: duplicate / upsert
// ===========================================================================

#[tokio::test]
async fn tus_duplicate_needs_upsert() {
    let h = harness().await;
    create_bucket(&h, &h.service, "up", json!({})).await;
    let (status, _b) = upload_raw(
        &h,
        &h.service,
        None,
        "up",
        "dup.txt",
        "text/plain",
        b"original",
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // TUS-upload to the same key without upsert: finalize -> 409.
    let payload = b"tus-bytes";
    let metadata = upload_metadata(&[
        ("bucketName", "up"),
        ("objectName", "dup.txt"),
        ("contentType", "text/plain"),
    ]);
    let (status, headers) = tus_create(
        &h,
        &h.service,
        None,
        &[
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    let (status, _h2, bytes) = call_raw(
        &h.app,
        "PATCH",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "Duplicate");

    // Retry with x-upsert: true on creation -> success, bytes replaced.
    let (status, headers) = tus_create(
        &h,
        &h.service,
        None,
        &[
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
            ("x-upsert", "true"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    let (status, _h2, _b) = call_raw(
        &h.app,
        "PATCH",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_s, _h2, bytes) = call_raw(
        &h.app,
        "GET",
        "/storage/v1/object/up/dup.txt",
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(bytes, payload);
}

// ===========================================================================
// TUS: typed failures
// ===========================================================================

#[tokio::test]
async fn tus_typed_failures() {
    let h = harness().await;
    create_bucket(&h, &h.service, "up", json!({})).await;
    create_bucket(
        &h,
        &h.service,
        "strict",
        json!({"file_size_limit": 8, "allowed_mime_types": ["text/plain"]}),
    )
    .await;

    // (a) creation without Tus-Resumable -> 412.
    let (status, h2, bytes) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/upload/resumable",
        &[("apikey", h.service.as_str()), ("upload-length", "4")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h2.get("tus-version").unwrap(), "1.0.0");
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "tus_precondition_failed");

    // (b) Upload-Defer-Length: 1 -> 501 with the exact code.
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/upload/resumable",
        &[
            ("apikey", h.service.as_str()),
            ("tus-resumable", "1.0.0"),
            ("upload-defer-length", "1"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        body["error"],
        "SUPA_COMPAT_STORAGE_TUS_DEFER_LENGTH_UNSUPPORTED"
    );

    // (c) missing bucketName in metadata -> 400 invalid_upload_metadata.
    let metadata = upload_metadata(&[("objectName", "a.txt")]);
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/upload/resumable",
        &[
            ("apikey", h.service.as_str()),
            ("tus-resumable", "1.0.0"),
            ("upload-length", "4"),
            ("upload-metadata", &metadata),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "invalid_upload_metadata");

    // (d) Upload-Length over a strict bucket's file_size_limit -> 413 at creation.
    let metadata = upload_metadata(&[
        ("bucketName", "strict"),
        ("objectName", "big.txt"),
        ("contentType", "text/plain"),
    ]);
    let (status, _headers) = tus_create(
        &h,
        &h.service,
        None,
        &[("upload-length", "9999"), ("upload-metadata", &metadata)],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // (e) disallowed contentType metadata on a mime-restricted bucket -> 415.
    let metadata = upload_metadata(&[
        ("bucketName", "strict"),
        ("objectName", "x.json"),
        ("contentType", "application/json"),
    ]);
    let (status, _headers) = tus_create(
        &h,
        &h.service,
        None,
        &[("upload-length", "2"), ("upload-metadata", &metadata)],
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // (f) PATCH with wrong Content-Type -> 415 invalid_content_type.
    let metadata = upload_metadata(&[
        ("bucketName", "up"),
        ("objectName", "ct.bin"),
        ("contentType", "application/octet-stream"),
    ]);
    let (status, headers) = tus_create(
        &h,
        &h.service,
        None,
        &[("upload-length", "4"), ("upload-metadata", &metadata)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    let (status, _h2, raw) = call_raw(
        &h.app,
        "PATCH",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[
            ("apikey", h.service.as_str()),
            ("content-type", "text/plain"),
            ("upload-offset", "0"),
        ],
        Some(b"ab".to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "invalid_content_type");

    // (g) unknown upload id -> 404.
    let (status, _h2, _b) = call_raw(
        &h.app,
        "HEAD",
        "/storage/v1/upload/resumable/00000000-0000-0000-0000-000000000000",
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // (h) force_expire then HEAD -> 410 upload_expired.
    let metadata = upload_metadata(&[
        ("bucketName", "up"),
        ("objectName", "expiring.bin"),
        ("contentType", "application/octet-stream"),
    ]);
    let (status, headers) = tus_create(
        &h,
        &h.service,
        None,
        &[("upload-length", "4"), ("upload-metadata", &metadata)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    h.tus.force_expire(&id.parse::<uuid::Uuid>().unwrap());
    // HEAD responses never carry a body (RFC 7231); assert on the status +
    // Tus-Resumable header only. The identical error body shape is already
    // exercised on the PATCH/DELETE paths elsewhere in this suite.
    let (status, headers, _raw) = call_raw(
        &h.app,
        "HEAD",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(headers.get("tus-resumable").unwrap(), "1.0.0");
}

// ===========================================================================
// TUS: RLS at finalize time
// ===========================================================================

/// Owner-scoped policies on storage.objects for `authenticated`, matching
/// `tests/supabase_storage_realtime.rs`'s `seed_owner_policies`.
async fn seed_owner_policies(h: &Harness) {
    create_bucket(h, &h.service, "mine", json!({})).await;
    let mut s = Session::new(h.db.clone(), "postgres");
    s.execute(
        "CREATE POLICY obj_owner_select ON storage.objects FOR SELECT TO authenticated \
             USING (owner = auth.uid());
         CREATE POLICY obj_owner_insert ON storage.objects FOR INSERT TO authenticated \
             WITH CHECK (owner = auth.uid());
         CREATE POLICY obj_owner_delete ON storage.objects FOR DELETE TO authenticated \
             USING (owner = auth.uid())",
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tus_rls_finalize_denied() {
    let h = harness().await;
    seed_owner_policies(&h).await;

    // anon: completes the byte transfer, but the final PATCH is denied by RLS.
    let payload = b"anon-bytes";
    let metadata = upload_metadata(&[
        ("bucketName", "mine"),
        ("objectName", "anon.bin"),
        ("contentType", "application/octet-stream"),
    ]);
    let (status, headers) = tus_create(
        &h,
        &h.anon,
        None,
        &[
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    let (status, _h2, raw) = call_raw(
        &h.app,
        "PATCH",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[
            ("apikey", h.anon.as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "42501");

    // No object/blob row was created: listing (service_role) is empty.
    let (_s, body) = call(
        &h.app,
        "POST",
        "/storage/v1/object/list/mine",
        Some(&h.service),
        None,
        Some(json!({"prefix": ""})),
    )
    .await;
    assert_eq!(body, json!([]));

    // A real user's TUS upload succeeds; the resulting object's owner is theirs.
    let token = user_token(UID_A);
    let (status, headers) = tus_create(
        &h,
        &h.anon,
        Some(&token),
        &[
            ("upload-length", &payload.len().to_string()),
            ("upload-metadata", &metadata),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = location_id(&headers);
    let (status, _h2, _b) = call_raw(
        &h.app,
        "PATCH",
        &format!("/storage/v1/upload/resumable/{id}"),
        &[
            ("apikey", h.anon.as_str()),
            ("authorization", format!("Bearer {token}").as_str()),
            ("content-type", "application/offset+octet-stream"),
            ("upload-offset", "0"),
        ],
        Some(payload.to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_s, body) = call(
        &h.app,
        "POST",
        "/storage/v1/object/list/mine",
        Some(&h.service),
        None,
        Some(json!({"prefix": ""})),
    )
    .await;
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "anon.bin");
    assert_eq!(arr[0]["owner"], UID_A);
}

// ===========================================================================
// multipart/form-data
// ===========================================================================

/// Build a `multipart/form-data` body with a file part (name="file",
/// filename set, given content-type) and an optional `cacheControl` text
/// field.
fn build_multipart(
    boundary: &str,
    filename: &str,
    file_content_type: &str,
    file_bytes: &[u8],
    cache_control: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(format!("Content-Type: {file_content_type}\r\n\r\n").as_bytes());
    out.extend_from_slice(file_bytes);
    out.extend_from_slice(b"\r\n");
    if let Some(cc) = cache_control {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"cacheControl\"\r\n\r\n");
        out.extend_from_slice(cc.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[tokio::test]
async fn multipart_upload_roundtrip() {
    let h = harness().await;
    create_bucket(&h, &h.service, "mp", json!({})).await;
    let boundary = "GuardianBoundary123";
    let png_bytes = b"\x89PNG\r\n\x1a\nfakepngdata";
    let body = build_multipart(
        boundary,
        "pic.png",
        "image/png",
        png_bytes,
        Some("max-age=120"),
    );

    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/mp/pic.png",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&raw));
    let resp: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(resp["Key"], "mp/pic.png");
    assert!(resp["Id"].is_string());

    let (status, headers, bytes) = call_raw(
        &h.app,
        "GET",
        "/storage/v1/object/mp/pic.png",
        &[("apikey", h.service.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, png_bytes);
    assert_eq!(
        headers.get("content-type").unwrap().to_str().unwrap(),
        "image/png"
    );
    assert_eq!(
        headers.get("cache-control").unwrap().to_str().unwrap(),
        "max-age=120"
    );
}

#[tokio::test]
async fn multipart_malformed_and_limits() {
    let h = harness().await;
    create_bucket(&h, &h.service, "mp", json!({})).await;
    create_bucket(
        &h,
        &h.service,
        "strict",
        json!({"file_size_limit": 8, "allowed_mime_types": ["text/plain"]}),
    )
    .await;
    let boundary = "B1";

    // (a) broken framing (missing final delimiter) -> 400 invalid_multipart.
    let mut broken = Vec::new();
    broken.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    broken.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhi\r\n",
    );
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/mp/broken.txt",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(broken),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "invalid_multipart");

    // (b) zero file parts -> 400.
    let mut no_file = Vec::new();
    no_file.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    no_file.extend_from_slice(b"Content-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n");
    no_file.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/mp/nofile.txt",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(no_file),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "invalid_multipart");

    // (c) two file parts -> 400.
    let mut two_files = Vec::new();
    two_files.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    two_files.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n\r\nA\r\n",
    );
    two_files.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    two_files.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file2\"; filename=\"b.txt\"\r\n\r\nB\r\n",
    );
    two_files.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/mp/two.txt",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(two_files),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(body["error"], "invalid_multipart");

    // (d) file part exceeding the bucket's file_size_limit -> 413.
    let big = build_multipart(
        boundary,
        "big.txt",
        "text/plain",
        b"way more than eight bytes",
        None,
    );
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/strict/big.txt",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(big),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        String::from_utf8_lossy(&raw)
    );

    // (e) disallowed part content-type -> 415.
    let json_part = build_multipart(boundary, "x.json", "application/json", b"{}", None);
    let (status, _h2, raw) = call_raw(
        &h.app,
        "POST",
        "/storage/v1/object/strict/x.json",
        &[
            ("apikey", h.service.as_str()),
            (
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            ),
        ],
        Some(json_part),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "{}",
        String::from_utf8_lossy(&raw)
    );
}
