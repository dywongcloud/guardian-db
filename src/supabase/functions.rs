//! Supabase Edge Functions-compatible service with two runtime substrates.
//!
//! Speaks the two halves of Supabase's Functions surface:
//!
//! * `/functions/v1/{slug}` — the **invocation** endpoint every Supabase client
//!   library posts to. Verifies the caller (default `verify_jwt=true`, matching
//!   the CLI), fetches the deployed body for `slug`, and runs it under the
//!   [`FunctionRuntime`] detected at deploy time, with the caller's request
//!   folded into an [`InvocationInput`] envelope. The guest returns an
//!   [`InvocationOutput`] envelope (status + headers + body) which is
//!   rendered as the HTTP response. Supports `GET`, `POST`, `PUT`, `PATCH`,
//!   `DELETE` and the CORS `OPTIONS` preflight (204).
//!
//! * `/functions/v1/_admin/*` — the **management** endpoints Supabase's CLI
//!   (`supabase functions deploy|list|delete`) and Studio talk to. All admin
//!   routes require `service_role`; every mutation goes through parameterised
//!   SQL against the `functions` schema (bootstrapped on first use).
//!
//! ## Runtime substrates
//!
//! A deployed body is sniffed at deploy time (see [`FunctionRuntime`]) and
//! stored with a `runtime` tag — no separate "which runtime" field for the
//! caller to set:
//!
//! * **`wasm`** — a WebAssembly module (starts with the `\0asm` magic) using
//!   the Guardian Compute ABI (`gdb_alloc` + a `handler` export with
//!   signature `(ptr, len) -> i64` where the return packs `(out_ptr << 32) |
//!   out_len`). Runs inside [`crate::compute::WasmRuntime`] — the same
//!   sandbox delegated Guardian Compute tasks get, gated behind the
//!   `compute` Cargo feature (it pulls in `wasmtime`). Every run gets a
//!   fresh `Store` and a hard resource ceiling; the only host capability
//!   linked in by default is `gdb.log`.
//! * **`deno`** — plain Deno TypeScript/JavaScript source, the shape a real
//!   Supabase Edge Function actually is
//!   (`Deno.serve((req) => new Response(...))`). Runs by shelling out to a
//!   `deno` binary — see the `functions_deno` module for the process
//!   sandbox (least-privilege permission flags, env-cleared child process,
//!   wall-clock + memory ceilings). **Needs no `compute`/wasmtime feature at
//!   all** — this is what lets a project deploy an ordinary Deno function
//!   without ever touching WebAssembly.
//!
//! Both substrates speak the same wire envelope, just different transports:
//! the WASM guest gets a CBOR-encoded [`InvocationInput`]/[`InvocationOutput`]
//! through linear memory; the Deno guest gets the same structs JSON-encoded
//! over the child process's stdin/stdout.
//!
//! When a project sets `verify_jwt=false` (the CLI's `--no-verify-jwt`), the
//! bearer/apikey is still required for admission but a missing `Authorization`
//! is allowed. When it is `true` (the default), the caller MUST supply an
//! `apikey` header AND a matching `Authorization: Bearer` token, and both
//! must verify against the project keys — a mismatch renders the same
//! `SUPA_COMPAT_INVALID_JWT` shape as `/rest/v1`.
//!
//! ## Storage model
//!
//! The `functions` schema (see [`BOOTSTRAP_SQL`]) holds three tables:
//!
//! * `functions.functions` — one row per deployed function (slug, name,
//!   verify_jwt, version, runtime, status, timestamps).
//! * `functions._code` — the deployed body (wasm bytes or Deno source text,
//!   as raw bytes either way), keyed by function id (`bytea`).
//! * `functions.secrets` — per-function environment variables (name/value),
//!   exposed to the guest through the input envelope's `env` map (the WASM
//!   guest reads it from the envelope; the Deno guest also gets it as real
//!   process env vars, scoped by `--allow-env`).
//!
//! All three tables have RLS enabled with **no default policies** — only
//! `service_role` reaches them, exactly like `storage.buckets`.
//!
//! ## Error shape
//!
//! Errors match Supabase's Functions runtime shape:
//! `{"error": <code>, "msg": <message>}`. The full taxonomy lives in
//! [`functions_error`] / [`FunctionsErrorCode`]. Gateway-level errors from
//! outside this module (missing apikey, invalid JWT) still render in the
//! shared `{code, message}` shape — that is the caller's contract with the
//! auth layer, unchanged here.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get};
use axum::{Extension, Json as AxumJson};
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};
use uuid::Uuid;

use crate::sql::{ExecResult, RelationalStorage, SqlValue};
use crate::supabase::error::{SupaError, status_for_sqlstate};
use crate::supabase::gateway::{AppState, AuthContext, run_batch, run_sql_as};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum accepted request body for a function invocation (bytes).
/// Deliberately conservative — function inputs travel through the SQL layer's
/// JSON envelope, and huge payloads should go through Storage instead.
pub const MAX_INVOKE_BODY_BYTES: usize = 6 * 1024 * 1024;

/// Maximum accepted WebAssembly bundle size when deploying (bytes).
pub const MAX_WASM_BUNDLE_BYTES: usize = 50 * 1024 * 1024;

/// Maximum accepted Deno source size when deploying (bytes). Smaller than
/// the wasm ceiling — this is a single source file, not a compiled bundle.
pub const MAX_DENO_SOURCE_BYTES: usize = 10 * 1024 * 1024;

/// The exported guest function every deployed WASM module must implement.
pub const HANDLER_EXPORT: &str = "handler";

/// Wall-clock ceiling for a single invocation, in milliseconds. Matches
/// Supabase's default Edge Functions timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// Ceiling on the wasm module's linear memory for a single invocation.
pub const DEFAULT_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

/// Ceiling on wasm fuel for a single invocation.
pub const DEFAULT_FUEL: u64 = 5_000_000_000;

// ---------------------------------------------------------------------------
// Schema bootstrap
// ---------------------------------------------------------------------------

/// The `functions` schema bootstrap. RLS is enabled with no default policies
/// so only `service_role` bypasses.
pub const BOOTSTRAP_SQL: &str = "
CREATE SCHEMA IF NOT EXISTS functions;

CREATE TABLE IF NOT EXISTS functions.functions (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    name text NOT NULL,
    verify_jwt boolean NOT NULL,
    version bigint NOT NULL,
    status text NOT NULL,
    runtime text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Migration for schemas bootstrapped before the `runtime` column existed
-- (deployments predating Deno-runtime support). Nullable and backfilled
-- lazily: a NULL/missing `runtime` reads as `wasm` (the only substrate that
-- existed before), and every write from here on sets it explicitly.
ALTER TABLE functions.functions ADD COLUMN IF NOT EXISTS runtime text;

CREATE TABLE IF NOT EXISTS functions._code (
    function_id uuid PRIMARY KEY,
    body bytea NOT NULL,
    content_sha256 text NOT NULL,
    size_bytes bigint NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS functions.secrets (
    function_id uuid NOT NULL,
    name text NOT NULL,
    value text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (function_id, name)
);

ALTER TABLE functions.functions ENABLE ROW LEVEL SECURITY;
ALTER TABLE functions._code ENABLE ROW LEVEL SECURITY;
ALTER TABLE functions.secrets ENABLE ROW LEVEL SECURITY;
";

/// The columns projected for every function metadata read.
const FUNCTION_COLUMNS: &str =
    "id, slug, name, verify_jwt, version, status, runtime, created_at, updated_at";

/// Bootstrap the `functions` schema exactly once per gateway instance.
pub async fn ensure_schema<S: RelationalStorage + 'static>(
    state: &AppState<S>,
) -> Result<(), SupaError> {
    state
        .functions_ready
        .get_or_try_init(|| async {
            run_batch(&state.db, "service_role", BOOTSTRAP_SQL)
                .await
                .map_err(SupaError::Sql)?;
            Ok::<(), SupaError>(())
        })
        .await
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Runtime detection
// ---------------------------------------------------------------------------

const WASM_MAGIC: &[u8] = b"\0asm";

/// Which substrate a deployed function body runs under, detected once at
/// deploy time from the body's content — never a field the caller sets
/// explicitly. Persisted as the `functions.functions.runtime` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionRuntime {
    /// A WebAssembly module, run in [`crate::compute::WasmRuntime`] (needs
    /// the `compute` Cargo feature).
    Wasm,
    /// Deno TypeScript/JavaScript source, run by shelling out to a `deno`
    /// binary (see the `functions_deno` module). Needs no extra Cargo
    /// feature.
    Deno,
}

impl FunctionRuntime {
    fn as_str(self) -> &'static str {
        match self {
            FunctionRuntime::Wasm => "wasm",
            FunctionRuntime::Deno => "deno",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "wasm" => Some(FunctionRuntime::Wasm),
            "deno" => Some(FunctionRuntime::Deno),
            _ => None,
        }
    }

    /// The `Content-Type` a deployed body of this runtime renders as on
    /// `GET .../body`.
    fn content_type(self) -> &'static str {
        match self {
            FunctionRuntime::Wasm => "application/wasm",
            FunctionRuntime::Deno => "application/typescript",
        }
    }
}

/// `Content-Type` values on `PUT .../body` that mean "this raw body is Deno
/// source, not base64" — mirrors the existing `application/wasm` /
/// `application/octet-stream` sniff for raw wasm bytes.
const DENO_SOURCE_CONTENT_TYPES: &[&str] = &[
    "application/typescript",
    "text/typescript",
    "application/x-typescript",
    "application/javascript",
    "text/javascript",
];

/// Validate a WebAssembly body: the `\0asm` magic and the size ceiling.
fn validate_wasm_body(bytes: &[u8]) -> Result<(), SupaError> {
    validate_wasm_magic(bytes)?;
    if bytes.len() > MAX_WASM_BUNDLE_BYTES {
        return Err(SupaError::BadRequest(format!(
            "wasm body exceeds {MAX_WASM_BUNDLE_BYTES} bytes ({} bytes)",
            bytes.len()
        )));
    }
    Ok(())
}

/// Validate a Deno source body: valid non-empty UTF-8 text under the size
/// ceiling. This is deliberately light — full syntax validation would need
/// an embedded JS/TS parser, and a real Deno process already gives an honest
/// boot-error at invoke time for anything that fails to parse.
fn validate_deno_body(bytes: &[u8]) -> Result<(), SupaError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| SupaError::BadRequest(format!("function source is not valid UTF-8: {e}")))?;
    if text.trim().is_empty() {
        return Err(SupaError::BadRequest("function source is empty".into()));
    }
    if bytes.len() > MAX_DENO_SOURCE_BYTES {
        return Err(SupaError::BadRequest(format!(
            "function source exceeds {MAX_DENO_SOURCE_BYTES} bytes ({} bytes)",
            bytes.len()
        )));
    }
    Ok(())
}

/// Detect and validate a deployed body's runtime purely from its content:
/// the `\0asm` magic means WebAssembly, otherwise it must be non-empty valid
/// UTF-8 (Deno source) — anything else (binary garbage, empty body) is
/// rejected. Used wherever the caller hasn't told us the runtime via
/// `Content-Type` (the base64 `body` field on create/update, and the
/// `PUT .../body` fallback for an unrecognized content type).
fn detect_runtime(bytes: &[u8]) -> Result<FunctionRuntime, SupaError> {
    if bytes.len() >= 4 && &bytes[..4] == WASM_MAGIC {
        validate_wasm_body(bytes)?;
        return Ok(FunctionRuntime::Wasm);
    }
    validate_deno_body(bytes)?;
    Ok(FunctionRuntime::Deno)
}

// ---------------------------------------------------------------------------
// Error rendering
// ---------------------------------------------------------------------------

/// The stable error codes the functions surface can surface. The wire body
/// is always `{"error": <code>, "msg": <message>}` at the associated HTTP
/// status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionsErrorCode {
    /// The function slug is not deployed.
    NotFound,
    /// The function's WASM body failed to compile or instantiate.
    BootError,
    /// The function trapped, exceeded fuel, memory, or deadline, or violated
    /// the ABI at runtime.
    RuntimeError,
    /// The invocation input was too large or malformed.
    BadRequest,
    /// The service role is required (admin routes).
    Forbidden,
    /// The deployed body was not a valid WebAssembly module.
    InvalidWasm,
    /// An internal gateway failure (never contains a secret).
    Internal,
}

impl FunctionsErrorCode {
    fn status(self) -> StatusCode {
        match self {
            FunctionsErrorCode::NotFound => StatusCode::NOT_FOUND,
            FunctionsErrorCode::BootError => StatusCode::INTERNAL_SERVER_ERROR,
            FunctionsErrorCode::RuntimeError => StatusCode::INTERNAL_SERVER_ERROR,
            FunctionsErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            FunctionsErrorCode::Forbidden => StatusCode::FORBIDDEN,
            FunctionsErrorCode::InvalidWasm => StatusCode::BAD_REQUEST,
            FunctionsErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(self) -> &'static str {
        match self {
            FunctionsErrorCode::NotFound => "SUPA_COMPAT_FUNCTION_NOT_FOUND",
            FunctionsErrorCode::BootError => "SUPA_COMPAT_FUNCTION_BOOT_ERROR",
            FunctionsErrorCode::RuntimeError => "SUPA_COMPAT_FUNCTION_RUNTIME_ERROR",
            FunctionsErrorCode::BadRequest => "SUPA_COMPAT_FUNCTION_BAD_REQUEST",
            FunctionsErrorCode::Forbidden => "SUPA_COMPAT_FUNCTION_FORBIDDEN",
            FunctionsErrorCode::InvalidWasm => "SUPA_COMPAT_FUNCTION_INVALID_WASM",
            FunctionsErrorCode::Internal => "SUPA_COMPAT_FUNCTION_INTERNAL",
        }
    }
}

/// Render a functions-shaped error: `{"error": <code>, "msg": <message>}`.
pub fn functions_error(code: FunctionsErrorCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    (
        code.status(),
        AxumJson(json!({
            "error": code.code(),
            "msg": msg,
        })),
    )
        .into_response()
}

/// Convert an infrastructure error to the functions error shape.
fn functions_error_from(e: SupaError) -> Response {
    if let SupaError::Sql(err) = &e {
        let state = err.sqlstate();
        return functions_error(
            match status_for_sqlstate(state) {
                StatusCode::NOT_FOUND => FunctionsErrorCode::NotFound,
                StatusCode::FORBIDDEN => FunctionsErrorCode::Forbidden,
                StatusCode::BAD_REQUEST => FunctionsErrorCode::BadRequest,
                _ => FunctionsErrorCode::Internal,
            },
            err.to_string(),
        );
    }
    match e {
        SupaError::Forbidden(what) => functions_error(
            FunctionsErrorCode::Forbidden,
            format!("{what} requires the service_role key"),
        ),
        SupaError::BadRequest(m) => functions_error(FunctionsErrorCode::BadRequest, m),
        SupaError::Internal(m) => {
            if let Some(rest) = m.strip_prefix("__functions_boot::") {
                functions_error(FunctionsErrorCode::BootError, rest)
            } else if let Some(rest) = m.strip_prefix("__functions_runtime::") {
                functions_error(FunctionsErrorCode::RuntimeError, rest)
            } else {
                functions_error(FunctionsErrorCode::Internal, m)
            }
        }
        other => other.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The invocation router mounted at `/functions/v1` **behind** the apikey
/// middleware. Both admin (`/_admin/...`) and invocation (`/{slug}`) routes
/// live here so a single apikey layer covers the whole namespace.
pub fn router<S: RelationalStorage + 'static>() -> Router<AppState<S>> {
    Router::new()
        // Admin: service_role-only CRUD.
        .route(
            "/_admin/functions",
            get(list_functions::<S>).post(create_function::<S>),
        )
        .route(
            "/_admin/functions/{slug}",
            get(get_function::<S>)
                .patch(update_function::<S>)
                .delete(delete_function::<S>),
        )
        .route(
            "/_admin/functions/{slug}/body",
            get(get_function_body::<S>).put(put_function_body::<S>),
        )
        .route(
            "/_admin/functions/{slug}/secrets",
            get(list_secrets::<S>)
                .post(upsert_secret::<S>)
                .delete(delete_all_secrets::<S>),
        )
        .route(
            "/_admin/functions/{slug}/secrets/{name}",
            delete(delete_secret::<S>),
        )
        // Invocation: OPTIONS is unauthenticated CORS preflight, all others
        // are authenticated per verify_jwt.
        .route("/{slug}", any(invoke_function::<S>))
        .layer(DefaultBodyLimit::max(MAX_INVOKE_BODY_BYTES))
}

// ---------------------------------------------------------------------------
// Admin: CRUD on functions.functions
// ---------------------------------------------------------------------------

/// The JSON shape for creating a function.
#[derive(Debug, Clone, Deserialize)]
struct CreateFunctionBody {
    slug: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_verify_jwt")]
    verify_jwt: bool,
    /// Base64-encoded `.wasm` bytes. Optional at create time so a slug can
    /// be reserved and the body PUT separately (matches Supabase's CLI flow).
    #[serde(default)]
    body: Option<String>,
}

fn default_verify_jwt() -> bool {
    true
}

/// The JSON shape for updating a function.
#[derive(Debug, Clone, Deserialize)]
struct UpdateFunctionBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    verify_jwt: Option<bool>,
    #[serde(default)]
    body: Option<String>,
}

async fn list_functions<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let result = run_sql_as(
            &state.db,
            &auth,
            &format!("SELECT {FUNCTION_COLUMNS} FROM functions.functions ORDER BY slug"),
            vec![],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(AxumJson(Json::Array(result_objects(result)?)).into_response())
    })
    .await
}

async fn create_function<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let req: CreateFunctionBody = serde_json::from_slice(&body)
            .map_err(|e| SupaError::BadRequest(format!("invalid create body: {e}")))?;
        validate_slug(&req.slug)?;

        let (code, runtime) = match req.body.as_deref() {
            Some(b64) => {
                let (bytes, rt) = decode_function_body(b64)?;
                (Some(bytes), Some(rt))
            }
            None => (None, None),
        };

        let id = Uuid::new_v4();
        let now = Utc::now();
        let name = req.name.unwrap_or_else(|| req.slug.clone());
        let status = if code.is_some() { "ACTIVE" } else { "PENDING" };
        let runtime_value = match runtime {
            Some(rt) => SqlValue::Text(rt.as_str().to_string()),
            None => SqlValue::Null,
        };

        let insert = run_sql_as(
            &state.db,
            &auth,
            "INSERT INTO functions.functions \
             (id, slug, name, verify_jwt, version, status, runtime, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $7)",
            vec![
                SqlValue::Uuid(id),
                SqlValue::Text(req.slug.clone()),
                SqlValue::Text(name),
                SqlValue::Bool(req.verify_jwt),
                SqlValue::Text(status.to_string()),
                runtime_value,
                SqlValue::Timestamptz(now),
            ],
        )
        .await;
        if let Err(e) = insert {
            if e.sqlstate() == "23505" {
                return Ok(functions_error(
                    FunctionsErrorCode::BadRequest,
                    format!("function slug \"{}\" already exists", req.slug),
                ));
            }
            return Err(SupaError::Sql(e));
        }

        if let Some(code) = code {
            insert_code(&state, &auth, id, &code, now).await?;
        }

        let row = fetch_one_function(&state, &auth, &req.slug).await?;
        Ok((StatusCode::CREATED, AxumJson(row)).into_response())
    })
    .await
}

async fn get_function<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        match load_function_row(&state, &auth, &slug).await? {
            Some(row) => Ok(AxumJson(row).into_response()),
            None => Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            )),
        }
    })
    .await
}

async fn update_function<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let req: UpdateFunctionBody = serde_json::from_slice(&body)
            .map_err(|e| SupaError::BadRequest(format!("invalid update body: {e}")))?;

        let Some(existing) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&existing)?;
        let now = Utc::now();

        let code_and_runtime = req.body.as_deref().map(decode_function_body).transpose()?;

        let mut sets = vec!["updated_at = $1".to_string()];
        let mut params: Vec<SqlValue> = vec![SqlValue::Timestamptz(now)];
        if let Some(name) = req.name {
            params.push(SqlValue::Text(name));
            sets.push(format!("name = ${}", params.len()));
        }
        if let Some(verify) = req.verify_jwt {
            params.push(SqlValue::Bool(verify));
            sets.push(format!("verify_jwt = ${}", params.len()));
        }
        if let Some((_, runtime)) = &code_and_runtime {
            sets.push("version = version + 1".to_string());
            sets.push("status = 'ACTIVE'".to_string());
            params.push(SqlValue::Text(runtime.as_str().to_string()));
            sets.push(format!("runtime = ${}", params.len()));
        }
        params.push(SqlValue::Text(slug.clone()));
        let sql = format!(
            "UPDATE functions.functions SET {} WHERE slug = ${}",
            sets.join(", "),
            params.len()
        );
        run_sql_as(&state.db, &auth, &sql, params)
            .await
            .map_err(SupaError::Sql)?;

        if let Some((code, _)) = code_and_runtime {
            replace_code(&state, &auth, id, &code, now).await?;
        }

        let row = fetch_one_function(&state, &auth, &slug).await?;
        Ok(AxumJson(row).into_response())
    })
    .await
}

async fn delete_function<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        // Cascade by hand — the engine's foreign keys are optional and the
        // storage.rs pattern (delete code + secrets + metadata) is what we
        // mirror here.
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions._code WHERE function_id = $1",
            vec![SqlValue::Uuid(id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions.secrets WHERE function_id = $1",
            vec![SqlValue::Uuid(id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions.functions WHERE slug = $1",
            vec![SqlValue::Text(slug)],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
    .await
}

async fn get_function_body<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        let Some(bytes) = load_code(&state, &auth, id).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" has no deployed body"),
            ));
        };
        let runtime = row_runtime(&row);
        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, runtime.content_type())],
            bytes,
        )
            .into_response())
    })
    .await
}

async fn put_function_body<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        // Accept raw application/wasm bytes, raw Deno source text (several
        // equivalent content types), or base64 text that gets sniffed.
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (code, runtime) = if content_type.starts_with("application/wasm")
            || content_type.starts_with("application/octet-stream")
        {
            let bytes = body.to_vec();
            validate_wasm_body(&bytes)?;
            (bytes, FunctionRuntime::Wasm)
        } else if DENO_SOURCE_CONTENT_TYPES
            .iter()
            .any(|ct| content_type.starts_with(ct))
        {
            let bytes = body.to_vec();
            validate_deno_body(&bytes)?;
            (bytes, FunctionRuntime::Deno)
        } else {
            let text = std::str::from_utf8(&body).map_err(|_| {
                SupaError::BadRequest(
                    "body must be application/wasm, Deno source text, or base64 text".into(),
                )
            })?;
            decode_function_body(text.trim())?
        };
        let now = Utc::now();
        replace_code(&state, &auth, id, &code, now).await?;
        run_sql_as(
            &state.db,
            &auth,
            "UPDATE functions.functions \
             SET version = version + 1, status = 'ACTIVE', runtime = $1, updated_at = $2 \
             WHERE slug = $3",
            vec![
                SqlValue::Text(runtime.as_str().to_string()),
                SqlValue::Timestamptz(now),
                SqlValue::Text(slug.clone()),
            ],
        )
        .await
        .map_err(SupaError::Sql)?;
        let row = fetch_one_function(&state, &auth, &slug).await?;
        Ok(AxumJson(row).into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// Admin: secrets
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UpsertSecretBody {
    name: String,
    value: String,
}

async fn list_secrets<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        // Never surface the value; return only names + timestamps.
        let result = run_sql_as(
            &state.db,
            &auth,
            "SELECT name, updated_at FROM functions.secrets \
             WHERE function_id = $1 ORDER BY name",
            vec![SqlValue::Uuid(id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(AxumJson(Json::Array(result_objects(result)?)).into_response())
    })
    .await
}

async fn upsert_secret<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let req: UpsertSecretBody = serde_json::from_slice(&body)
            .map_err(|e| SupaError::BadRequest(format!("invalid secret body: {e}")))?;
        validate_secret_name(&req.name)?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        let now = Utc::now();
        // Upsert without ON CONFLICT (portable across engine flavours): DELETE
        // then INSERT, both parameterised.
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions.secrets WHERE function_id = $1 AND name = $2",
            vec![SqlValue::Uuid(id), SqlValue::Text(req.name.clone())],
        )
        .await
        .map_err(SupaError::Sql)?;
        run_sql_as(
            &state.db,
            &auth,
            "INSERT INTO functions.secrets (function_id, name, value, updated_at) \
             VALUES ($1, $2, $3, $4)",
            vec![
                SqlValue::Uuid(id),
                SqlValue::Text(req.name.clone()),
                SqlValue::Text(req.value),
                SqlValue::Timestamptz(now),
            ],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(AxumJson(json!({ "name": req.name, "updated_at": now.to_rfc3339() })).into_response())
    })
    .await
}

async fn delete_secret<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path((slug, name)): Path<(String, String)>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions.secrets WHERE function_id = $1 AND name = $2",
            vec![SqlValue::Uuid(id), SqlValue::Text(name)],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
    .await
}

async fn delete_all_secrets<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let Some(row) = load_function_row(&state, &auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let id = extract_id(&row)?;
        run_sql_as(
            &state.db,
            &auth,
            "DELETE FROM functions.secrets WHERE function_id = $1",
            vec![SqlValue::Uuid(id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// Invocation
// ---------------------------------------------------------------------------

/// The JSON envelope handed to the guest as CBOR input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationInput {
    pub method: String,
    pub url: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    /// Base64-encoded request body (may be empty).
    #[serde(default)]
    pub body_b64: String,
    /// Per-function env (name/value pairs from `functions.secrets`).
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// The caller's resolved role (`anon` / `authenticated` / `service_role`).
    pub role: String,
    /// The caller's `x-request-id`.
    pub request_id: String,
    /// The raw bearer JWT the caller supplied (when verify_jwt=true this is
    /// verified). May be empty when verify_jwt=false and no bearer was sent.
    #[serde(default)]
    pub jwt: String,
}

/// The JSON envelope the guest returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationOutput {
    #[serde(default = "default_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Base64-encoded response body.
    #[serde(default)]
    pub body_b64: String,
}

fn default_status() -> u16 {
    200
}

async fn invoke_function<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    // CORS preflight is answered without touching the DB.
    if method == Method::OPTIONS {
        return cors_preflight_response(&headers);
    }
    run(async {
        ensure_schema(&state).await?;

        // Routing metadata lookup runs as service_role: an anon caller cannot
        // read `functions.functions` under the schema's default-deny RLS, and
        // whether a slug is deployed is not a user-visible fact — it is a
        // routing decision equivalent to the storage-api's `_blobs` fetch.
        let admin_auth = as_service_role(&auth);
        let Some(row) = load_function_row(&state, &admin_auth, &slug).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" not found"),
            ));
        };
        let verify_jwt = extract_bool(&row, "verify_jwt").unwrap_or(true);
        if verify_jwt && auth.claims.is_none() {
            return Ok(functions_error(
                FunctionsErrorCode::Forbidden,
                "this function requires a bearer token (verify_jwt=true)",
            ));
        }
        let id = extract_id(&row)?;
        let runtime = row_runtime(&row);
        let Some(code) = load_code(&state, &admin_auth, id).await? else {
            return Ok(functions_error(
                FunctionsErrorCode::NotFound,
                format!("function \"{slug}\" has no deployed body"),
            ));
        };
        let secrets = load_secrets(&state, &admin_auth, id).await?;

        let query_str = query.unwrap_or_default();
        let path = format!("/functions/v1/{slug}");
        let url = format!(
            "{}{}{}",
            state.project.api_url.trim_end_matches('/'),
            path,
            if query_str.is_empty() {
                String::new()
            } else {
                format!("?{query_str}")
            },
        );

        let mut header_pairs = Vec::with_capacity(headers.len());
        for (k, v) in headers.iter() {
            if let Ok(s) = v.to_str() {
                header_pairs.push((k.as_str().to_string(), s.to_string()));
            }
        }

        let jwt = auth
            .claims
            .as_ref()
            .and_then(|_| bearer_from(&headers))
            .unwrap_or_default();

        let input = InvocationInput {
            method: method.to_string(),
            url,
            path,
            query: query_str,
            headers: header_pairs,
            body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
            env: secrets,
            role: auth.role.clone(),
            request_id: auth.request_id.clone(),
            jwt,
        };

        let output = run_guest(runtime, &code, &input).await?;

        render_output(output)
    })
    .await
}

/// Dispatch a guest invocation to the substrate its deployed body was
/// detected as at deploy time. Both branches ultimately produce the same
/// `SupaError::Internal("__functions_{boot,runtime}::...")` shape that
/// [`functions_error_from`] classifies into the right typed
/// `SUPA_COMPAT_FUNCTION_*` code — the invocation surface doesn't need to
/// know which substrate ran.
async fn run_guest(
    runtime: FunctionRuntime,
    code: &[u8],
    input: &InvocationInput,
) -> Result<InvocationOutput, SupaError> {
    match runtime {
        FunctionRuntime::Wasm => run_wasm_guest(code, input).await,
        FunctionRuntime::Deno => crate::supabase::functions_deno::run_deno_guest(
            code,
            input,
            DEFAULT_TIMEOUT_MS,
            DEFAULT_MEMORY_BYTES,
        )
        .await
        .map_err(guest_error_to_supa),
    }
}

fn guest_error_to_supa(e: GuestError) -> SupaError {
    match e {
        GuestError::Boot(msg) => SupaError::Internal(format!("__functions_boot::{msg}")),
        GuestError::Runtime(msg) => SupaError::Internal(format!("__functions_runtime::{msg}")),
    }
}

/// The result of running a WASM guest, before it becomes an HTTP response.
async fn run_wasm_guest(
    wasm: &[u8],
    input: &InvocationInput,
) -> Result<InvocationOutput, SupaError> {
    let input_bytes = serde_cbor_to_bytes(input)?;
    let wasm = wasm.to_vec();
    // The guardian compute runtime is synchronous and CPU-bound; run it in
    // spawn_blocking so we do not stall the tokio scheduler.
    let joined = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, GuestError> {
        run_guest_blocking(&wasm, HANDLER_EXPORT, &input_bytes)
    })
    .await
    .map_err(|e| SupaError::Internal(format!("guest runner join error: {e}")))?;

    let bytes = joined.map_err(guest_error_to_supa)?;

    let out: InvocationOutput = serde_cbor_from_bytes(&bytes)?;
    Ok(out)
}

/// Errors distinguishing boot-time (compile/instantiate/missing export) from
/// runtime (trap/deadline/fuel/etc.), so the invocation surface can render
/// the correct `SUPA_COMPAT_FUNCTION_*` code. Shared by both the WASM and
/// Deno substrates (see the `functions_deno` module).
#[derive(Debug)]
pub(crate) enum GuestError {
    Boot(String),
    Runtime(String),
}

#[cfg(feature = "compute")]
fn run_guest_blocking(wasm: &[u8], entrypoint: &str, input: &[u8]) -> Result<Vec<u8>, GuestError> {
    use crate::compute::ResourceLimits;
    use crate::compute::runtime::TaskError;
    use crate::compute::runtime::{HostGrants, WasmRuntime};

    let runtime = WasmRuntime::new().map_err(|e| GuestError::Boot(e.to_string()))?;
    let task = runtime
        .compile(wasm)
        .map_err(|e| GuestError::Boot(e.to_string()))?;
    let limits = ResourceLimits {
        max_memory_bytes: DEFAULT_MEMORY_BYTES,
        fuel: DEFAULT_FUEL,
        timeout_ms: DEFAULT_TIMEOUT_MS,
    };
    let grants = HostGrants {
        log: true,
        ..HostGrants::default()
    };
    let result = runtime
        .execute_with_host(&task, entrypoint, input, &limits, &grants)
        .map_err(|e| match e {
            TaskError::InvalidModule(m) => GuestError::Boot(format!("invalid module: {m}")),
            TaskError::MissingExport(m) => GuestError::Boot(format!("missing export: {m}")),
            TaskError::HostCapabilityDenied(m) => {
                GuestError::Boot(format!("host capability denied: {m}"))
            }
            TaskError::FuelExhausted => GuestError::Runtime("fuel exhausted".into()),
            TaskError::DeadlineExceeded => {
                GuestError::Runtime("wall-clock deadline exceeded".into())
            }
            TaskError::MemoryLimitExceeded => GuestError::Runtime("memory limit exceeded".into()),
            TaskError::AbiViolation(m) => GuestError::Runtime(format!("abi violation: {m}")),
            TaskError::Trapped(m) => GuestError::Runtime(format!("trap: {m}")),
            TaskError::WasmUnavailable(m) => GuestError::Boot(format!("wasm unavailable: {m}")),
            TaskError::Runtime(m) => GuestError::Runtime(m),
        })?;
    let _ = &result.metrics;
    Ok(result.output)
}

/// Fallback runner when the `compute` feature is not enabled: no WASM sandbox
/// is available. This preserves the module's compile-shape while making it
/// clear the runtime substrate is off.
#[cfg(not(feature = "compute"))]
fn run_guest_blocking(
    _wasm: &[u8],
    _entrypoint: &str,
    _input: &[u8],
) -> Result<Vec<u8>, GuestError> {
    Err(GuestError::Boot(
        "the `compute` feature must be enabled to invoke functions".into(),
    ))
}

fn render_output(output: InvocationOutput) -> Result<Response, SupaError> {
    let status = StatusCode::from_u16(output.status).map_err(|_| {
        SupaError::Internal(format!("__functions_runtime::bad status {}", output.status))
    })?;
    let body_bytes = if output.body_b64.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(output.body_b64.as_bytes())
            .map_err(|e| {
                SupaError::Internal(format!("__functions_runtime::bad body base64: {e}"))
            })?
    };
    let mut response = (status, body_bytes).into_response();
    for (k, v) in output.headers {
        let (Ok(name), Ok(value)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) else {
            continue;
        };
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

/// The standard Supabase Functions CORS preflight response — 204 with the
/// echo of the caller's request headers. Matches how the deno-runtime CLI
/// answers OPTIONS before dispatching to user code.
fn cors_preflight_response(req_headers: &HeaderMap) -> Response {
    let allow_headers = req_headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authorization, x-client-info, apikey, content-type, x-supabase-api-version")
        .to_string();
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("POST, GET, PUT, PATCH, DELETE, OPTIONS"),
    );
    if let Ok(v) = HeaderValue::try_from(allow_headers) {
        h.insert("access-control-allow-headers", v);
    }
    h.insert("access-control-max-age", HeaderValue::from_static("86400"));
    resp
}

// ---------------------------------------------------------------------------
// Data-access helpers
// ---------------------------------------------------------------------------

async fn insert_code<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    id: Uuid,
    wasm: &[u8],
    now: chrono::DateTime<Utc>,
) -> Result<(), SupaError> {
    let sha = hex_sha256(wasm);
    run_sql_as(
        &state.db,
        auth,
        "INSERT INTO functions._code \
         (function_id, body, content_sha256, size_bytes, updated_at) \
         VALUES ($1, $2, $3, $4, $5)",
        vec![
            SqlValue::Uuid(id),
            SqlValue::Bytea(wasm.to_vec()),
            SqlValue::Text(sha),
            SqlValue::Int8(wasm.len() as i64),
            SqlValue::Timestamptz(now),
        ],
    )
    .await
    .map_err(SupaError::Sql)?;
    Ok(())
}

async fn replace_code<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    id: Uuid,
    wasm: &[u8],
    now: chrono::DateTime<Utc>,
) -> Result<(), SupaError> {
    run_sql_as(
        &state.db,
        auth,
        "DELETE FROM functions._code WHERE function_id = $1",
        vec![SqlValue::Uuid(id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    insert_code(state, auth, id, wasm, now).await
}

async fn load_code<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    id: Uuid,
) -> Result<Option<Vec<u8>>, SupaError> {
    let result = run_sql_as(
        &state.db,
        auth,
        "SELECT body FROM functions._code WHERE function_id = $1",
        vec![SqlValue::Uuid(id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    let ExecResult::Rows { rows, .. } = result else {
        return Ok(None);
    };
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    match row.into_iter().next() {
        Some(SqlValue::Bytea(bytes)) => Ok(Some(bytes)),
        Some(SqlValue::Null) => Ok(None),
        _ => Err(SupaError::Internal(
            "function body column is not bytea".into(),
        )),
    }
}

async fn load_secrets<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    id: Uuid,
) -> Result<Vec<(String, String)>, SupaError> {
    let result = run_sql_as(
        &state.db,
        auth,
        "SELECT name, value FROM functions.secrets WHERE function_id = $1 ORDER BY name",
        vec![SqlValue::Uuid(id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    let ExecResult::Rows { rows, .. } = result else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut it = row.into_iter();
        let name = match it.next() {
            Some(SqlValue::Text(s)) => s,
            _ => continue,
        };
        let value = match it.next() {
            Some(SqlValue::Text(s)) => s,
            _ => continue,
        };
        out.push((name, value));
    }
    Ok(out)
}

async fn load_function_row<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    slug: &str,
) -> Result<Option<Json>, SupaError> {
    let result = run_sql_as(
        &state.db,
        auth,
        &format!("SELECT {FUNCTION_COLUMNS} FROM functions.functions WHERE slug = $1"),
        vec![SqlValue::Text(slug.to_string())],
    )
    .await
    .map_err(SupaError::Sql)?;
    let objs = result_objects(result)?;
    Ok(objs.into_iter().next())
}

async fn fetch_one_function<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    slug: &str,
) -> Result<Json, SupaError> {
    load_function_row(state, auth, slug)
        .await?
        .ok_or_else(|| SupaError::Internal(format!("function \"{slug}\" vanished after write")))
}

fn extract_id(row: &Json) -> Result<Uuid, SupaError> {
    row.get("id")
        .and_then(Json::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| SupaError::Internal("function row missing id".into()))
}

fn extract_bool(row: &Json, key: &str) -> Option<bool> {
    row.get(key).and_then(Json::as_bool)
}

/// The row's `runtime`, defaulting to [`FunctionRuntime::Wasm`] when absent
/// — a NULL/missing column means the row predates Deno-runtime support (see
/// the `BOOTSTRAP_SQL` migration note), and wasm was the only substrate then.
fn row_runtime(row: &Json) -> FunctionRuntime {
    row.get("runtime")
        .and_then(Json::as_str)
        .and_then(FunctionRuntime::parse)
        .unwrap_or(FunctionRuntime::Wasm)
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

fn require_service_role(auth: &AuthContext) -> Result<(), SupaError> {
    if auth.is_service_role() {
        Ok(())
    } else {
        Err(SupaError::Forbidden("this admin route"))
    }
}

/// Build a service-role-shaped copy of the caller's `AuthContext`, preserving
/// their claims and request-id — used for internal metadata lookups on the
/// invocation path that must bypass the RLS-default-deny on `functions.*`.
fn as_service_role(auth: &AuthContext) -> AuthContext {
    let mut clone = auth.clone();
    clone.role = "service_role".into();
    clone
}

fn validate_slug(slug: &str) -> Result<(), SupaError> {
    let ok = !slug.is_empty()
        && slug.len() <= 128
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(SupaError::BadRequest(format!(
            "invalid function slug: \"{slug}\" (allowed: [A-Za-z0-9_-], max 128)"
        )))
    }
}

fn validate_secret_name(name: &str) -> Result<(), SupaError> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(SupaError::BadRequest(format!(
            "invalid secret name: \"{name}\" (must match [A-Za-z_][A-Za-z0-9_]*, max 128)"
        )))
    }
}

/// Base64-decode a deployed body and detect+validate its runtime from the
/// decoded bytes (see [`detect_runtime`]).
fn decode_function_body(b64: &str) -> Result<(Vec<u8>, FunctionRuntime), SupaError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| SupaError::BadRequest(format!("body is not valid base64: {e}")))?;
    let runtime = detect_runtime(&bytes)?;
    Ok((bytes, runtime))
}

fn validate_wasm_magic(bytes: &[u8]) -> Result<(), SupaError> {
    if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC {
        return Err(SupaError::BadRequest(
            "body is not a WebAssembly module (missing \\0asm magic)".into(),
        ));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    #[cfg(feature = "sql")]
    {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }
    #[cfg(not(feature = "sql"))]
    {
        // The `supabase` feature implies `sql`, which pulls in sha2, but keep
        // the fallback so a hypothetical feature-shuffled build still builds.
        format!("blake3-{}", blake3::hash(bytes).to_hex())
    }
}

fn bearer_from(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
                .or_else(|| v.strip_prefix("BEARER "))
                .map(str::trim)
                .map(String::from)
        })
}

/// Encode a value as CBOR — bytes-safe transport for guest input.
fn serde_cbor_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SupaError> {
    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|e| SupaError::Internal(format!("__functions_runtime::cbor encode: {e}")))?;
    Ok(out)
}

fn serde_cbor_from_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, SupaError> {
    ciborium::de::from_reader(bytes)
        .map_err(|e| SupaError::Internal(format!("__functions_runtime::cbor decode: {e}")))
}

// ---------------------------------------------------------------------------
// ExecResult → JSON (mirrors the storage.rs helper; kept local to avoid
// pulling private helpers across modules)
// ---------------------------------------------------------------------------

/// Convert an `ExecResult` into an array of JSON objects.
fn result_objects(result: ExecResult) -> Result<Vec<Json>, SupaError> {
    match result {
        ExecResult::Rows { fields, rows } => {
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let mut obj = Map::with_capacity(fields.len());
                for (field, value) in fields.iter().zip(row) {
                    obj.insert(field.name.clone(), value_to_json(value));
                }
                out.push(Json::Object(obj));
            }
            Ok(out)
        }
        ExecResult::Command { .. } => Ok(Vec::new()),
    }
}

/// Local, self-contained SqlValue → JSON rendering. Mirrors the shape of the
/// REST module's helper without depending on it, since this feature-slice
/// keeps its module surface minimal.
fn value_to_json(v: SqlValue) -> Json {
    match v {
        SqlValue::Null => Json::Null,
        SqlValue::Bool(b) => Json::Bool(b),
        SqlValue::Int2(n) => Json::from(n),
        SqlValue::Int4(n) => Json::from(n),
        SqlValue::Int8(n) => Json::from(n),
        SqlValue::Float4(f) => serde_json::Number::from_f64(f as f64)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        SqlValue::Float8(f) => serde_json::Number::from_f64(f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        SqlValue::Numeric(d) => Json::String(d.to_string()),
        SqlValue::Text(s) => Json::String(s),
        SqlValue::Citext(s) => Json::String(s),
        SqlValue::Bytea(b) => Json::String(base64::engine::general_purpose::STANDARD.encode(b)),
        SqlValue::Uuid(u) => Json::String(u.to_string()),
        SqlValue::Date(d) => Json::String(d.to_string()),
        SqlValue::Time(t) => Json::String(t.to_string()),
        SqlValue::Timestamp(t) => Json::String(t.to_string()),
        SqlValue::Timestamptz(t) => Json::String(t.to_rfc3339()),
        SqlValue::Json(j) => j,
        SqlValue::Array(items) => Json::Array(items.into_iter().map(value_to_json).collect()),
        SqlValue::Vector(v) => Json::Array(
            v.into_iter()
                .filter_map(|f| serde_json::Number::from_f64(f as f64).map(Json::Number))
                .collect(),
        ),
        SqlValue::HStore(m) => {
            let mut obj = Map::with_capacity(m.len());
            for (k, v) in m {
                obj.insert(k, v.map(Json::String).unwrap_or(Json::Null));
            }
            Json::Object(obj)
        }
        SqlValue::Ltree(s) => Json::String(s),
        SqlValue::Cube { ll, ur } => json!({ "ll": ll, "ur": ur }),
        SqlValue::TsVector(_) | SqlValue::TsQuery(_) => Json::Null,
    }
}

// ---------------------------------------------------------------------------
// Error-driven response helper (mirrors storage.rs's `run` helper)
// ---------------------------------------------------------------------------

async fn run<F>(fut: F) -> Response
where
    F: std::future::Future<Output = Result<Response, SupaError>>,
{
    fut.await.unwrap_or_else(functions_error_from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation() {
        assert!(validate_slug("hello-world").is_ok());
        assert!(validate_slug("hello_world_2").is_ok());
        assert!(validate_slug("Hello123").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("has space").is_err());
        assert!(validate_slug("has/slash").is_err());
        assert!(validate_slug(&"a".repeat(129)).is_err());
    }

    #[test]
    fn secret_name_validation() {
        assert!(validate_secret_name("MY_ENV").is_ok());
        assert!(validate_secret_name("_leading").is_ok());
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name("1leading").is_err());
        assert!(validate_secret_name("has-dash").is_err());
    }

    #[test]
    fn wasm_magic_check() {
        assert!(validate_wasm_magic(b"\0asm\x01\x00\x00\x00").is_ok());
        assert!(validate_wasm_magic(b"not-wasm").is_err());
        assert!(validate_wasm_magic(b"").is_err());
    }

    #[test]
    fn error_shape_stable() {
        let resp = functions_error(FunctionsErrorCode::NotFound, "no such fn");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn cbor_round_trip() {
        let input = InvocationInput {
            method: "POST".into(),
            url: "http://x/functions/v1/hi".into(),
            path: "/functions/v1/hi".into(),
            query: String::new(),
            headers: vec![("x".into(), "1".into())],
            body_b64: base64::engine::general_purpose::STANDARD.encode(b"hello"),
            env: vec![("SECRET".into(), "s3cret".into())],
            role: "anon".into(),
            request_id: "req-1".into(),
            jwt: String::new(),
        };
        let bytes = serde_cbor_to_bytes(&input).unwrap();
        let back: InvocationInput = serde_cbor_from_bytes(&bytes).unwrap();
        assert_eq!(back.method, "POST");
        assert_eq!(back.headers, vec![("x".to_string(), "1".to_string())]);
    }

    #[test]
    fn default_status_is_200() {
        let out: InvocationOutput = serde_json::from_value(json!({})).unwrap();
        assert_eq!(out.status, 200);
        assert!(out.body_b64.is_empty());
    }
}
