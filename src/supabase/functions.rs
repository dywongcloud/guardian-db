//! `/functions/v1` — Supabase Edge Functions compatibility.
//!
//! Two composed transports behind one router, deliberately with **no
//! JS/WASM runtime**:
//!
//! * **Mode 1 (default, in-process)**: a replicated registry table
//!   (`supabase_functions.functions`, bootstrapped on first use — see
//!   [`BOOTSTRAP_SQL`]) maps a slug to a SQL-engine user-defined function
//!   living in schema `public` (handler functions must live there —
//!   `crate::sql::names::function_dispatch_name` drops schema qualifiers on
//!   dispatch). Invocation ([`invoke_local`]) maps the JSON body to the
//!   function's declared parameters, opens a per-request [`Session`] bound to
//!   the resolved role with the caller's JWT claims installed exactly like
//!   `/rest/v1`, and renders the scalar result.
//! * **Mode 2 (config'd escape hatch)**: when
//!   [`crate::supabase::project::ServiceConfig::functions_upstream`] is set,
//!   every request — including `OPTIONS` and unknown slugs, since the
//!   upstream owns 404s in this mode — is forwarded verbatim via `reqwest`
//!   to a self-hosted Supabase Edge Runtime (see [`proxy`]).
//!
//! Management of Mode 1's registry is **SQL-only**: there is no admin REST
//! surface. An operator runs `CREATE FUNCTION public.my_handler(...)` then
//! `INSERT INTO supabase_functions.functions (slug, function_name, ...)
//! VALUES (...)` as `service_role`.
//!
//! Two distinct JSON error shapes are in play: ordinary gateway/engine
//! failures (missing/invalid API key, bad request, SQL errors) render via the
//! existing [`SupaError`] taxonomy unchanged; failures that real Supabase's
//! *functions-relay* itself would raise (unknown slug, a dangling registry
//! entry, a malformed `response_kind='http'` envelope, an unreachable
//! upstream) render via [`relay_error`] — the `{"code","message"}` shape
//! `functions-js` inspects for `FunctionsRelayError`/`FunctionsHttpError`.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Extension, Json as AxumJson, Router};
use chrono::Utc;
use serde_json::{Map, Value as Json, json};

use crate::relational::FunctionDef;
use crate::sql::engine::Session;
use crate::sql::{ExecResult, RelationalStorage, SqlError, SqlType, SqlValue};
use crate::supabase::error::SupaError;
use crate::supabase::gateway::{
    AppState, AuthContext, RequestId, header_str, load_catalog, resolve_auth, run_batch, run_sql,
};
use crate::supabase::rest::{json_to_sqlvalue, parse_query_pairs, validate_ident, value_to_json};

/// The registry schema bootstrap. Row security is enabled with **no
/// policies** — same pattern as `storage`'s bootstrap
/// ([`crate::supabase::storage::BOOTSTRAP_SQL`]): `service_role` (an
/// RLS-bypass role) manages the registry; every other role is default-denied.
/// There is deliberately no REST surface over this table — it is managed by
/// hand-written SQL only.
pub const BOOTSTRAP_SQL: &str = "
CREATE SCHEMA IF NOT EXISTS supabase_functions;

CREATE TABLE IF NOT EXISTS supabase_functions.functions (
    slug text PRIMARY KEY,
    function_name text NOT NULL,
    verify_jwt boolean,
    response_kind text,
    created_at timestamptz,
    updated_at timestamptz
);

ALTER TABLE supabase_functions.functions ENABLE ROW LEVEL SECURITY;
";

/// Bootstrap the `supabase_functions` schema exactly once per gateway
/// instance (see [`AppState::functions_ready`](crate::supabase::gateway::AppState)).
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
// Router
// ---------------------------------------------------------------------------

/// The `/functions/v1` subrouter. Mounted **outside** the apikey middleware
/// (see `gateway::build_router`) — `verify_jwt` is a per-function registry
/// setting checked inside [`invoke`], not a blanket Kong-level gate, and Mode
/// 2's upstream owns its own auth story entirely.
pub fn router<S: RelationalStorage + 'static>() -> Router<AppState<S>> {
    Router::new()
        .route("/{slug}", any(invoke::<S>))
        .route("/{slug}/{*path}", any(invoke::<S>))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .fallback(fallback_404)
}

/// A path under `/functions/v1` that matched neither route (e.g. the mount
/// root with no slug) — never a bare 404.
async fn fallback_404() -> Response {
    let mut resp = relay_error(StatusCode::NOT_FOUND, "Requested function was not found");
    cors_headers(&mut resp, false);
    resp
}

/// The parsed route + request pieces every invocation path (local, proxy)
/// needs, assembled once by [`invoke`].
struct FnRequest {
    slug: String,
    /// `"/"` when the request targeted `/{slug}` with no further path;
    /// otherwise `"/"` plus the trailing path segments — what the function
    /// body reads back via `current_setting('request.path')`.
    subpath: String,
    query: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
}

async fn invoke<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Path(params): Path<HashMap<String, String>>,
    Extension(rid): Extension<RequestId>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let req = FnRequest {
        slug: params.get("slug").cloned().unwrap_or_default(),
        subpath: params
            .get("path")
            .map(|p| format!("/{p}"))
            .unwrap_or_else(|| "/".to_string()),
        query: query.unwrap_or_default(),
        method,
        headers,
        body,
    };

    // Mode 2: the upstream owns everything, including OPTIONS and 404s.
    if let Some(upstream) = state.config.functions_upstream.clone() {
        return proxy(&state, &upstream, &req).await;
    }

    if req.method == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        cors_headers(&mut resp, true);
        return resp;
    }

    let mut resp = invoke_local(&state, &req, rid.0).await;
    cors_headers(&mut resp, false);
    resp
}

/// Apply the fixed CORS policy every `/functions/v1` (Mode 1) response
/// carries. `preflight` additionally sets `access-control-allow-{headers,
/// methods}` for the `OPTIONS` response; every other response gets only
/// `access-control-allow-origin`.
fn cors_headers(resp: &mut Response, preflight: bool) {
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    if preflight {
        h.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, apikey, content-type, x-client-info"),
        );
        h.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET,POST,PUT,PATCH,DELETE,OPTIONS"),
        );
    }
}

/// Render a Supabase functions-relay-shaped error: `{"code","message"}` with
/// `code` as the numeric HTTP status — distinct from [`SupaError`]'s
/// `SUPA_COMPAT_*`-coded shape. This is what `functions-js` inspects to raise
/// `FunctionsRelayError` / `FunctionsHttpError` instead of parsing the body as
/// the function's own response.
fn relay_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        AxumJson(json!({"code": status.as_u16(), "message": message})),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Mode 1: in-process, SQL-backed invocation
// ---------------------------------------------------------------------------

/// One row of the `supabase_functions.functions` registry.
struct RegistryRow {
    function_name: String,
    verify_jwt: Option<bool>,
    response_kind: Option<String>,
}

/// `^[A-Za-z0-9_-]{1,63}$`.
fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 63
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Look up `slug` in the registry. The slug is only ever bound as `$1` — never
/// string-interpolated into SQL. `Ok(None)` covers both invalid slug syntax
/// and "no such row"; the caller renders both as the same relay 404.
async fn lookup_slug<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    slug: &str,
) -> Result<Option<RegistryRow>, SupaError> {
    if !is_valid_slug(slug) {
        return Ok(None);
    }
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT function_name, verify_jwt, response_kind FROM supabase_functions.functions \
         WHERE slug = $1",
        vec![SqlValue::Text(slug.to_string())],
    )
    .await
    .map_err(SupaError::Sql)?;
    let ExecResult::Rows { rows, .. } = result else {
        return Ok(None);
    };
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(RegistryRow {
        function_name: row.first().and_then(SqlValue::to_text).unwrap_or_default(),
        verify_jwt: match row.get(1) {
            Some(SqlValue::Bool(b)) => Some(*b),
            _ => None,
        },
        response_kind: match row.get(2) {
            Some(SqlValue::Text(s)) | Some(SqlValue::Citext(s)) => Some(s.clone()),
            _ => None,
        },
    }))
}

/// Parse the request body per its content-type, per the fixed rules this
/// slice supports (see module docs). `body.is_empty()` short-circuits to
/// `Json::Null` before any content-type dispatch — an empty POST is common
/// and must not fail JSON parsing.
fn parse_body(headers: &HeaderMap, body: &[u8]) -> Result<Json, SupaError> {
    if body.is_empty() {
        return Ok(Json::Null);
    }
    let ct = header_str(headers, "content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.is_empty() || ct == "application/json" {
        return serde_json::from_slice(body)
            .map_err(|e| SupaError::BadRequest(format!("invalid JSON body: {e}")));
    }
    if ct == "multipart/form-data" {
        return Err(SupaError::NotImplemented("FUNCTIONS_MULTIPART"));
    }
    if ct.starts_with("text/") {
        return std::str::from_utf8(body)
            .map(|s| Json::String(s.to_string()))
            .map_err(|e| SupaError::BadRequest(format!("body is not valid utf-8: {e}")));
    }
    Err(SupaError::NotImplemented("FUNCTIONS_BINARY_BODY"))
}

/// Outcome of [`select_target`] failing: either a relay-shaped error (a
/// dangling registry entry — the function itself no longer exists) or an
/// ordinary typed [`SupaError`] (no signature matched the body).
enum TargetOutcome {
    Relay(StatusCode, String),
    Supa(SupaError),
}

/// Map the parsed JSON body to one `candidates` signature and its bound
/// arguments, in this precedence order:
///
/// 1. the body is a JSON object whose key set exactly equals a candidate's
///    declared argument names → that candidate, args in declared order;
/// 2. else a candidate with arity 1 whose sole argument is `json`/`jsonb` →
///    bind the *entire* body as one `jsonb` argument (whole-payload handler);
/// 3. else an empty body (`Json::Null`) and an arity-0 candidate → that
///    candidate;
/// 4. no candidates are registered for the function name at all → a relay
///    500 naming the dangling function;
/// 5. otherwise → a typed 400 listing every candidate's expected parameters.
fn select_target(
    candidates: &[FunctionDef],
    body: &Json,
    function_name: &str,
) -> Result<Vec<SqlValue>, TargetOutcome> {
    if candidates.is_empty() {
        return Err(TargetOutcome::Relay(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "function \"public.{function_name}\" is registered for this slug but does not \
                 exist in the catalog"
            ),
        ));
    }

    // (1) exact key-set match.
    if let Json::Object(map) = body {
        let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        if let Some(def) = candidates.iter().find(|d| {
            let arg_keys: BTreeSet<&str> = d.args.iter().map(|a| a.name.as_str()).collect();
            arg_keys == keys
        }) {
            let args = def
                .args
                .iter()
                .map(|a| {
                    let v = map
                        .get(a.name.as_str())
                        .expect("key set already verified equal");
                    json_to_sqlvalue(v, Some(&a.ty))
                })
                .collect();
            return Ok(args);
        }
    }

    // (2) a single jsonb argument: bind the whole payload.
    if candidates
        .iter()
        .any(|d| d.arity() == 1 && matches!(d.args[0].ty, SqlType::Json | SqlType::Jsonb))
    {
        return Ok(vec![SqlValue::Json(body.clone())]);
    }

    // (3) empty body + an arity-0 candidate.
    if body.is_null() && candidates.iter().any(|d| d.arity() == 0) {
        return Ok(Vec::new());
    }

    // (5) nothing matched.
    let expected: Vec<String> = candidates
        .iter()
        .map(|d| {
            format!(
                "({})",
                d.args
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    Err(TargetOutcome::Supa(SupaError::BadRequest(format!(
        "request body does not match any parameter signature of function \"{function_name}\"; \
         expected one of: {}",
        expected.join(", ")
    ))))
}

/// Build the JSON object of lowercased header name → value text, as
/// `current_setting('request.headers')` reads it.
fn headers_json(headers: &HeaderMap) -> String {
    let mut obj = Map::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            obj.insert(
                name.as_str().to_ascii_lowercase(),
                Json::String(v.to_string()),
            );
        }
    }
    Json::Object(obj).to_string()
}

/// Build the JSON object of query parameters, as
/// `current_setting('request.query')` reads it.
fn query_json(query: &str) -> String {
    let mut obj = Map::new();
    for (k, v) in parse_query_pairs(query) {
        obj.insert(k, Json::String(v));
    }
    Json::Object(obj).to_string()
}

/// Run `public.<function_name>(args...)` in a session bound to `auth`'s role,
/// with the caller's JWT claims and the request-context GUCs
/// (`request.method` / `request.path` / `request.headers` / `request.query`)
/// installed — RLS-aware exactly like `/rest/v1`. `function_name` was
/// validated with [`validate_ident`] by the caller ([`invoke_local`]), the
/// same defense `rest::do_rpc` uses before splicing a name into SQL text.
async fn call_udf<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    auth: &AuthContext,
    function_name: &str,
    args: Vec<SqlValue>,
    req: &FnRequest,
) -> Result<ExecResult, SqlError> {
    let mut session = Session::new(state.db.clone(), auth.role.clone());
    session.set_var("request.jwt.claims", &auth.claims_json());
    session.set_var("request.method", req.method.as_str());
    session.set_var("request.path", &req.subpath);
    session.set_var("request.headers", &headers_json(&req.headers));
    session.set_var("request.query", &query_json(&req.query));

    let placeholders: Vec<String> = (1..=args.len()).map(|i| format!("${i}")).collect();
    let sql = format!("SELECT {function_name}({})", placeholders.join(", "));
    let prepared = session.prepare(&sql)?;
    session.execute_one(&prepared.statement, &args).await
}

/// The full Mode-1 invoke flow: schema bootstrap, registry lookup, auth
/// resolution, body parsing, argument mapping, execution, response
/// rendering.
async fn invoke_local<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    req: &FnRequest,
    request_id: String,
) -> Response {
    if let Err(e) = ensure_schema(state).await {
        return e.into_response();
    }

    let row = match lookup_slug(state, &req.slug).await {
        Ok(Some(row)) => row,
        Ok(None) => return relay_error(StatusCode::NOT_FOUND, "Requested function was not found"),
        Err(e) => return e.into_response(),
    };

    if validate_ident(&row.function_name, "function").is_err() {
        return relay_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!(
                "function \"{}\" registered for slug \"{}\" has an invalid name",
                row.function_name, req.slug
            ),
        );
    }

    // `verify_jwt = false` synthesizes an honest anon context (no auth check
    // performed); NULL or `true` requires the usual apikey/bearer resolution.
    let auth = if row.verify_jwt == Some(false) {
        AuthContext {
            role: "anon".to_string(),
            api_key_role: "anon".to_string(),
            claims: None,
            request_id,
        }
    } else {
        let now = Utc::now().timestamp();
        match resolve_auth(state, &req.headers, request_id, now).await {
            Ok(a) => a,
            Err(e) => return e.into_response(),
        }
    };

    let body_json = match parse_body(&req.headers, &req.body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let catalog = match load_catalog(&state.db).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let candidates: Vec<FunctionDef> = catalog
        .as_ref()
        .map(|c| {
            c.functions()
                .filter(|f| f.schema == "public" && f.name == row.function_name)
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    let args = match select_target(&candidates, &body_json, &row.function_name) {
        Ok(a) => a,
        Err(TargetOutcome::Relay(status, msg)) => return relay_error(status, &msg),
        Err(TargetOutcome::Supa(e)) => return e.into_response(),
    };

    match call_udf(state, &auth, &row.function_name, args, req).await {
        Ok(result) => render_value(scalar_result(result), row.response_kind.as_deref()),
        Err(sql_err) => SupaError::Sql(sql_err).into_response(),
    }
}

/// Reduce an [`ExecResult`] to the function-return scalar convention: the
/// first row's first column, `NULL` for no rows or a command tag.
fn scalar_result(result: ExecResult) -> SqlValue {
    match result {
        ExecResult::Rows { rows, .. } => rows
            .into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .unwrap_or(SqlValue::Null),
        ExecResult::Command { .. } => SqlValue::Null,
    }
}

/// Render the scalar UDF result. Default (`response_kind` NULL or `'value'`):
/// natural content-negotiated rendering. `response_kind = 'http'`: the value
/// must be a jsonb `{"status","headers"?,"body"}` envelope — see
/// [`render_http_envelope`].
fn render_value(value: SqlValue, response_kind: Option<&str>) -> Response {
    if response_kind == Some("http") {
        return render_http_envelope(value);
    }
    match value {
        SqlValue::Null => StatusCode::NO_CONTENT.into_response(),
        SqlValue::Text(s) | SqlValue::Citext(s) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            s,
        )
            .into_response(),
        SqlValue::Json(j) => (StatusCode::OK, AxumJson(j)).into_response(),
        other => (StatusCode::OK, AxumJson(value_to_json(&other))).into_response(),
    }
}

/// Render a `response_kind = 'http'` envelope: `{"status": int, "headers":
/// {str: str}?, "body": any}`. No heuristic sniffing — this rendering only
/// runs when the registry row explicitly opted in. A malformed envelope
/// (not a jsonb object, or a missing/invalid `status`) is a relay 500, not a
/// typed [`SupaError`] — the handler itself is what is broken, not the
/// caller's request.
fn render_http_envelope(value: SqlValue) -> Response {
    let SqlValue::Json(Json::Object(obj)) = value else {
        return relay_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response_kind='http' handler must return a jsonb object with a \"status\" field",
        );
    };
    let Some(status) = obj
        .get("status")
        .and_then(Json::as_u64)
        .and_then(|s| u16::try_from(s).ok())
        .and_then(|s| StatusCode::from_u16(s).ok())
    else {
        return relay_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response_kind='http' envelope is missing a valid integer \"status\"",
        );
    };

    let mut builder = Response::builder().status(status);
    let mut has_content_type = false;
    if let Some(Json::Object(hdrs)) = obj.get("headers") {
        for (k, v) in hdrs {
            if let Some(s) = v.as_str() {
                if k.eq_ignore_ascii_case("content-type") {
                    has_content_type = true;
                }
                builder = builder.header(k.as_str(), s);
            }
        }
    }

    let body = obj.get("body").cloned().unwrap_or(Json::Null);
    let (default_ct, bytes): (&str, Vec<u8>) = match &body {
        Json::String(s) => ("text/plain; charset=utf-8", s.clone().into_bytes()),
        other => (
            "application/json",
            serde_json::to_vec(other).unwrap_or_default(),
        ),
    };
    if !has_content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, default_ct);
    }
    builder
        .body(axum::body::Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ---------------------------------------------------------------------------
// Mode 2: upstream proxy
// ---------------------------------------------------------------------------

/// Forward `req` to `upstream` verbatim: `upstream + "/" + slug + subpath +
/// query`, method/body/headers copied (minus `host`/`content-length`), the
/// response streamed back minus hop-by-hop headers. Connect/timeout/read
/// failures render as a relay 502 with `x-relay-error: true` — what
/// `functions-js` checks to raise `FunctionsRelayError`.
async fn proxy<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    upstream: &str,
    req: &FnRequest,
) -> Response {
    let client = state
        .functions_http
        .get_or_init(|| async {
            // reqwest's `rustls-no-provider` feature requires a process-wide
            // crypto provider before the first HTTPS request; a no-op if one
            // is already installed (e.g. by iroh's own networking stack).
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("failed to build the Edge Functions upstream-proxy HTTP client")
        })
        .await
        .clone();

    let path_suffix = if req.subpath == "/" {
        ""
    } else {
        req.subpath.as_str()
    };
    let mut url = format!(
        "{}/{}{}",
        upstream.trim_end_matches('/'),
        req.slug,
        path_suffix
    );
    if !req.query.is_empty() {
        url.push('?');
        url.push_str(&req.query);
    }

    let mut builder = client.request(req.method.clone(), url);
    for (name, value) in req.headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == "host" || lname == "content-length" {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    builder = builder.body(req.body.to_vec());

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(_) => return relay_gateway_error(),
    };

    let status = upstream_resp.status();
    let mut out_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == "connection" || lname == "transfer-encoding" || lname == "content-length" {
            continue;
        }
        out_headers.append(name.clone(), value.clone());
    }
    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(_) => return relay_gateway_error(),
    };

    let mut resp = (status, bytes).into_response();
    *resp.headers_mut() = out_headers;
    resp
}

fn relay_gateway_error() -> Response {
    let mut resp = relay_error(
        StatusCode::BAD_GATEWAY,
        "the Edge Functions upstream server is unreachable",
    );
    resp.headers_mut()
        .insert("x-relay-error", HeaderValue::from_static("true"));
    resp
}
