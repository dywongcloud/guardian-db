//! Integration tests for `/functions/v1` (Supabase Edge Functions
//! compatibility): the in-process SQL-backed registry (Mode 1) and the
//! upstream-proxy escape hatch (Mode 2).
//!
//! Follows the same in-process `tower::ServiceExt::oneshot` harness pattern
//! as `tests/supabase_gateway.rs` / `tests/supabase_storage_realtime.rs`
//! (duplicated here rather than shared, per this repo's test-file
//! convention). Mode 2 additionally spins a second, real axum server on an
//! ephemeral 127.0.0.1 port (the same pattern the realtime tests use for a
//! real websocket) to act as the upstream Edge Runtime.

#![cfg(feature = "supabase")]

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tower::ServiceExt;

use guardian_db::sql::MemoryStorage;
use guardian_db::sql::engine::{Database, Session};
use guardian_db::supabase::project::ProjectKeys;
use guardian_db::supabase::{AppState, ServiceConfig, SupabaseCompatProject, build_router};

const TEST_SECRET: &str = "integration-test-jwt-secret-value-0123456789";
const IAT: i64 = 1_700_000_000;

struct Harness {
    app: Router,
    anon: String,
    service: String,
    db: Arc<Database<MemoryStorage>>,
}

async fn harness() -> Harness {
    harness_with_config(ServiceConfig::default()).await
}

async fn harness_with_config(config: ServiceConfig) -> Harness {
    let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "app"));
    let keys = ProjectKeys::from_secret(TEST_SECRET, IAT).unwrap();
    let anon = keys.anon_key.clone();
    let service = keys.service_role_key.clone();
    let project =
        SupabaseCompatProject::shell("app", "http://127.0.0.1:54321", keys, chrono::Utc::now());
    let state = AppState::new(db.clone(), project, config);
    let app = build_router(state);
    Harness {
        app,
        anon,
        service,
        db,
    }
}

/// Mint a real user access token (`role: authenticated`, `sub: <uuid>`). Kept
/// for parity with the sibling test files' harness (not every test here
/// needs a user token, but `#[allow(dead_code)]` would be noisier than just
/// keeping the copy verbatim).
#[allow(dead_code)]
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

/// Bootstrap the `supabase_functions` registry (idempotent), run `ddl`
/// (typically `CREATE FUNCTION` and any supporting tables), and register
/// `slug -> function_name`. Mirrors the "SQL-only management" story: no
/// admin REST surface exists for the registry, so tests seed it exactly the
/// way an operator would.
async fn setup(
    h: &Harness,
    ddl: &str,
    slug: &str,
    function_name: &str,
    verify_jwt: Option<bool>,
    response_kind: Option<&str>,
) {
    let mut s = Session::new(h.db.clone(), "service_role");
    s.execute(guardian_db::supabase::functions::BOOTSTRAP_SQL)
        .await
        .unwrap();
    if !ddl.is_empty() {
        s.execute(ddl).await.unwrap();
    }
    let verify_sql = match verify_jwt {
        Some(true) => "true",
        Some(false) => "false",
        None => "NULL",
    };
    let response_kind_sql = match response_kind {
        Some(k) => format!("'{k}'"),
        None => "NULL".to_string(),
    };
    let insert = format!(
        "INSERT INTO supabase_functions.functions (slug, function_name, verify_jwt, response_kind) \
         VALUES ('{slug}', '{function_name}', {verify_sql}, {response_kind_sql})"
    );
    s.execute(&insert).await.unwrap();
}

// ===========================================================================
// Mode 1: in-process SQL-backed invocation
// ===========================================================================

#[tokio::test]
async fn unknown_slug_is_relay_404() {
    let h = harness().await;

    // With credentials.
    let (status, body) = call(
        &h.app,
        "POST",
        "/functions/v1/does-not-exist",
        Some(&h.anon),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body,
        json!({"code": 404, "message": "Requested function was not found"})
    );

    // Without any credentials — proves the route sits outside the apikey
    // layer (a missing apikey would otherwise be a 401, not a 404).
    let (status, body) = call(
        &h.app,
        "POST",
        "/functions/v1/does-not-exist",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body,
        json!({"code": 404, "message": "Requested function was not found"})
    );
}

#[tokio::test]
async fn invoke_named_args_returns_text() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.hello(name text) RETURNS text LANGUAGE sql AS $$ SELECT 'Hello ' || name $$",
        "hello",
        "hello",
        None,
        None,
    )
    .await;

    let (status, headers, bytes) = call_raw(
        &h.app,
        "POST",
        "/functions/v1/hello",
        &[
            ("apikey", h.anon.as_str()),
            ("content-type", "application/json"),
        ],
        Some(json!({"name": "GuardianDB"}).to_string().into_bytes()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    assert_eq!(String::from_utf8(bytes).unwrap(), "Hello GuardianDB");
}

#[tokio::test]
async fn single_jsonb_arg_receives_whole_body() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.echo_json(payload jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT payload $$",
        "echo",
        "echo_json",
        None,
        None,
    )
    .await;

    let payload = json!({"a": 1, "b": [true, null, "x"], "c": {"nested": 2.5}});
    let (status, headers, bytes) = call_raw(
        &h.app,
        "POST",
        "/functions/v1/echo",
        &[
            ("apikey", h.anon.as_str()),
            ("content-type", "application/json"),
        ],
        Some(payload.to_string().into_bytes()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    let got: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        got, payload,
        "whole body must round-trip through the jsonb arg"
    );
}

#[tokio::test]
async fn request_context_gucs() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.ctx_probe() RETURNS text LANGUAGE sql AS $$ \
         SELECT current_setting('request.method') || ':' || current_setting('request.path') $$",
        "ctx",
        "ctx_probe",
        Some(false),
        None,
    )
    .await;

    let (status, _headers, bytes) =
        call_raw(&h.app, "POST", "/functions/v1/ctx/extra?x=1", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(bytes).unwrap(), "POST:/extra");
}

#[tokio::test]
async fn rls_enforced_under_caller_role() {
    let h = harness().await;
    setup(
        &h,
        "CREATE TABLE rls_demo (id int PRIMARY KEY, val text); \
         ALTER TABLE rls_demo ENABLE ROW LEVEL SECURITY; \
         CREATE FUNCTION public.count_rows() RETURNS int LANGUAGE plpgsql AS $$ \
         BEGIN \
           INSERT INTO rls_demo (id, val) VALUES (1, 'x'); \
           RETURN (SELECT count(*) FROM rls_demo); \
         END; \
         $$",
        "count",
        "count_rows",
        None,
        None,
    )
    .await;

    // anon: `rls_demo` has RLS enabled with no policies, so the INSERT's
    // WITH CHECK phase default-denies -> 42501, rendered exactly like
    // `/rest/v1` through the unchanged SQL error taxonomy.
    let (status, body) = call(
        &h.app,
        "POST",
        "/functions/v1/count",
        Some(&h.anon),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "42501");

    // service_role bypasses row security entirely.
    let (status, body) = call(
        &h.app,
        "POST",
        "/functions/v1/count",
        Some(&h.service),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, 1);
}

#[tokio::test]
async fn verify_jwt_false_allows_unauthenticated() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.ping() RETURNS text LANGUAGE sql AS $$ SELECT 'pong' $$",
        "ping",
        "ping",
        Some(false),
        None,
    )
    .await;

    let (status, _headers, bytes) = call_raw(&h.app, "POST", "/functions/v1/ping", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(bytes).unwrap(), "pong");
}

#[tokio::test]
async fn verify_jwt_true_requires_key() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.ping2() RETURNS text LANGUAGE sql AS $$ SELECT 'pong' $$",
        "ping2",
        "ping2",
        Some(true),
        None,
    )
    .await;

    let (status, body) = call(&h.app, "POST", "/functions/v1/ping2", None, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "SUPA_COMPAT_MISSING_API_KEY");
}

#[tokio::test]
async fn options_preflight_cors() {
    let h = harness().await;
    let (status, headers, _bytes) =
        call_raw(&h.app, "OPTIONS", "/functions/v1/whatever", &[], None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    assert_eq!(
        headers.get("access-control-allow-headers").unwrap(),
        "authorization, apikey, content-type, x-client-info"
    );
    assert_eq!(
        headers.get("access-control-allow-methods").unwrap(),
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
}

#[tokio::test]
async fn arg_mismatch_typed_400() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.add_nums(a int, b int) RETURNS int LANGUAGE sql AS $$ SELECT a + b $$",
        "add",
        "add_nums",
        None,
        None,
    )
    .await;

    // Unmatched body keys -> 400 naming the expected params.
    let (status, body) = call(
        &h.app,
        "POST",
        "/functions/v1/add",
        Some(&h.anon),
        None,
        Some(json!({"a": 1, "c": 2})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "SUPA_COMPAT_REST_BAD_REQUEST");
    assert!(
        body["message"].as_str().unwrap().contains("a, b"),
        "expected parameter names in message: {body}"
    );

    // multipart/form-data content-type -> typed 501.
    let (status, _headers, bytes) = call_raw(
        &h.app,
        "POST",
        "/functions/v1/add",
        &[
            ("apikey", h.anon.as_str()),
            ("content-type", "multipart/form-data; boundary=x"),
        ],
        Some(b"--x--".to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["code"],
        "SUPA_COMPAT_FUNCTIONS_MULTIPART_NOT_IMPLEMENTED"
    );
}

#[tokio::test]
async fn raise_exception_maps_to_500() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.boom() RETURNS int LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'kaboom'; END; $$",
        "boom",
        "boom",
        Some(false),
        None,
    )
    .await;

    let (status, body) = call(&h.app, "POST", "/functions/v1/boom", None, None, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], "P0001");
}

#[tokio::test]
async fn http_envelope_controls_status() {
    let h = harness().await;
    setup(
        &h,
        "CREATE FUNCTION public.custom_response() RETURNS jsonb LANGUAGE sql AS $$ \
         SELECT '{\"status\":201,\"headers\":{\"x-custom\":\"yes\"},\"body\":{\"ok\":true}}'::jsonb $$",
        "custom",
        "custom_response",
        Some(false),
        Some("http"),
    )
    .await;

    let (status, headers, bytes) =
        call_raw(&h.app, "POST", "/functions/v1/custom", &[], None).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("x-custom").unwrap(), "yes");
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body, json!({"ok": true}));

    // Malformed envelope: a jsonb scalar (not an object) -> relay 500.
    setup(
        &h,
        "CREATE FUNCTION public.bad_response() RETURNS jsonb LANGUAGE sql AS $$ \
         SELECT '\"just-a-string\"'::jsonb $$",
        "bad",
        "bad_response",
        Some(false),
        Some("http"),
    )
    .await;
    let (status, body) = call(&h.app, "POST", "/functions/v1/bad", None, None, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], 500);
}

// ===========================================================================
// Mode 2: upstream proxy
// ===========================================================================

/// A tiny echo server standing in for a self-hosted Supabase Edge Runtime:
/// reports back the method, path+query, and body it received.
async fn spawn_echo_server() -> std::net::SocketAddr {
    async fn echo(method: Method, uri: Uri, body: Bytes) -> Response {
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_default();
        axum::Json(json!({
            "method": method.as_str(),
            "path": path_and_query,
            "body": String::from_utf8_lossy(&body).to_string(),
        }))
        .into_response()
    }
    let app = Router::new().fallback(axum::routing::any(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    addr
}

#[tokio::test]
async fn proxy_mode_forwards() {
    let upstream_addr = spawn_echo_server().await;
    let h = harness_with_config(ServiceConfig {
        functions_upstream: Some(format!("http://{upstream_addr}")),
        ..ServiceConfig::default()
    })
    .await;

    let (status, _headers, bytes) = call_raw(
        &h.app,
        "POST",
        "/functions/v1/hello/world?x=1",
        &[("content-type", "application/json")],
        Some(b"{\"a\":1}".to_vec()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/hello/world?x=1");
    assert_eq!(body["body"], "{\"a\":1}");
}

#[tokio::test]
async fn proxy_upstream_down_is_relay_502() {
    // Bind then immediately drop, so the port is definitely closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let h = harness_with_config(ServiceConfig {
        functions_upstream: Some(format!("http://{addr}")),
        ..ServiceConfig::default()
    })
    .await;

    let (status, headers, bytes) =
        call_raw(&h.app, "GET", "/functions/v1/anything", &[], None).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(headers.get("x-relay-error").unwrap(), "true");
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], 502);
}
