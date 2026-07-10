//! Integration tests for GoTrue-compatible transactional email flows (signup
//! confirmation, password recovery, magic link, resend, verify).
//!
//! Drives the axum `Router` directly with `tower::ServiceExt::oneshot` over a
//! `MemoryStorage`-backed `Database` — no real ports are bound, except in
//! `http_mailer_posts_generic_json`, which binds a second ephemeral server to
//! stand in for an operator's mail webhook (same idiom as
//! `tests/supabase_functions.rs`'s `spawn_echo_server`).

#![cfg(feature = "supabase")]

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tower::ServiceExt;

use guardian_db::sql::MemoryStorage;
use guardian_db::sql::engine::Database;
use guardian_db::supabase::mailer::{EmailType, MailerConfig, MemoryMailer};
use guardian_db::supabase::project::{ProjectKeys, Secret};
use guardian_db::supabase::{AppState, ServiceConfig, SupabaseCompatProject, build_router};

const TEST_SECRET: &str = "integration-test-jwt-secret-value-0123456789";
const IAT: i64 = 1_700_000_000;

struct Harness {
    app: Router,
    anon: String,
    #[allow(dead_code)]
    service: String,
}

/// Build a harness with the default `ServiceConfig` and no mailer override
/// (config-default `MailerConfig::Unconfigured`) — the pre-existing,
/// mailer-less behavior.
async fn harness() -> Harness {
    harness_with_config(ServiceConfig::default()).await
}

/// Build a harness with a caller-supplied `ServiceConfig`, no mailer
/// override — used to exercise `AppState::new`'s own `build_mailer(&config.mailer)`
/// path (e.g. `MailerConfig::Http` / `MailerConfig::Smtp` / the unconfigured
/// default) rather than a test-injected `MemoryMailer`.
async fn harness_with_config(config: ServiceConfig) -> Harness {
    let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "app"));
    let keys = ProjectKeys::from_secret(TEST_SECRET, IAT).unwrap();
    let anon = keys.anon_key.clone();
    let service = keys.service_role_key.clone();
    let project =
        SupabaseCompatProject::shell("app", "http://127.0.0.1:54321", keys, chrono::Utc::now());
    let state = AppState::new(db, project, config);
    let app = build_router(state);
    Harness { app, anon, service }
}

/// Build a harness with a caller-supplied `ServiceConfig` AND a shared
/// `MemoryMailer` injected via `AppState::with_mailer`, so the test can read
/// `mailer.messages()` afterward regardless of `config.mailer`.
async fn harness_with_mailer(config: ServiceConfig) -> (Harness, Arc<MemoryMailer>) {
    let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "app"));
    let keys = ProjectKeys::from_secret(TEST_SECRET, IAT).unwrap();
    let anon = keys.anon_key.clone();
    let service = keys.service_role_key.clone();
    let project =
        SupabaseCompatProject::shell("app", "http://127.0.0.1:54321", keys, chrono::Utc::now());
    let mailer = Arc::new(MemoryMailer::new());
    let state = AppState::new(db, project, config).with_mailer(mailer.clone());
    let app = build_router(state);
    (Harness { app, anon, service }, mailer)
}

/// Send a request and return (status, headers, JSON body).
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    apikey: Option<&str>,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(k) = apikey {
        builder = builder.header("apikey", k);
    }
    if let Some(b) = bearer {
        builder = builder.header("authorization", format!("Bearer {b}"));
    }
    let req = match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, headers, json)
}

/// Send a request with NO apikey / bearer headers at all — for exercising
/// `/auth/v1/verify`'s credential-less `open_router` mount.
async fn call_raw(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    call(app, method, uri, None, None, body).await
}

/// Extract the raw 64-hex-char token embedded in a captured email's `html`
/// (`?token=<hex>`), the same substring a browser's clicked link would carry.
fn extract_token(html: &str) -> String {
    let marker = "token=";
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} in captured email: {html}"))
        + marker.len();
    let token: String = html[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    assert_eq!(
        token.len(),
        64,
        "expected a 64-hex-char token, got {token:?} from: {html}"
    );
    token
}

// ---------------------------------------------------------------------------
// Signup confirmation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signup_confirmation_end_to_end() {
    let (h, mailer) = harness_with_mailer(ServiceConfig {
        require_email_confirmation: true,
        ..ServiceConfig::default()
    })
    .await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "alice@example.com", "password": "hunter2pass"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signup body: {body}");
    assert!(body["access_token"].is_null(), "body: {body}");
    assert!(!body["confirmation_sent_at"].is_null(), "body: {body}");

    let messages = mailer.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].email_type, EmailType::Signup);
    assert_eq!(messages[0].to, "alice@example.com");

    let token = extract_token(&messages[0].html);

    // Password grant before confirming: typed 400.
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/token?grant_type=password",
        Some(&h.anon),
        None,
        Some(json!({"email": "alice@example.com", "password": "hunter2pass"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error_code"], "email_not_confirmed");

    // Verify.
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify body: {body}");
    assert!(body["access_token"].is_string());
    let access = body["access_token"].as_str().unwrap().to_string();

    let (status, _h, user) = call(
        &h.app,
        "GET",
        "/auth/v1/user",
        Some(&h.anon),
        Some(&access),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "user body: {user}");
    assert!(!user["email_confirmed_at"].is_null(), "user: {user}");

    // Password grant now succeeds.
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/token?grant_type=password",
        Some(&h.anon),
        None,
        Some(json!({"email": "alice@example.com", "password": "hunter2pass"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn get_verify_redirects_with_token_fragment() {
    let (h, mailer) = harness_with_mailer(ServiceConfig {
        require_email_confirmation: true,
        ..ServiceConfig::default()
    })
    .await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "bob@example.com", "password": "hunter2pass"})),
    )
    .await;
    let messages = mailer.messages();
    let token = extract_token(&messages[0].html);

    // No apikey header at all: the open_router wiring must still work.
    let (status, headers, _body) = call_raw(
        &h.app,
        "GET",
        &format!("/auth/v1/verify?token={token}&type=signup"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "headers: {headers:?}");
    let location = headers
        .get("location")
        .expect("Location header")
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("http://localhost:3000"),
        "location: {location}"
    );
    assert!(location.contains("access_token="), "location: {location}");
    assert!(location.contains("type=signup"), "location: {location}");
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recover_flow_issues_session_and_allows_password_change() {
    let (h, mailer) = harness_with_mailer(ServiceConfig::default()).await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "carol@example.com", "password": "original-pass-1"})),
    )
    .await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/recover",
        Some(&h.anon),
        None,
        Some(json!({"email": "carol@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, json!({}));

    let messages = mailer.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].email_type, EmailType::Recovery);
    let token = extract_token(&messages[0].html);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "recovery", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access = body["access_token"].as_str().unwrap().to_string();

    let (status, _h, body) = call(
        &h.app,
        "PUT",
        "/auth/v1/user",
        Some(&h.anon),
        Some(&access),
        Some(json!({"password": "new-password-123"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/token?grant_type=password",
        Some(&h.anon),
        None,
        Some(json!({"email": "carol@example.com", "password": "new-password-123"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "new password body: {body}");

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/token?grant_type=password",
        Some(&h.anon),
        None,
        Some(json!({"email": "carol@example.com", "password": "original-pass-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "old password body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn recover_unknown_email_is_silent_200() {
    let (h, mailer) = harness_with_mailer(ServiceConfig::default()).await;
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/recover",
        Some(&h.anon),
        None,
        Some(json!({"email": "nobody@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, json!({}));
    assert!(mailer.messages().is_empty());
}

// ---------------------------------------------------------------------------
// OTP / magic link
// ---------------------------------------------------------------------------

#[tokio::test]
async fn otp_magic_link_creates_and_signs_in() {
    let (h, mailer) = harness_with_mailer(ServiceConfig::default()).await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/otp",
        Some(&h.anon),
        None,
        Some(json!({"email": "new@x.com", "create_user": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let messages = mailer.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].email_type, EmailType::MagicLink);
    let token = extract_token(&messages[0].html);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "magiclink", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["access_token"].is_string());
    assert!(
        !body["user"]["email_confirmed_at"].is_null(),
        "body: {body}"
    );
}

#[tokio::test]
async fn otp_with_phone_is_typed_501() {
    let (h, _mailer) = harness_with_mailer(ServiceConfig::default()).await;
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/otp",
        Some(&h.anon),
        None,
        Some(json!({"phone": "+15550100"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(body["code"], "SUPA_COMPAT_AUTH_SMS_NOT_IMPLEMENTED");
}

// ---------------------------------------------------------------------------
// Expiry / reuse / bogus tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_token_is_403_otp_expired() {
    let (h, mailer) = harness_with_mailer(ServiceConfig {
        require_email_confirmation: true,
        mailer_otp_exp: 0,
        ..ServiceConfig::default()
    })
    .await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "dave@example.com", "password": "hunter2pass"})),
    )
    .await;
    let messages = mailer.messages();
    let token = extract_token(&messages[0].html);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error_code"], "otp_expired");

    let (status, headers, _body) = call_raw(
        &h.app,
        "GET",
        &format!("/auth/v1/verify?token={token}&type=signup"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers.get("location").unwrap().to_str().unwrap();
    assert!(
        location.contains("error_code=otp_expired"),
        "location: {location}"
    );
}

#[tokio::test]
async fn reused_token_is_403() {
    let (h, mailer) = harness_with_mailer(ServiceConfig {
        require_email_confirmation: true,
        ..ServiceConfig::default()
    })
    .await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "erin@example.com", "password": "hunter2pass"})),
    )
    .await;
    let messages = mailer.messages();
    let token = extract_token(&messages[0].html);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first verify body: {body}");

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "second verify body: {body}");
    assert_eq!(body["error_code"], "otp_expired");
}

#[tokio::test]
async fn bogus_token_is_403() {
    let h = harness().await;
    let bogus = "a".repeat(64);
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": bogus})),
    )
    .await;
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_ne!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
}

#[tokio::test]
async fn verify_email_change_and_sms_are_typed_501() {
    let h = harness().await;
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "email_change", "token": "x".repeat(64)})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(
        body["code"],
        "SUPA_COMPAT_AUTH_EMAIL_CHANGE_NOT_IMPLEMENTED"
    );

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "sms", "token": "x".repeat(64)})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(body["code"], "SUPA_COMPAT_AUTH_SMS_NOT_IMPLEMENTED");
}

// ---------------------------------------------------------------------------
// Resend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resend_rotates_token() {
    let (h, mailer) = harness_with_mailer(ServiceConfig {
        require_email_confirmation: true,
        ..ServiceConfig::default()
    })
    .await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "frank@example.com", "password": "hunter2pass"})),
    )
    .await;
    let token1 = extract_token(&mailer.messages()[0].html);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/resend",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "email": "frank@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let messages = mailer.messages();
    assert_eq!(messages.len(), 2);
    let token2 = extract_token(&messages[1].html);
    assert_ne!(token1, token2);

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token1})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "token1 body: {body}");

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/verify",
        Some(&h.anon),
        None,
        Some(json!({"type": "signup", "token": token2})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token2 body: {body}");
}

// ---------------------------------------------------------------------------
// Mailer configuration errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unconfigured_mailer_is_typed_error() {
    let h = harness_with_config(ServiceConfig {
        require_email_confirmation: true,
        ..ServiceConfig::default()
    })
    .await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "gina@example.com", "password": "hunter2pass"})),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["code"], "SUPA_COMPAT_AUTH_MAILER_NOT_CONFIGURED");

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/recover",
        Some(&h.anon),
        None,
        Some(json!({"email": "gina@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["code"], "SUPA_COMPAT_AUTH_MAILER_NOT_CONFIGURED");
}

#[tokio::test]
async fn smtp_config_is_typed_501() {
    let h = harness_with_config(ServiceConfig {
        mailer: MailerConfig::Smtp {
            host: "localhost".into(),
        },
        ..ServiceConfig::default()
    })
    .await;

    // Default config autoconfirms signup, so this user exists and is
    // confirmed by the time /recover is called.
    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "harry@example.com", "password": "hunter2pass"})),
    )
    .await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/recover",
        Some(&h.anon),
        None,
        Some(json!({"email": "harry@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(body["code"], "SUPA_COMPAT_AUTH_SMTP_NOT_IMPLEMENTED");
}

// ---------------------------------------------------------------------------
// HttpMailer: production transport, end to end, no real network
// ---------------------------------------------------------------------------

/// Requests captured by [`spawn_mail_capture_server`], oldest first.
type CapturedRequests = Arc<tokio::sync::Mutex<Vec<(HeaderMap, Bytes)>>>;

/// A tiny axum server standing in for an operator's mail webhook: captures
/// every request's headers + body into a shared `Vec` the test can inspect.
async fn spawn_mail_capture_server() -> (std::net::SocketAddr, CapturedRequests) {
    let captured: CapturedRequests = Arc::default();

    async fn capture(
        State(captured): State<CapturedRequests>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        captured.lock().await.push((headers, body));
        StatusCode::OK.into_response()
    }

    let app = Router::new()
        .fallback(axum::routing::any(capture))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (addr, captured)
}

#[tokio::test]
async fn http_mailer_posts_generic_json() {
    let (addr, captured) = spawn_mail_capture_server().await;

    let h = harness_with_config(ServiceConfig {
        mailer: MailerConfig::Http {
            url: format!("http://{addr}"),
            authorization: Some(Secret::new("Bearer sekrit")),
        },
        ..ServiceConfig::default()
    })
    .await;

    call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "ivy@example.com", "password": "hunter2pass"})),
    )
    .await;

    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/recover",
        Some(&h.anon),
        None,
        Some(json!({"email": "ivy@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 1, "expected exactly one webhook POST");
    let (headers, bytes) = &requests[0];
    assert_eq!(
        headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer sekrit"
    );
    let payload: Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(payload["to"], "ivy@example.com");
    assert!(payload["subject"].is_string());
    assert_eq!(payload["type"], "recovery");
    assert!(
        payload["html"]
            .as_str()
            .unwrap()
            .contains("/auth/v1/verify?token="),
        "html: {}",
        payload["html"]
    );
    assert!(payload["text"].is_string());
}

// ---------------------------------------------------------------------------
// Regression guard: default config's autoconfirm behavior is unaffected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_config_signup_unchanged() {
    let h = harness().await;
    let (status, _h, body) = call(
        &h.app,
        "POST",
        "/auth/v1/signup",
        Some(&h.anon),
        None,
        Some(json!({"email": "jill@example.com", "password": "hunter2pass"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["access_token"].is_string(), "body: {body}");
}
