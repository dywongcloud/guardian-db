//! GoTrue-compatible authentication over the SQL engine.
//!
//! On first use the `auth` schema is bootstrapped by running DDL through a
//! [`Session`](crate::sql::engine::Session) (see [`BOOTSTRAP_SQL`]). Passwords
//! are hashed with `bcrypt` (the same crate the pgcrypto extension uses); access
//! tokens are HS256 JWTs signed with the project secret; refresh tokens are
//! opaque, rotated on use, and stored in `auth.refresh_tokens`.
//!
//! Responses match GoTrue's JSON: the token endpoints return an
//! `AccessTokenResponse` (`{access_token, token_type:"bearer", expires_in,
//! expires_at, refresh_token, user}`), and errors use GoTrue's
//! `{code,error_code,msg}` / `{error,error_description}` shapes. OAuth/SSO
//! providers return a typed [`SupaError::AuthProviderUnsupported`], never fake
//! success.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json as AxumJson};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::sql::{ExecResult, OutField, RelationalStorage, SqlValue};
use crate::supabase::error::{SupaError, gotrue_error, gotrue_oauth_error};
use crate::supabase::gateway::{AppState, AuthContext, run_batch, run_sql};
use crate::supabase::jwt::{self, Claims};
use crate::supabase::mailer::{self, EmailType};
use crate::supabase::rest::{parse_query_pairs, value_to_json};

/// bcrypt work factor for stored passwords (kept moderate so tests stay fast
/// while remaining well above brute-force feasibility).
const AUTH_BCRYPT_COST: u32 = 10;

/// The columns selected whenever a user is returned to a client.
const USER_COLUMNS: &str = "id, aud, role, email, email_confirmed_at, last_sign_in_at, \
     raw_app_meta_data, raw_user_meta_data, created_at, updated_at, phone, is_anonymous, \
     confirmation_sent_at, recovery_sent_at";

/// The `auth` schema bootstrap. Column set is the Supabase/GoTrue subset that
/// GuardianDB's engine supports (uuid / text / timestamptz / jsonb / boolean /
/// bigint). All statements are `IF NOT EXISTS`, so bootstrap is idempotent.
///
/// Notes on divergence from stock Supabase (verified against GuardianDB's
/// engine): GoTrue's generated/identity columns, partial indexes and
/// `CHECK`-heavy columns are omitted; `auth.refresh_tokens` is keyed by its
/// opaque `token` (stock uses a `bigserial id`), which the engine supports as a
/// text primary key.
pub const BOOTSTRAP_SQL: &str = "
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.users (
    id uuid PRIMARY KEY,
    aud text,
    role text,
    email text,
    encrypted_password text,
    email_confirmed_at timestamptz,
    invited_at timestamptz,
    confirmation_token text,
    confirmation_sent_at timestamptz,
    recovery_token text,
    recovery_sent_at timestamptz,
    email_change_token_new text,
    email_change text,
    email_change_sent_at timestamptz,
    last_sign_in_at timestamptz,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_super_admin boolean,
    created_at timestamptz,
    updated_at timestamptz,
    phone text,
    phone_confirmed_at timestamptz,
    banned_until timestamptz,
    deleted_at timestamptz,
    is_anonymous boolean
);

CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
    token text PRIMARY KEY,
    user_id uuid,
    session_id uuid,
    parent text,
    revoked boolean,
    created_at timestamptz,
    updated_at timestamptz
);

CREATE TABLE IF NOT EXISTS auth.sessions (
    id uuid PRIMARY KEY,
    user_id uuid,
    created_at timestamptz,
    updated_at timestamptz,
    not_after timestamptz,
    aal text
);

CREATE TABLE IF NOT EXISTS auth.identities (
    id uuid PRIMARY KEY,
    user_id uuid,
    identity_data jsonb,
    provider text,
    provider_id text,
    email text,
    created_at timestamptz,
    updated_at timestamptz
);

CREATE TABLE IF NOT EXISTS auth.audit_log_entries (
    id uuid PRIMARY KEY,
    payload jsonb,
    ip_address text,
    created_at timestamptz
);

CREATE TABLE IF NOT EXISTS auth.instances (
    id uuid PRIMARY KEY,
    raw_base_config text,
    created_at timestamptz,
    updated_at timestamptz
);

CREATE TABLE IF NOT EXISTS auth.schema_migrations (
    version text PRIMARY KEY
);
";

/// The Auth subrouter mounted at `/auth/v1`, behind the gateway's apikey
/// layer.
pub fn router<S: RelationalStorage + 'static>() -> Router<AppState<S>> {
    Router::new()
        .route("/signup", post(signup::<S>))
        .route("/token", post(token::<S>))
        .route("/logout", post(logout::<S>))
        .route("/recover", post(recover::<S>))
        .route("/otp", post(otp::<S>))
        .route("/magiclink", post(otp::<S>))
        .route("/resend", post(resend::<S>))
        .route("/user", get(get_user::<S>).put(put_user::<S>))
        .route(
            "/admin/users",
            get(admin_list_users::<S>).post(admin_create_user::<S>),
        )
        .route(
            "/admin/users/{id}",
            get(admin_get_user::<S>)
                .put(admin_update_user::<S>)
                .delete(admin_delete_user::<S>),
        )
}

/// The credential-less subrouter mounted at `/auth/v1`, OUTSIDE the gateway's
/// apikey layer: `GET`/`POST /verify` is the target of the link a browser
/// follows straight out of an email, which carries no `apikey` header (see
/// [`crate::supabase::gateway::build_router`]).
pub fn open_router<S: RelationalStorage + 'static>() -> Router<AppState<S>> {
    Router::new().route("/verify", get(verify_get::<S>).post(verify_post::<S>))
}

// ---------------------------------------------------------------------------
// Schema bootstrap
// ---------------------------------------------------------------------------

/// Bootstrap the `auth` schema exactly once for this gateway instance.
pub async fn ensure_schema<S: RelationalStorage + 'static>(
    state: &AppState<S>,
) -> Result<(), SupaError> {
    state
        .schema_ready
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
// signup
// ---------------------------------------------------------------------------

async fn signup<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        if state.config.disable_signup {
            return Ok(gotrue_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "signup_disabled",
                "Signups not allowed for this instance",
            ));
        }
        let obj = json_object(&body)?;
        let email = require_email(&obj)?;
        let password = require_password(&obj)?;
        let metadata = obj.get("data").cloned().unwrap_or_else(|| json!({}));

        if find_user_by_email(&state, &email).await?.is_some() {
            return Ok(gotrue_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "user_already_exists",
                "User already registered",
            ));
        }

        if state.config.require_email_confirmation {
            // Fail closed, before any row is created: a misconfigured
            // deployment must never leave an orphaned unconfirmed user with
            // no way to ever receive the confirmation link.
            if !state.mailer.is_configured() {
                return Err(SupaError::MailerNotConfigured);
            }
            let user_id = uuid::Uuid::new_v4();
            create_user_row(&state, user_id, &email, &password, metadata, false).await?;
            let redirect_to = extract_redirect_to(&obj);
            send_auth_email(
                &state,
                EmailType::Signup,
                user_id,
                &email,
                redirect_to.as_deref(),
            )
            .await?;
            let user = fetch_user_json(&state, "id", &SqlValue::Uuid(user_id))
                .await?
                .ok_or_else(|| SupaError::Internal("user vanished after insert".into()))?;
            // GoTrue does not issue a session until the confirmation link is
            // clicked: bare user JSON, no access_token.
            return Ok((StatusCode::OK, AxumJson(user)).into_response());
        }

        let user_id = uuid::Uuid::new_v4();
        create_user_row(&state, user_id, &email, &password, metadata, true).await?;
        let issued = issue_session(&state, user_id, &email).await?;
        let user = fetch_user_json(&state, "id", &SqlValue::Uuid(user_id))
            .await?
            .ok_or_else(|| SupaError::Internal("user vanished after insert".into()))?;
        Ok((
            StatusCode::OK,
            AxumJson(access_token_response(&issued, user)),
        )
            .into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// token (grant_type = password | refresh_token)
// ---------------------------------------------------------------------------

async fn token<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let grant = parse_query_pairs(query.as_deref().unwrap_or(""))
            .into_iter()
            .find(|(k, _)| k == "grant_type")
            .map(|(_, v)| v)
            .unwrap_or_default();
        match grant.as_str() {
            "password" => token_password(&state, &body).await,
            "refresh_token" => token_refresh(&state, &body).await,
            "" => Ok(gotrue_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "grant_type is required",
            )),
            other if is_oauth_grant(other) => {
                Err(SupaError::AuthProviderUnsupported(other.to_string()))
            }
            other => Ok(gotrue_oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("grant_type \"{other}\" is not supported"),
            )),
        }
    })
    .await
}

async fn token_password<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    body: &[u8],
) -> Result<Response, SupaError> {
    let obj = json_object(body)?;
    let email = require_email(&obj)?;
    let password = require_password(&obj)?;

    let Some((user_id, hash, email_confirmed_at)) = find_user_credentials(state, &email).await?
    else {
        return Ok(invalid_credentials());
    };
    if !verify_password(&password, &hash) {
        return Ok(invalid_credentials());
    }
    if email_confirmed_at.is_none() {
        return Ok(gotrue_error(
            StatusCode::BAD_REQUEST,
            "email_not_confirmed",
            "Email not confirmed",
        ));
    }
    mark_signed_in(state, user_id).await?;
    let issued = issue_session(state, user_id, &email).await?;
    let user = fetch_user_json(state, "id", &SqlValue::Uuid(user_id))
        .await?
        .ok_or_else(|| SupaError::Internal("user missing".into()))?;
    Ok((
        StatusCode::OK,
        AxumJson(access_token_response(&issued, user)),
    )
        .into_response())
}

async fn token_refresh<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    body: &[u8],
) -> Result<Response, SupaError> {
    let obj = json_object(body)?;
    let token = obj
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| SupaError::BadRequest("refresh_token is required".into()))?;

    // Look up a live (non-revoked) refresh token.
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT user_id, session_id FROM auth.refresh_tokens WHERE token = $1 AND revoked = FALSE",
        vec![SqlValue::Text(token.clone())],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    let Some(row) = rows.first() else {
        return Ok(gotrue_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Invalid Refresh Token: Already Used",
        ));
    };
    let user_id = match &row[0] {
        SqlValue::Uuid(u) => *u,
        other => uuid::Uuid::parse_str(&other.to_text().unwrap_or_default())
            .map_err(|_| SupaError::Internal("bad user_id on refresh token".into()))?,
    };
    let session_id = match &row[1] {
        SqlValue::Uuid(u) => Some(*u),
        SqlValue::Null => None,
        other => uuid::Uuid::parse_str(&other.to_text().unwrap_or_default()).ok(),
    };

    // Rotate: revoke the presented token, mint a new one on the same session.
    run_sql(
        &state.db,
        "service_role",
        "UPDATE auth.refresh_tokens SET revoked = TRUE, updated_at = $2 WHERE token = $1",
        vec![
            SqlValue::Text(token.clone()),
            SqlValue::Timestamptz(Utc::now()),
        ],
    )
    .await
    .map_err(SupaError::Sql)?;

    let email = fetch_user_email(state, user_id).await?.unwrap_or_default();
    let issued = issue_session_with(state, user_id, &email, session_id, Some(token)).await?;
    let user = fetch_user_json(state, "id", &SqlValue::Uuid(user_id))
        .await?
        .ok_or_else(|| SupaError::Internal("user missing".into()))?;
    Ok((
        StatusCode::OK,
        AxumJson(access_token_response(&issued, user)),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------

async fn logout<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let Some(uid) = auth.user_id() else {
            return Err(SupaError::InvalidJwt(jwt::JwtError::Malformed));
        };
        let user_id = uuid::Uuid::parse_str(uid)
            .map_err(|_| SupaError::BadRequest("invalid user id in token".into()))?;
        // Revoke this user's refresh tokens (all sessions in this slice).
        run_sql(
            &state.db,
            "service_role",
            "UPDATE auth.refresh_tokens SET revoked = TRUE, updated_at = $2 WHERE user_id = $1",
            vec![SqlValue::Uuid(user_id), SqlValue::Timestamptz(Utc::now())],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// recover / otp / magiclink / resend — transactional email flows
// ---------------------------------------------------------------------------

/// `POST /recover {email}` — sends a password-recovery email. Anti-enumeration:
/// an unknown email still answers `200 {}`, just without sending anything.
async fn recover<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        // Checked before any lookup: a misconfigured deployment must fail
        // typed rather than silently pretend the email was sent.
        if !state.mailer.is_configured() {
            return Err(SupaError::MailerNotConfigured);
        }
        let obj = json_object(&body)?;
        let email = require_email(&obj)?;
        let redirect_to = extract_redirect_to(&obj);
        if let Some(user_id) = find_user_by_email(&state, &email).await? {
            send_auth_email(
                &state,
                EmailType::Recovery,
                user_id,
                &email,
                redirect_to.as_deref(),
            )
            .await?;
        }
        Ok((StatusCode::OK, AxumJson(json!({}))).into_response())
    })
    .await
}

/// `POST /otp {email, create_user?}` and its `POST /magiclink {email}` alias —
/// sends a magic-link sign-in email, optionally creating the account first
/// (GoTrue's default: `create_user` defaults to `true` when absent).
async fn otp<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let obj = json_object(&body)?;
        if obj.contains_key("phone") {
            return Err(SupaError::NotImplemented("AUTH_SMS"));
        }
        if !state.mailer.is_configured() {
            return Err(SupaError::MailerNotConfigured);
        }
        let email = require_email(&obj)?;
        let create_user = obj
            .get("create_user")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let redirect_to = extract_redirect_to(&obj);

        let user_id = match find_user_by_email(&state, &email).await? {
            Some(id) => id,
            None => {
                if !create_user || state.config.disable_signup {
                    // Anti-enumeration: still answer 200 with no send.
                    return Ok((StatusCode::OK, AxumJson(json!({}))).into_response());
                }
                let new_id = uuid::Uuid::new_v4();
                // An empty encrypted_password: `require_password` (the same
                // guard `token_password` already applies to every
                // password-grant login) rejects an empty password field
                // outright, so this account can never be signed into with a
                // password — only via the magic link this call sends.
                create_user_row(&state, new_id, &email, "", json!({}), false).await?;
                new_id
            }
        };
        send_auth_email(
            &state,
            EmailType::MagicLink,
            user_id,
            &email,
            redirect_to.as_deref(),
        )
        .await?;
        Ok((StatusCode::OK, AxumJson(json!({}))).into_response())
    })
    .await
}

/// `POST /resend {type, email}` — regenerates and resends a confirmation
/// email, invalidating any previously-issued link for that flow.
async fn resend<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let obj = json_object(&body)?;
        let kind = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("signup")
            .to_string();
        match kind.as_str() {
            "email_change" => return Err(SupaError::NotImplemented("AUTH_EMAIL_CHANGE")),
            "sms" | "phone" => return Err(SupaError::NotImplemented("AUTH_SMS")),
            "signup" => {}
            other => {
                return Err(SupaError::BadRequest(format!(
                    "unsupported resend type \"{other}\""
                )));
            }
        }
        if !state.mailer.is_configured() {
            return Err(SupaError::MailerNotConfigured);
        }
        let email = require_email(&obj)?;
        let redirect_to = extract_redirect_to(&obj);

        let Some((user_id, email_confirmed_at)) = fetch_id_and_confirmed(&state, &email).await?
        else {
            return Ok((StatusCode::OK, AxumJson(json!({}))).into_response());
        };
        if email_confirmed_at.is_some() {
            // Already confirmed: nothing to resend, still 200 (anti-enumeration).
            return Ok((StatusCode::OK, AxumJson(json!({}))).into_response());
        }
        send_auth_email(
            &state,
            EmailType::Signup,
            user_id,
            &email,
            redirect_to.as_deref(),
        )
        .await?;
        Ok((StatusCode::OK, AxumJson(json!({}))).into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// verify — GET/POST, credential-less (mounted via open_router)
// ---------------------------------------------------------------------------

async fn verify_get<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    RawQuery(query): RawQuery,
) -> Response {
    let pairs = parse_query_pairs(query.as_deref().unwrap_or(""));
    let get_param = |k: &str| pairs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
    verify_common(
        &state,
        get_param("token"),
        get_param("type"),
        get_param("redirect_to"),
        true,
    )
    .await
}

async fn verify_post<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    body: Bytes,
) -> Response {
    let obj = match json_object(&body) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let str_field = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(str::to_string);
    verify_common(
        &state,
        str_field("token"),
        str_field("type"),
        str_field("redirect_to"),
        false,
    )
    .await
}

/// Shared `GET`/`POST /verify` implementation. `is_get` selects the response
/// shape: a `303` redirect carrying the session in a URL fragment for `GET`
/// (what a browser follows straight from the email link), or a `200`
/// `AccessTokenResponse` body for `POST` (what a client SDK calls
/// programmatically).
async fn verify_common<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    token: Option<String>,
    kind: Option<String>,
    redirect_to: Option<String>,
    is_get: bool,
) -> Response {
    run(async {
        ensure_schema(state).await?;
        let kind = kind.ok_or_else(|| SupaError::BadRequest("type is required".into()))?;
        let token = token.ok_or_else(|| SupaError::BadRequest("token is required".into()))?;

        match kind.as_str() {
            "email_change" => return Err(SupaError::NotImplemented("AUTH_EMAIL_CHANGE")),
            "sms" | "phone" => return Err(SupaError::NotImplemented("AUTH_SMS")),
            "signup" | "recovery" | "magiclink" => {}
            other => {
                return Err(SupaError::BadRequest(format!(
                    "unsupported verification type \"{other}\""
                )));
            }
        }

        let Some((user_id, email)) = consume_verify_token(state, &kind, &token).await? else {
            return Ok(verify_failure_response(
                state,
                is_get,
                redirect_to.as_deref(),
            ));
        };

        let now = Utc::now();
        if kind == "signup" {
            // Confirm the account and clear the (now-used) confirmation token.
            run_sql(
                &state.db,
                "service_role",
                "UPDATE auth.users SET email_confirmed_at = $1, confirmation_token = $2, \
                 updated_at = $1 WHERE id = $3",
                vec![
                    SqlValue::Timestamptz(now),
                    SqlValue::Null,
                    SqlValue::Uuid(user_id),
                ],
            )
            .await
            .map_err(SupaError::Sql)?;
        } else {
            // recovery | magiclink: clear the (now-used) recovery token; a
            // click on either link also proves email ownership, so confirm
            // the account here too if it was not already confirmed.
            let already_confirmed = fetch_email_confirmed(state, user_id).await?;
            if already_confirmed {
                run_sql(
                    &state.db,
                    "service_role",
                    "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $1, \
                     updated_at = $2 WHERE id = $3",
                    vec![
                        SqlValue::Null,
                        SqlValue::Timestamptz(now),
                        SqlValue::Uuid(user_id),
                    ],
                )
                .await
                .map_err(SupaError::Sql)?;
            } else {
                run_sql(
                    &state.db,
                    "service_role",
                    "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $1, \
                     email_confirmed_at = $2, updated_at = $2 WHERE id = $3",
                    vec![
                        SqlValue::Null,
                        SqlValue::Timestamptz(now),
                        SqlValue::Uuid(user_id),
                    ],
                )
                .await
                .map_err(SupaError::Sql)?;
            }
        }

        let issued = issue_session(state, user_id, &email).await?;

        if is_get {
            let redirect = validate_redirect_to(state, redirect_to.as_deref());
            let location = format!(
                "{redirect}#access_token={}&expires_in={}&expires_at={}&refresh_token={}&\
                 token_type=bearer&type={kind}",
                issued.access_token, issued.expires_in, issued.expires_at, issued.refresh_token,
            );
            Ok(redirect_response(&location))
        } else {
            let user = fetch_user_json(state, "id", &SqlValue::Uuid(user_id))
                .await?
                .ok_or_else(|| SupaError::Internal("user vanished after verify".into()))?;
            Ok((
                StatusCode::OK,
                AxumJson(access_token_response(&issued, user)),
            )
                .into_response())
        }
    })
    .await
}

/// The response for an invalid, expired, or already-consumed token: a typed
/// `403` for `POST`, a `303` redirect carrying the error in the fragment for
/// `GET` (so a browser lands on the app with an actionable error instead of a
/// bare JSON body).
fn verify_failure_response<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    is_get: bool,
    redirect_to: Option<&str>,
) -> Response {
    if is_get {
        let redirect = validate_redirect_to(state, redirect_to);
        let location = format!(
            "{redirect}#error=access_denied&error_code=otp_expired&\
             error_description=Email+link+is+invalid+or+has+expired"
        );
        redirect_response(&location)
    } else {
        gotrue_error(
            StatusCode::FORBIDDEN,
            "otp_expired",
            "Email link is invalid or has expired",
        )
    }
}

fn redirect_response(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(location) {
        resp.headers_mut().insert("location", value);
    }
    resp
}

// ---------------------------------------------------------------------------
// GET / PUT /user
// ---------------------------------------------------------------------------

async fn get_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let user_id = require_user(&auth)?;
        match fetch_user_json(&state, "id", &SqlValue::Uuid(user_id)).await? {
            Some(user) => Ok((StatusCode::OK, AxumJson(user)).into_response()),
            None => Ok(gotrue_error(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "User not found",
            )),
        }
    })
    .await
}

async fn put_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Response {
    run(async {
        ensure_schema(&state).await?;
        let user_id = require_user(&auth)?;
        let obj = json_object(&body)?;
        apply_user_update(&state, user_id, &obj).await?;
        match fetch_user_json(&state, "id", &SqlValue::Uuid(user_id)).await? {
            Some(user) => Ok((StatusCode::OK, AxumJson(user)).into_response()),
            None => Ok(gotrue_error(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "User not found",
            )),
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// Admin (service_role only)
// ---------------------------------------------------------------------------

async fn admin_list_users<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let sql = format!("SELECT {USER_COLUMNS} FROM auth.users ORDER BY created_at");
        let result = run_sql(&state.db, "service_role", &sql, Vec::new())
            .await
            .map_err(SupaError::Sql)?;
        let (fields, rows) = rows_of(result)?;
        let users: Vec<Json> = rows.iter().map(|r| row_to_user(&fields, r)).collect();
        Ok((
            StatusCode::OK,
            AxumJson(json!({"users": users, "aud": "authenticated"})),
        )
            .into_response())
    })
    .await
}

async fn admin_create_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let obj = json_object(&body)?;
        let email = require_email(&obj)?;
        let password = obj
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let metadata = obj
            .get("user_metadata")
            .or_else(|| obj.get("data"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        if find_user_by_email(&state, &email).await?.is_some() {
            return Ok(gotrue_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "user_already_exists",
                "A user with this email address has already been registered",
            ));
        }
        let confirm = obj
            .get("email_confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let user_id = uuid::Uuid::new_v4();
        create_user_row(&state, user_id, &email, &password, metadata, confirm).await?;
        let user = fetch_user_json(&state, "id", &SqlValue::Uuid(user_id))
            .await?
            .ok_or_else(|| SupaError::Internal("user missing after insert".into()))?;
        Ok((StatusCode::OK, AxumJson(user)).into_response())
    })
    .await
}

async fn admin_get_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let user_id = parse_uuid(&id)?;
        match fetch_user_json(&state, "id", &SqlValue::Uuid(user_id)).await? {
            Some(user) => Ok((StatusCode::OK, AxumJson(user)).into_response()),
            None => Ok(gotrue_error(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "User not found",
            )),
        }
    })
    .await
}

async fn admin_update_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let user_id = parse_uuid(&id)?;
        let obj = json_object(&body)?;
        apply_user_update(&state, user_id, &obj).await?;
        match fetch_user_json(&state, "id", &SqlValue::Uuid(user_id)).await? {
            Some(user) => Ok((StatusCode::OK, AxumJson(user)).into_response()),
            None => Ok(gotrue_error(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "User not found",
            )),
        }
    })
    .await
}

async fn admin_delete_user<S: RelationalStorage + 'static>(
    State(state): State<AppState<S>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    run(async {
        require_service_role(&auth)?;
        ensure_schema(&state).await?;
        let user_id = parse_uuid(&id)?;
        let existing = fetch_user_json(&state, "id", &SqlValue::Uuid(user_id)).await?;
        if existing.is_none() {
            return Ok(gotrue_error(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "User not found",
            ));
        }
        run_sql(
            &state.db,
            "service_role",
            "DELETE FROM auth.refresh_tokens WHERE user_id = $1",
            vec![SqlValue::Uuid(user_id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        run_sql(
            &state.db,
            "service_role",
            "DELETE FROM auth.users WHERE id = $1",
            vec![SqlValue::Uuid(user_id)],
        )
        .await
        .map_err(SupaError::Sql)?;
        Ok((StatusCode::OK, AxumJson(existing.unwrap())).into_response())
    })
    .await
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

async fn create_user_row<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
    email: &str,
    password: &str,
    metadata: Json,
    confirm: bool,
) -> Result<(), SupaError> {
    let now = Utc::now();
    let hash = hash_password(password)?;
    let app_meta = json!({"provider": "email", "providers": ["email"]});
    let confirmed_at = if confirm {
        SqlValue::Timestamptz(now)
    } else {
        SqlValue::Null
    };
    run_sql(
        &state.db,
        "service_role",
        "INSERT INTO auth.users \
         (id, aud, role, email, encrypted_password, email_confirmed_at, \
          raw_app_meta_data, raw_user_meta_data, created_at, updated_at, is_anonymous) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        vec![
            SqlValue::Uuid(user_id),
            SqlValue::Text("authenticated".into()),
            SqlValue::Text("authenticated".into()),
            SqlValue::Text(email.to_string()),
            SqlValue::Text(hash),
            confirmed_at,
            SqlValue::Json(app_meta),
            SqlValue::Json(metadata),
            SqlValue::Timestamptz(now),
            SqlValue::Timestamptz(now),
            SqlValue::Bool(false),
        ],
    )
    .await
    .map_err(SupaError::Sql)?;
    Ok(())
}

async fn apply_user_update<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
    obj: &Map<String, Json>,
) -> Result<(), SupaError> {
    let mut sets: Vec<String> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();
    if let Some(email) = obj.get("email").and_then(|v| v.as_str()) {
        params.push(SqlValue::Text(email.to_lowercase()));
        sets.push(format!("email = ${}", params.len()));
    }
    if let Some(password) = obj.get("password").and_then(|v| v.as_str()) {
        params.push(SqlValue::Text(hash_password(password)?));
        sets.push(format!("encrypted_password = ${}", params.len()));
    }
    if let Some(data) = obj.get("data").or_else(|| obj.get("user_metadata")) {
        params.push(SqlValue::Json(data.clone()));
        sets.push(format!("raw_user_meta_data = ${}", params.len()));
    }
    if sets.is_empty() {
        return Ok(());
    }
    params.push(SqlValue::Timestamptz(Utc::now()));
    sets.push(format!("updated_at = ${}", params.len()));
    params.push(SqlValue::Uuid(user_id));
    let sql = format!(
        "UPDATE auth.users SET {} WHERE id = ${}",
        sets.join(", "),
        params.len()
    );
    run_sql(&state.db, "service_role", &sql, params)
        .await
        .map_err(SupaError::Sql)?;
    Ok(())
}

async fn mark_signed_in<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
) -> Result<(), SupaError> {
    let now = Utc::now();
    run_sql(
        &state.db,
        "service_role",
        "UPDATE auth.users SET last_sign_in_at = $1, updated_at = $1 WHERE id = $2",
        vec![SqlValue::Timestamptz(now), SqlValue::Uuid(user_id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    Ok(())
}

async fn find_user_by_email<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    email: &str,
) -> Result<Option<uuid::Uuid>, SupaError> {
    Ok(find_user_credentials(state, email)
        .await?
        .map(|(id, _, _)| id))
}

/// Returns `(user_id, encrypted_password, email_confirmed_at)` for the given
/// email, if a matching user exists. `email_confirmed_at` is `None` for an
/// account created with `require_email_confirmation=true` (or admin
/// `email_confirm:false`) that has not yet clicked its confirmation link.
async fn find_user_credentials<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    email: &str,
) -> Result<Option<(uuid::Uuid, String, Option<DateTime<Utc>>)>, SupaError> {
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT id, encrypted_password, email_confirmed_at FROM auth.users WHERE email = $1",
        vec![SqlValue::Text(email.to_lowercase())],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let id = match &row[0] {
        SqlValue::Uuid(u) => *u,
        other => uuid::Uuid::parse_str(&other.to_text().unwrap_or_default())
            .map_err(|_| SupaError::Internal("bad user id".into()))?,
    };
    let hash = row[1].to_text().unwrap_or_default();
    let confirmed_at = match &row[2] {
        SqlValue::Timestamptz(dt) => Some(*dt),
        _ => None,
    };
    Ok(Some((id, hash, confirmed_at)))
}

async fn fetch_user_email<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
) -> Result<Option<String>, SupaError> {
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT email FROM auth.users WHERE id = $1",
        vec![SqlValue::Uuid(user_id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .and_then(|v| v.to_text()))
}

async fn fetch_user_json<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    column: &str,
    value: &SqlValue,
) -> Result<Option<Json>, SupaError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM auth.users WHERE {column} = $1");
    let result = run_sql(&state.db, "service_role", &sql, vec![value.clone()])
        .await
        .map_err(SupaError::Sql)?;
    let (fields, rows) = rows_of(result)?;
    Ok(rows.first().map(|r| row_to_user(&fields, r)))
}

// ---------------------------------------------------------------------------
// Token issuance
// ---------------------------------------------------------------------------

struct Issued {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    expires_at: i64,
}

async fn issue_session<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
    email: &str,
) -> Result<Issued, SupaError> {
    issue_session_with(state, user_id, email, None, None).await
}

/// Issue an access + refresh token, creating a session when one is not supplied
/// (fresh sign-in) or reusing `session_id` (refresh rotation).
async fn issue_session_with<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
    email: &str,
    session_id: Option<uuid::Uuid>,
    parent: Option<String>,
) -> Result<Issued, SupaError> {
    let now = Utc::now();
    let session_id = match session_id {
        Some(s) => s,
        None => {
            let s = uuid::Uuid::new_v4();
            run_sql(
                &state.db,
                "service_role",
                "INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) \
                 VALUES ($1, $2, $3, $3, $4)",
                vec![
                    SqlValue::Uuid(s),
                    SqlValue::Uuid(user_id),
                    SqlValue::Timestamptz(now),
                    SqlValue::Text("aal1".into()),
                ],
            )
            .await
            .map_err(SupaError::Sql)?;
            s
        }
    };

    let refresh = random_token();
    run_sql(
        &state.db,
        "service_role",
        "INSERT INTO auth.refresh_tokens \
         (token, user_id, session_id, parent, revoked, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, FALSE, $5, $5)",
        vec![
            SqlValue::Text(refresh.clone()),
            SqlValue::Uuid(user_id),
            SqlValue::Uuid(session_id),
            parent.map(SqlValue::Text).unwrap_or(SqlValue::Null),
            SqlValue::Timestamptz(now),
        ],
    )
    .await
    .map_err(SupaError::Sql)?;

    let iat = now.timestamp();
    let exp = iat + state.config.jwt_exp;
    let claims = Claims {
        iss: Some(format!("{}/auth/v1", state.project.api_url)),
        role: "authenticated".to_string(),
        sub: Some(user_id.to_string()),
        email: Some(email.to_string()),
        aud: Some(state.config.jwt_aud.clone()),
        iat,
        exp,
        session_id: Some(session_id.to_string()),
        extra: Map::new(),
    };
    let access_token = jwt::sign(&claims, state.project.keys.jwt_secret.expose())
        .map_err(|e| SupaError::Internal(format!("token signing failed: {e}")))?;

    Ok(Issued {
        access_token,
        refresh_token: refresh,
        expires_in: state.config.jwt_exp,
        expires_at: exp,
    })
}

fn access_token_response(issued: &Issued, user: Json) -> Json {
    json!({
        "access_token": issued.access_token,
        "token_type": "bearer",
        "expires_in": issued.expires_in,
        "expires_at": issued.expires_at,
        "refresh_token": issued.refresh_token,
        "user": user,
    })
}

// ---------------------------------------------------------------------------
// Email flows: token discipline, sending, and verification
// ---------------------------------------------------------------------------
//
// A raw token (from `random_token()`, the same 64-hex-char generator used for
// refresh tokens) is what goes in the emailed link. Only `sha256(raw)` — never
// the raw token — is written to `auth.users.confirmation_token` /
// `recovery_token`, because rows replicate to peers in GuardianDB-backed
// deployments and a leaked replica must not yield a usable link. The `token`
// query/body parameter `/verify` accepts is therefore already what GoTrue
// calls a `token_hash`: rehashing it and matching against the stored hash is
// the whole verification, no separate `token_hash` code path is needed.

/// `sha256(raw)` as lowercase hex — the form stored in `confirmation_token` /
/// `recovery_token`.
fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Percent-encode a value for embedding as a single query-parameter value
/// (RFC 3986 unreserved set passed through verbatim; everything else escaped).
fn percent_encode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A caller-supplied redirect is only honored when it targets this
/// deployment: the site (`config.site_url`) or the gateway's own API
/// (`project.api_url`, used e.g. by a mobile deep link scheme registered
/// there). Anything else falls back to `site_url`, exactly like GoTrue's
/// allow-list behavior — an open redirect in a password-reset link is a
/// account-takeover primitive.
fn validate_redirect_to<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    requested: Option<&str>,
) -> String {
    match requested {
        Some(url)
            if url.starts_with(&state.config.site_url)
                || url.starts_with(&state.project.api_url) =>
        {
            url.to_string()
        }
        _ => state.config.site_url.clone(),
    }
}

/// Extracts an optional redirect target from a request body, accepting both
/// the flat `redirect_to` GuardianDB/GoTrue REST convention and
/// supabase-js's nested `options.{emailRedirectTo,redirectTo}`.
fn extract_redirect_to(obj: &Map<String, Json>) -> Option<String> {
    obj.get("redirect_to")
        .or_else(|| obj.get("options").and_then(|o| o.get("emailRedirectTo")))
        .or_else(|| obj.get("options").and_then(|o| o.get("redirectTo")))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Generates a fresh raw token, stores its hash (+ `*_sent_at`) in the column
/// pair `kind` uses, and sends the matching built-in template through
/// `state.mailer`. `EmailType::Recovery` and `EmailType::MagicLink` share the
/// `recovery_token`/`recovery_sent_at` columns — GoTrue itself has only one
/// "click a link to sign in" token slot per user.
async fn send_auth_email<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    kind: EmailType,
    user_id: uuid::Uuid,
    email: &str,
    redirect_to: Option<&str>,
) -> Result<(), SupaError> {
    let raw_token = random_token();
    let hashed = hash_token(&raw_token);
    let now = Utc::now();
    let (token_col, sent_col) = match kind {
        EmailType::Signup => ("confirmation_token", "confirmation_sent_at"),
        EmailType::Recovery | EmailType::MagicLink => ("recovery_token", "recovery_sent_at"),
    };
    let sql = format!("UPDATE auth.users SET {token_col} = $1, {sent_col} = $2 WHERE id = $3");
    run_sql(
        &state.db,
        "service_role",
        &sql,
        vec![
            SqlValue::Text(hashed),
            SqlValue::Timestamptz(now),
            SqlValue::Uuid(user_id),
        ],
    )
    .await
    .map_err(SupaError::Sql)?;

    let redirect = validate_redirect_to(state, redirect_to);
    let type_str = kind.as_str();
    let confirmation_url = format!(
        "{}/auth/v1/verify?token={raw_token}&type={type_str}&redirect_to={}",
        state.project.api_url,
        percent_encode_query_value(&redirect),
    );

    let vars = [
        ("ConfirmationURL", confirmation_url.as_str()),
        ("Token", raw_token.as_str()),
        ("SiteURL", state.config.site_url.as_str()),
        ("Email", email),
    ];
    let (subject, text_tpl, html_tpl) = match kind {
        EmailType::Signup => (
            mailer::SIGNUP_SUBJECT,
            mailer::SIGNUP_TEMPLATE_TEXT,
            mailer::SIGNUP_TEMPLATE_HTML,
        ),
        EmailType::Recovery => (
            mailer::RECOVERY_SUBJECT,
            mailer::RECOVERY_TEMPLATE_TEXT,
            mailer::RECOVERY_TEMPLATE_HTML,
        ),
        EmailType::MagicLink => (
            mailer::MAGICLINK_SUBJECT,
            mailer::MAGICLINK_TEMPLATE_TEXT,
            mailer::MAGICLINK_TEMPLATE_HTML,
        ),
    };

    state
        .mailer
        .send(mailer::EmailMessage {
            to: email.to_string(),
            subject: subject.to_string(),
            html: mailer::render(html_tpl, &vars),
            text: mailer::render(text_tpl, &vars),
            email_type: kind,
        })
        .await?;
    Ok(())
}

/// Looks up the user whose stored hash (for `kind`'s column pair) matches
/// `sha256(token_or_hash)`, and checks it has not expired against
/// `config.mailer_otp_exp`. Returns `Some((user_id, email))` on a live match,
/// `None` for no match / already-cleared / expired — the caller decides how
/// to render that (a `403` or a redirect-with-error). Does not clear the
/// token itself: signup vs. recovery/magiclink apply different follow-up
/// writes, so the caller does that after deciding what "success" means here.
async fn consume_verify_token<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    kind: &str,
    token_or_hash: &str,
) -> Result<Option<(uuid::Uuid, String)>, SupaError> {
    let (token_col, sent_col) = match kind {
        "signup" => ("confirmation_token", "confirmation_sent_at"),
        "recovery" | "magiclink" => ("recovery_token", "recovery_sent_at"),
        _ => return Ok(None),
    };
    let hashed = hash_token(token_or_hash);
    let sql = format!("SELECT id, email, {sent_col} FROM auth.users WHERE {token_col} = $1");
    let result = run_sql(
        &state.db,
        "service_role",
        &sql,
        vec![SqlValue::Text(hashed)],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let sent_at = match &row[2] {
        SqlValue::Timestamptz(dt) => *dt,
        _ => return Ok(None),
    };
    let expires_at = sent_at + chrono::Duration::seconds(state.config.mailer_otp_exp);
    if Utc::now() > expires_at {
        return Ok(None);
    }
    let user_id = match &row[0] {
        SqlValue::Uuid(u) => *u,
        other => uuid::Uuid::parse_str(&other.to_text().unwrap_or_default())
            .map_err(|_| SupaError::Internal("bad user id on verify".into()))?,
    };
    let email = row[1].to_text().unwrap_or_default();
    Ok(Some((user_id, email)))
}

/// Whether `user_id`'s email is already confirmed (used by `/verify` to
/// decide whether a recovery/magiclink click needs to also set
/// `email_confirmed_at`) and by `/resend` to skip re-sending a signup
/// confirmation that has already been used.
async fn fetch_email_confirmed<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    user_id: uuid::Uuid,
) -> Result<bool, SupaError> {
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT email_confirmed_at FROM auth.users WHERE id = $1",
        vec![SqlValue::Uuid(user_id)],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    Ok(rows
        .first()
        .map(|r| !matches!(r[0], SqlValue::Null))
        .unwrap_or(false))
}

/// `(user_id, email_confirmed_at)` for `/resend`'s anti-enumeration + already-
/// confirmed checks in one query.
async fn fetch_id_and_confirmed<S: RelationalStorage + 'static>(
    state: &AppState<S>,
    email: &str,
) -> Result<Option<(uuid::Uuid, Option<DateTime<Utc>>)>, SupaError> {
    let result = run_sql(
        &state.db,
        "service_role",
        "SELECT id, email_confirmed_at FROM auth.users WHERE email = $1",
        vec![SqlValue::Text(email.to_lowercase())],
    )
    .await
    .map_err(SupaError::Sql)?;
    let (_, rows) = rows_of(result)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let user_id = match &row[0] {
        SqlValue::Uuid(u) => *u,
        other => uuid::Uuid::parse_str(&other.to_text().unwrap_or_default())
            .map_err(|_| SupaError::Internal("bad user id".into()))?,
    };
    let confirmed_at = match &row[1] {
        SqlValue::Timestamptz(dt) => Some(*dt),
        _ => None,
    };
    Ok(Some((user_id, confirmed_at)))
}

// ---------------------------------------------------------------------------
// User JSON shaping
// ---------------------------------------------------------------------------

fn row_to_user(fields: &[OutField], row: &[SqlValue]) -> Json {
    let mut m = Map::new();
    for (f, v) in fields.iter().zip(row.iter()) {
        m.insert(f.name.clone(), value_to_json(v));
    }
    let app_metadata = m
        .remove("raw_app_meta_data")
        .filter(|v| !v.is_null())
        .unwrap_or_else(|| json!({}));
    let user_metadata = m
        .remove("raw_user_meta_data")
        .filter(|v| !v.is_null())
        .unwrap_or_else(|| json!({}));
    let take = |m: &mut Map<String, Json>, k: &str| m.remove(k).unwrap_or(Json::Null);
    let email_confirmed_at = m.get("email_confirmed_at").cloned().unwrap_or(Json::Null);
    json!({
        "id": take(&mut m, "id"),
        "aud": take(&mut m, "aud"),
        "role": take(&mut m, "role"),
        "email": take(&mut m, "email"),
        "email_confirmed_at": email_confirmed_at,
        "confirmed_at": take(&mut m, "email_confirmed_at"),
        "phone": m.remove("phone").filter(|v| !v.is_null()).unwrap_or_else(|| json!("")),
        "last_sign_in_at": take(&mut m, "last_sign_in_at"),
        "app_metadata": app_metadata,
        "user_metadata": user_metadata,
        "identities": json!([]),
        "created_at": take(&mut m, "created_at"),
        "updated_at": take(&mut m, "updated_at"),
        "is_anonymous": m.remove("is_anonymous").filter(|v| !v.is_null()).unwrap_or(Json::Bool(false)),
        "confirmation_sent_at": take(&mut m, "confirmation_sent_at"),
        "recovery_sent_at": take(&mut m, "recovery_sent_at"),
    })
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

fn hash_password(password: &str) -> Result<String, SupaError> {
    bcrypt::hash(password, AUTH_BCRYPT_COST)
        .map_err(|e| SupaError::Internal(format!("password hashing failed: {e}")))
}

fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Run a fallible response-producing future, mapping any [`SupaError`] to its
/// response so handlers stay flat.
async fn run<F>(fut: F) -> Response
where
    F: std::future::Future<Output = Result<Response, SupaError>>,
{
    match fut.await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

fn json_object(body: &[u8]) -> Result<Map<String, Json>, SupaError> {
    if body.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Json>(body) {
        Ok(Json::Object(o)) => Ok(o),
        Ok(Json::Null) => Ok(Map::new()),
        Ok(_) => Err(SupaError::BadRequest(
            "request body must be a JSON object".into(),
        )),
        Err(e) => Err(SupaError::BadRequest(format!("invalid JSON body: {e}"))),
    }
}

fn require_email(obj: &Map<String, Json>) -> Result<String, SupaError> {
    let email = obj
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SupaError::BadRequest("email is required".into()))?;
    Ok(email)
}

fn require_password(obj: &Map<String, Json>) -> Result<String, SupaError> {
    obj.get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| SupaError::BadRequest("password is required".into()))
}

fn require_user(auth: &AuthContext) -> Result<uuid::Uuid, SupaError> {
    let uid = auth
        .user_id()
        .ok_or(SupaError::InvalidJwt(jwt::JwtError::Malformed))?;
    parse_uuid(uid)
}

fn require_service_role(auth: &AuthContext) -> Result<(), SupaError> {
    if auth.is_service_role() {
        Ok(())
    } else {
        Err(SupaError::Forbidden("the admin API"))
    }
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, SupaError> {
    uuid::Uuid::parse_str(s).map_err(|_| SupaError::BadRequest(format!("invalid user id: {s}")))
}

fn invalid_credentials() -> Response {
    gotrue_oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "Invalid login credentials",
    )
}

fn is_oauth_grant(grant: &str) -> bool {
    matches!(
        grant,
        "authorization_code" | "pkce" | "id_token" | "web3" | "implicit"
    )
}

fn random_token() -> String {
    // Two v4 UUIDs (OS CSPRNG) → 64 hex chars of unpredictable entropy.
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn rows_of(result: ExecResult) -> Result<(Vec<OutField>, Vec<Vec<SqlValue>>), SupaError> {
    match result {
        ExecResult::Rows { fields, rows } => Ok((fields, rows)),
        ExecResult::Command { tag } => Err(SupaError::Internal(format!(
            "expected rows, got command tag: {tag}"
        ))),
    }
}

/// Unix time helper kept for symmetry with GoTrue's `expires_at` semantics.
#[allow(dead_code)]
fn unix(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}
