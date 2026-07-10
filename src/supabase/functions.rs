//! `/functions/v1` — Supabase Edge Functions compatibility.
//!
//! Placeholder: every route returns a typed `501` (never a bare `404`, never
//! fake success). Replaced by a real implementation (SQL-backed function
//! invocation + an optional upstream-proxy mode) in a later slice.

use crate::sql::RelationalStorage;
use crate::supabase::error::SupaError;
use crate::supabase::gateway::AppState;
use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::any;

pub fn router<S: RelationalStorage + 'static>() -> Router<AppState<S>> {
    Router::new().route("/{*rest}", any(not_impl))
}

async fn not_impl() -> Response {
    SupaError::NotImplemented("FUNCTIONS").into_response()
}
