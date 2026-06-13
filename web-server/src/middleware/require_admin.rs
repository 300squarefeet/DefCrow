//! Admin-role guard. Expected to be layered _on top of_
//! [`crate::middleware::auth::require_auth`] so the JWT has already
//! been verified and [`SessionClaims`] are present in request
//! extensions. Returns 403 when the claims do not name the `admin`
//! role.
//!
//! Wiring pattern:
//! ```ignore
//! Router::new()
//!     .route("/api/admin/...", get(handler))
//!     .route_layer(axum::middleware::from_fn(require_admin))
//!     .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_auth));
//! ```
//! `route_layer` applies layers in reverse-add order, so `require_auth`
//! still runs first per request.

use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::middleware::auth::SessionClaims;

pub async fn require_admin(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let role_ok = req.extensions()
        .get::<SessionClaims>()
        .map(|c| c.role == "admin")
        .unwrap_or(false);
    if !role_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}
