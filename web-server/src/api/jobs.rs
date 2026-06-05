use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use crate::state::AppState;

pub async fn get_job_status(
    State(state): State<AppState>,
    Path(id):     Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = state.jobs.get_status(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::to_value(status).unwrap()))
}

pub async fn delete_job(
    State(state): State<AppState>,
    Path(id):     Path<String>,
) -> StatusCode {
    state.jobs.remove(&id);
    StatusCode::NO_CONTENT
}
