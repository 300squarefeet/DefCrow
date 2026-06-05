use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
};
use crate::state::AppState;

pub async fn download_artifact(
    State(state): State<AppState>,
    Path(id):     Path<String>,
) -> Result<Response, StatusCode> {
    // Resolve download_id → file path
    let dl_meta = std::path::PathBuf::from(&state.config.artifacts_dir)
        .join(&id)
        .with_extension("path");

    let path_str = std::fs::read_to_string(&dl_meta)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let path = path_str.trim();

    if !std::path::Path::new(path).exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    let bytes = std::fs::read(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let filename = std::path::Path::new(path)
        .file_name().unwrap_or_default()
        .to_string_lossy().to_string();

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(Body::from(bytes))
        .unwrap())
}
