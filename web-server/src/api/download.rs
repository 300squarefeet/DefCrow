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
    let artifacts_dir = std::path::PathBuf::from(&state.config.artifacts_dir);
    let dl_meta  = artifacts_dir.join(&id).with_extension("path");
    let consumed = artifacts_dir.join(&id).with_extension("path.consumed");

    // Atomically claim this download — rename is atomic on the same filesystem.
    // If .path is already gone (consumed or never existed) → 404.
    match std::fs::rename(&dl_meta, &consumed) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(_)  => {}
    }

    let path_str = match std::fs::read_to_string(&consumed) {
        Ok(s)  => s,
        Err(_) => { let _ = std::fs::remove_file(&consumed); return Err(StatusCode::INTERNAL_SERVER_ERROR); }
    };
    let path = path_str.trim().to_owned();

    let bytes = match std::fs::read(&path) {
        Ok(b)  => b,
        Err(_) => { let _ = std::fs::remove_file(&consumed); return Err(StatusCode::NOT_FOUND); }
    };

    let filename = std::path::Path::new(&path)
        .file_name().unwrap_or_default()
        .to_string_lossy().to_string();

    // Burn artifact and consumed marker — one-time delivery.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&consumed);

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header("Pragma", "no-cache")
        .body(Body::from(bytes))
        .unwrap())
}
