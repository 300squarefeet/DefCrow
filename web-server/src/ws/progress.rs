use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::Response,
};
use crate::{builder::job_store::JobStatus, state::AppState};

pub async fn ws_job_progress(
    ws:           WebSocketUpgrade,
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state, job_id))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, job_id: String) {
    let mut rx = match state.jobs.subscribe(&job_id) {
        Some(rx) => rx,
        None => {
            let _ = socket.send(Message::Text(
                r#"{"status":"error","msg":"job not found"}"#.to_string(),
            )).await;
            return;
        }
    };

    // Send current status immediately
    {
        let current = rx.borrow().clone();
        let json = serde_json::to_string(&current).unwrap_or_default();
        if socket.send(Message::Text(json)).await.is_err() { return; }
    }

    loop {
        if rx.changed().await.is_err() { break; }
        let status = rx.borrow().clone();
        let done = matches!(status, JobStatus::Done { .. } | JobStatus::Error { .. });
        let json = serde_json::to_string(&status).unwrap_or_default();
        if socket.send(Message::Text(json)).await.is_err() { break; }
        if done { break; }
    }
}
