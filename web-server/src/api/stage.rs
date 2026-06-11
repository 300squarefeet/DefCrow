use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use crate::state::AppState;

type HmacSha256 = Hmac<sha2::Sha256>;

// ── JWT ──────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct StageClaims {
    pub pid:   String,
    pub sz:    usize,
    pub iat:   i64,
    pub exp:   i64,
    pub nonce: String,
}

pub fn sign_jwt(key: &[u8; 32], claims: &StageClaims) -> String {
    let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims).unwrap());
    let data    = format!("{}.{}", header, payload);
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

pub fn verify_jwt(key: &[u8; 32], token: &str) -> Option<StageClaims> {
    let mut parts = token.splitn(3, '.');
    let header  = parts.next()?;
    let payload = parts.next()?;
    let sig     = parts.next()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let data = format!("{}.{}", header, payload);
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    // constant-time comparison prevents timing side-channel on HMAC verification
    mac.verify_slice(&sig_bytes).ok()?;
    let raw = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&raw).ok()
}

// ── Metadata ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct StageMeta {
    pub pid:        String,
    pub name:       String,
    pub size:       usize,
    pub arch:       String,
    pub created_at: String,
}

// ── PID validation ───────────────────────────────────────────────────────────

fn validate_pid(pid: &str) -> bool {
    pid.len() == 16 && pid.chars().all(|c| c.is_ascii_hexdigit())
}

// ── POST /api/v1/stage ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct UploadResponse {
    pub pid:  String,
    pub size: usize,
    pub name: String,
    pub jwt:  String,
    pub url:  String,
}

pub async fn upload_stage(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, String)> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name = "payload.bin".to_string();

    while let Some(field) = multipart.next_field().await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))? {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("payload.bin").to_string();
            file_bytes = Some(field.bytes().await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?.to_vec());
        }
    }

    let bytes = file_bytes.ok_or((StatusCode::BAD_REQUEST, "missing file field".into()))?;
    let size  = bytes.len();

    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    let pid: String = hash.iter().take(8).map(|b| format!("{:02x}", b)).collect();

    tokio::fs::create_dir_all(&state.staged_dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let bin_path  = state.staged_dir.join(format!("{}.bin", pid));
    let meta_path = state.staged_dir.join(format!("{}.json", pid));

    tokio::fs::write(&bin_path, &bytes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let meta = StageMeta {
        pid:        pid.clone(),
        name:       file_name.clone(),
        size,
        arch:       "x64".into(),
        created_at: now.to_string(),
    };
    tokio::fs::write(&meta_path, serde_json::to_string(&meta).unwrap())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let nonce: String = rand::thread_rng().gen::<[u8; 8]>().iter().map(|b| format!("{:02x}", b)).collect();
    let claims = StageClaims { pid: pid.clone(), sz: size, iat: now, exp: now + 3600, nonce };
    let jwt = sign_jwt(&state.staged_key, &claims);
    let url = format!("/api/v1/stage/{}", pid);

    Ok(Json(UploadResponse { pid, size, name: file_name, jwt, url }))
}

// ── GET /api/v1/stage/:pid ────────────────────────────────────────────────────

pub async fn fetch_stage(
    State(state): State<AppState>,
    Path(pid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None    => return (StatusCode::UNAUTHORIZED, "missing Bearer token").into_response(),
    };

    let claims = match verify_jwt(&state.staged_key, &token) {
        Some(c) => c,
        None    => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    if claims.exp < now {
        return (StatusCode::UNAUTHORIZED, "token expired").into_response();
    }

    if !validate_pid(&pid) {
        return (StatusCode::BAD_REQUEST, "invalid pid").into_response();
    }

    if claims.pid != pid {
        return (StatusCode::FORBIDDEN, "pid mismatch").into_response();
    }

    let bin_path = state.staged_dir.join(format!("{}.bin", pid));
    match tokio::fs::read(&bin_path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        ).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "stage not found").into_response(),
    }
}

// ── DELETE /api/v1/stage/:pid ─────────────────────────────────────────────────

pub async fn delete_stage(
    State(state): State<AppState>,
    Path(pid): Path<String>,
) -> StatusCode {
    if !validate_pid(&pid) {
        return StatusCode::BAD_REQUEST;
    }
    let bin_path  = state.staged_dir.join(format!("{}.bin", pid));
    let meta_path = state.staged_dir.join(format!("{}.json", pid));
    let _ = tokio::fs::remove_file(&bin_path).await;
    let _ = tokio::fs::remove_file(&meta_path).await;
    StatusCode::NO_CONTENT
}

// ── GET /api/v1/stage ─────────────────────────────────────────────────────────

pub async fn list_stages(State(state): State<AppState>) -> Json<Vec<StageMeta>> {
    let mut result = Vec::new();
    if let Ok(mut dir) = tokio::fs::read_dir(&state.staged_dir).await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(raw) = tokio::fs::read_to_string(&path).await {
                    if let Ok(meta) = serde_json::from_str::<StageMeta>(&raw) {
                        result.push(meta);
                    }
                }
            }
        }
    }
    Json(result)
}

// ── POST /api/v1/stage/:pid/token ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct TokenResponse { pub jwt: String }

pub async fn rotate_token(
    State(state): State<AppState>,
    Path(pid): Path<String>,
) -> Result<Json<TokenResponse>, StatusCode> {
    if !validate_pid(&pid) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let meta_path = state.staged_dir.join(format!("{}.json", pid));
    let raw = tokio::fs::read_to_string(&meta_path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let meta: StageMeta = serde_json::from_str(&raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now   = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let nonce: String = rand::thread_rng().gen::<[u8; 8]>().iter().map(|b| format!("{:02x}", b)).collect();
    let claims = StageClaims { pid: pid.clone(), sz: meta.size, iat: now, exp: now + 3600, nonce };
    let jwt = sign_jwt(&state.staged_key, &claims);
    Ok(Json(TokenResponse { jwt }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] { [0x42u8; 32] }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = test_key();
        let claims = StageClaims { pid: "abc123".into(), sz: 512, iat: 1700000000, exp: 1700003600, nonce: "deadbeef01234567".into() };
        let token = sign_jwt(&key, &claims);
        assert_eq!(token.splitn(3, '.').count(), 3);
        let decoded = verify_jwt(&key, &token).expect("should verify");
        assert_eq!(decoded.pid, "abc123");
        assert_eq!(decoded.sz, 512);
    }

    #[test]
    fn tampered_token_fails_verify() {
        let key = test_key();
        let claims = StageClaims { pid: "x".into(), sz: 1, iat: 0, exp: 9999999999, nonce: "n".into() };
        let mut token = sign_jwt(&key, &claims);
        token.push('x');
        assert!(verify_jwt(&key, &token).is_none());
    }

    #[test]
    fn wrong_key_fails_verify() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let claims = StageClaims { pid: "y".into(), sz: 2, iat: 0, exp: 9999999999, nonce: "n".into() };
        let token = sign_jwt(&key1, &claims);
        assert!(verify_jwt(&key2, &token).is_none());
    }
}
