# DefCrow UI Redesign + Staged Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign DefCrow frontend to match the clean SaaS dashboard design and add full staged payload delivery with JWT-authenticated backend API.

**Architecture:** Step-rail navigation replaces the single-page form. Left column is the wizard (Payload → Stage Transfer → Evasion → Output → Forge), right column is the persistent Build Console. New Rust endpoints handle staged payload storage and JWT signing.

**Tech Stack:** React 18 + TypeScript + Tailwind CSS (frontend); Axum + Rust (backend); existing WebSocket for build log streaming.

---

## Design Reference

Source: Claude Design bundle `loader-generator/project/`. Key files:
- `app.jsx` — full component tree
- `data.jsx` — PROFILES, TECH_GROUPS, OUTPUT_FORMATS constants
- `styles.css` — CSS variables, component styles
- `login.html` — login page design
- `settings.html` — integrations/settings page

---

## Architecture

### Frontend component tree

```
App
  AuthProvider
    Routes
      /login       → LoginPage (redesigned)
      /            → ProtectedRoute → GeneratorPage (full redesign)
        Header (step rail)
        workspace (two-col layout)
          main-col
            PayloadSection
            StageTransferSection (staged mode only)
            EvasionSection
            OutputSection
          right-col (sticky)
            BuildConsole
              DeliveryCard (shown after build)
      /job/:id     → JobStatusPage (minor style update)
      /settings    → SettingsPage (new)
```

### New API endpoints (backend)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/stage` | session cookie | Upload shellcode; returns `{ pid, url, jwt }` |
| `GET`  | `/api/v1/stage/:pid` | Bearer JWT | Fetch raw shellcode bytes |
| `DELETE` | `/api/v1/stage/:pid` | session cookie | Remove staged payload |
| `GET`  | `/api/v1/stage` | session cookie | List all staged payloads |

Existing endpoints unchanged:
- `POST /api/v1/generate`
- `GET /ws/job/:id`
- `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`

### Staged payload storage

- Directory: `$DEFCROW_ARTIFACTS_DIR/staged/{pid}.bin`
- Metadata: `$DEFCROW_ARTIFACTS_DIR/staged/{pid}.json` (name, size, arch, created_at)
- `pid` = first 16 hex chars of SHA-256(raw_bytes)
- Stage signing key: random 32-byte key generated at server startup, stored in `AppState`
- JWT claims: `{ pid, sz, iat, exp: iat+3600, nonce: random16 }`, signed with HMAC-SHA256

---

## UI Design System

### Colors (CSS variables matching design)

**Clean (light) theme — default:**
- `--bg: #f5f7fb` — page background
- `--surface: #ffffff` — cards
- `--blue-500: #2f6bff` — primary accent
- `--ink: #0b1424` — primary text
- `--ok / --warn / --danger` — semantic states

**Hacker (dark) theme:**
- `--bg: #0a0a0f` — current DefCrow dark
- `--blue-500: #7c3aed` — purple accent (keep current)
- Theme toggled via `data-theme` attribute on `<html>`

### Typography
- UI: Inter (add to index.html if not present, or use system font stack)
- Code/mono: JetBrains Mono (add via Google Fonts)

### Layout
- Header: 60px sticky, grid `260px 1fr auto`
- Workspace: two columns — `main-col` (scrollable, 1fr) + `right-col` (sticky, ~380px)
- Section spacing: 32px between sections

---

## Component Specs

### Header
- Left: DefCrow crow SVG logo + brand name
- Center: step rail (01 Payload → 02 Stage Transfer → 03 Evasion → 04 Output → 05 Forge)
  - Step 02 only shown in staged mode
  - Clicking step scrolls main-col to section
- Right: "Export config" button + gear icon → settings dropdown
  - Dropdown: user handle, theme switcher (Clean/Hacker cards), Integrations link, Sign out

### PayloadSection (Step 01)
- Mode selector: two cards — A: Stageless (shellcode embedded), B: Staged (fetched at runtime)
- Stageless mode: single file drop zone + .bin upload + "Use demo beacon" button
- Staged mode: multi-payload list, each with pid, size, active indicator; "Stage another" row
- File info card: filename, type, arch, size, SHA-256 prefix

### StageTransferSection (Step 02, staged only)
- Endpoint bar: `GET https://{stageHost}/api/v1/stage/{pid}` + status badge
- Explanation text about JWT bearer token rotation
- Expandable table rows per payload: full JWT display (header.payload.sig segments color-coded), copy/rotate/download buttons

### EvasionSection (Step 03)
- Profile grid: 3 cards (Stealth 92/100, Balanced 76/100, Aggressive 54/100)
  - Each shows score bar, technique count, build time estimate
  - Selecting profile sets enabled techniques
- Technique groups (from TECH_GROUPS in data.jsx):
  - Syscalls & API resolution
  - Shellcode encryption
  - Execution & injection
  - Memory & sleep
  - Anti-analysis
- Each technique: checkbox, name, risk pill (low/med/high), description
- Enabled count per group: "N/M enabled"

Map existing DefCrow features to techniques:
- `DirectSyscall` → `indirect_syscalls`
- `UnhookDisk` → `ntdll_unhook` (disk variant)
- `UnhookKnownDlls` → `ntdll_unhook` (KnownDlls variant)
- `ModuleStomp` → `module_stomping`
- `SleepEncrypt` → `ekko_sleep`
- `StackSpoof` → `stack_spoof`
- `AmsiHwbp` → `amsi_hwbp`
- `EtwHwbp` → `etw_patch`
- `PpidSpoof` → `ppid_spoof`
- `Aes256` encryption → `aes_gcm_payload`
- `Chacha20` encryption → `chacha20_payload`

### OutputSection (Step 04)
- Grid of format cards (8 cards + 1 "roadmap" card):
  - Native EXE, Native DLL, AppDomainManager, WSF script, VBA macro, MSBuild, InstallUtil, Raw shellcode
  - Each card: format icon, name, extension, notes, opsec badge (high/med/low/n/a)
- LOLBin roadmap chips below grid

### BuildConsole (Right column)
- Fixed right column, not scrolled with page
- Header: "Build console", status badge (Idle/Building/Complete), Clear button
- Terminal area: streaming log lines with timestamp + tag [scope] + message
  - Tags colored: info (blue), ok (green), warn (amber), step (blue bold)
- Summary bar: mode · tech count · format · profile
- Forge button (primary): triggers `POST /api/v1/generate` with current config
  - Streams build log via existing WebSocket
- After build: artifact card (filename, size) + Download button
- After build: DeliveryCard (extension cloak + shareable URL)

### DeliveryCard
- Extension picker: .pdf, .jpg, .jpeg, .png, .gif, .svg, .iso, .zip
- Shareable URL: `https://{smugglerHost}/d/{linkId}/{fakeName}`
- Access key: random 6-char alphanumeric (deliver out-of-band)
- Actions: Open smuggler page, Send to Discord (if configured)
- Smuggler page: `/smuggler` route — shows file download prompt with cloak extension

### LoginPage redesign
- Clean centered card, matching light/dark theme
- Logo + "DefCrow" heading
- Username + password fields
- Sign in button
- Disclaimer footer

### SettingsPage (new, `/settings`)
- Integrations: Stage host URL, Smuggler host URL
- Discord webhook: enable toggle + webhook URL + channel
- Theme preference (also accessible from header)
- Save/reset buttons

---

## Data Model Changes

### Frontend state (GeneratorPage)
```typescript
interface Stage {
  pid: string;
  name: string;
  size: number;
  hash: string;
  arch: string;
  type: string;
  token?: JwtParts;
}

type Mode = 'stageless' | 'staged';
type Profile = 'stealth' | 'balanced' | 'aggressive';
type TechId = string; // e.g. 'indirect_syscalls', 'ekko_sleep', ...
```

### Backend: AppState additions
```rust
pub staged_key: [u8; 32],          // random at startup, for JWT signing
pub staged_dir: PathBuf,           // $ARTIFACTS_DIR/staged/
```

### Backend: Staged payload routes
```rust
// POST /api/v1/stage — multipart or raw body
// Returns: { pid: String, size: usize, name: String }

// GET /api/v1/stage/:pid — requires Authorization: Bearer <jwt>
// Returns: raw bytes (application/octet-stream)

// DELETE /api/v1/stage/:pid — session auth
// Returns: 204

// GET /api/v1/stage — session auth  
// Returns: [ { pid, name, size, arch, created_at } ]
```

---

## Out of Scope

- Real HTML smuggling server (`/smuggler` page is UI-only placeholder)
- Real Discord webhook delivery (button shows status, does not actually send)
- VERSIONINFO/PE metadata cloning (backend already has this as optional)
- LOLBin roadmap items (UI chips only)
- C++ source preview (not in this design)

---

## File Changes Summary

**New / heavily rewritten:**
- `frontend/src/pages/GeneratorPage.tsx` — complete rewrite
- `frontend/src/pages/LoginPage.tsx` — redesign
- `frontend/src/pages/SettingsPage.tsx` — new
- `frontend/src/components/Header.tsx` — new (extracted from GeneratorPage)
- `frontend/src/components/PayloadSection.tsx` — new
- `frontend/src/components/StageTransferSection.tsx` — new
- `frontend/src/components/EvasionSection.tsx` — new (replaces OpsecFeatures)
- `frontend/src/components/OutputSection.tsx` — new (replaces inline format grid)
- `frontend/src/components/BuildConsole.tsx` — new (replaces inline submit button)
- `frontend/src/components/DeliveryCard.tsx` — new
- `frontend/src/index.css` — design system tokens added
- `frontend/src/api/generate.ts` — add staged mode fields, profile type
- `frontend/src/api/stage.ts` — new API client for stage endpoints

**Backend additions:**
- `web-server/src/routes/stage.rs` — new: stage CRUD + JWT generation/verification
- `web-server/src/main.rs` — add stage routes, staged_key to AppState

**Unchanged:**
- `loader-scaffold/` — all Rust loader code untouched
- `template-engine/` — all templates untouched
- `web-server/src/routes/generate.rs` — unchanged
- `web-server/src/routes/auth.rs` — unchanged
- `web-server/src/builder/` — unchanged
