# DefCrow — Rust Loader + Web Generator UI

**Date:** 2026-06-05  
**Status:** Approved (Revised)

---

## Overview

Redesign ScareCrow loader dari Go ke Rust. Konsep identik ScareCrow: **Tera template engine → generate Rust source code dengan variabel ter-randomize → compile → output binary**. Bukan port langsung — semua teknik eksekusi dan bypass diganti ke standar OPSEC 2024/2025. Dilengkapi web application (Axum backend + React+Vite frontend) untuk generate loader via browser dengan progress real-time via WebSocket.

---

## Pola Inti (Sama dengan ScareCrow)

ScareCrow bekerja dengan cara:
1. Template engine mengisi `map[string]string` variabel dengan nama acak (`VarNumberLength`)
2. Hasilnya adalah source code Go yang ter-randomize tiap build
3. `go build` mengkompilasi source tersebut
4. Scaffold (zip berisi go.mod, asm, icons) sudah pre-packed, hanya file generated yang dikompilasi baru

DefCrow mengadopsi pola yang sama dalam Rust:
1. Tera template mengisi variabel dengan identifier acak (Rust equivalent)
2. Hasilnya adalah `loader-config.rs` — source Rust tipis (~50-100 baris) yang ter-randomize tiap build
3. `rustc loader-config.rs --extern scaffold=libscaffold.rlib` — hanya compile file ini
4. `libscaffold.rlib` sudah pre-compiled saat server startup (mirip zip scaffold ScareCrow)

---

## Stack

| Layer | Technology |
|---|---|
| Loader payload | Rust, cross-compile ke `x86_64-pc-windows-gnu` |
| Template engine | Tera (`.rs.tera` templates) |
| Scaffold library | `libscaffold.rlib` — pre-compiled sekali saat startup |
| Backend | Rust + Axum + Tokio |
| Build comms | WebSocket (progress streaming) + REST (job management) |
| Frontend | React + Vite (static files served dari Axum) |
| Auth | Username + password login, session token |
| Build cache | sccache (cache rustc artifacts antar request) |

---

## Arsitektur Build — Pre-compiled Scaffold

```
Server Startup (sekali, ~90 detik):
  cargo build --release → libscaffold.rlib
  (semua modul OPSEC sudah di-compile dalam lib ini)

Per Request (~5-12 detik):
  1. Tera template → loader-config.rs (50-100 baris, variabel ter-randomize)
  2. rustc loader-config.rs
       --extern scaffold=libscaffold.rlib
       --target x86_64-pc-windows-gnu
       --crate-type cdylib / bin
  3. PE metadata inject + code signing
  4. Artifact siap diunduh

Warm Cache (sccache hit, ~1-2 detik):
  Kombinasi feature + randomized config yang identik → dari cache
```

---

## Monorepo Layout

```
defcrow/
├── Cargo.toml                         ← workspace root
│
├── loader-scaffold/                   ← pre-compiled library (libscaffold.rlib)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── evasion/
│       │   ├── syscalls.rs            ← indirect syscalls (SSN + trampoline)
│       │   ├── unhook.rs              ← NTDLL unhook: Disk / KnownDLLs
│       │   ├── module_stomp.rs        ← module stomping (non-MEM_PRIVATE)
│       │   ├── sleep_mask.rs          ← full PE masking saat sleep (Ekko/Gargoyle)
│       │   └── stack_spoof.rs         ← synthetic stack frames (return addr spoof)
│       ├── bypass/
│       │   ├── amsi_hwbp.rs           ← AMSI via hardware breakpoint (DR0-DR3)
│       │   └── etw_hwbp.rs            ← ETW via hardware breakpoint
│       ├── sandbox/
│       │   ├── domain.rs              ← domain-joined check (NetGetJoinInformation)
│       │   └── usercheck.rs           ← mouse movement, proses, RAM, uptime
│       ├── inject/
│       │   ├── exec.rs                ← fiber execution + NtProtect RW→RX (no RWX)
│       │   ├── threadless.rs          ← threadless injection via TpAllocWork callback
│       │   ├── ppid_spoof.rs          ← parent process ID spoofing
│       │   └── appdomain.rs           ← CLR hosting via ICLRRuntimeHost2
│       ├── resolve/
│       │   └── api_hash.rs            ← WinAPI resolution by djb2/FNV hash (no IAT)
│       └── crypto/
│           ├── aes256.rs
│           └── chacha20.rs
│
├── loader-gen/                        ← generated per-request (thin, ~50-100 baris)
│   └── templates/
│       ├── binary.rs.tera
│       ├── dll.rs.tera
│       ├── appdomain.rs.tera
│       └── injector.rs.tera
│
├── web-server/                        ← Axum backend
│   ├── Cargo.toml
│   ├── build.rs                       ← npm run build saat compile
│   └── src/
│       ├── main.rs
│       ├── api/
│       │   ├── auth.rs                ← POST /api/auth/login, /logout
│       │   ├── generate.rs            ← POST /api/generate
│       │   ├── jobs.rs                ← GET /api/jobs/:id
│       │   └── download.rs            ← GET /api/download/:id, DELETE
│       ├── builder/
│       │   ├── scaffold.rs            ← pre-compile libscaffold.rlib saat startup
│       │   ├── template_gen.rs        ← Tera template → loader-config.rs
│       │   ├── rustc_runner.rs        ← invoke rustc dengan --extern scaffold
│       │   ├── config_gen.rs          ← render appdomain .config XML
│       │   └── pe_sign.rs             ← PE metadata + cert cloning
│       ├── ws/
│       │   └── progress.rs            ← WebSocket progress streaming
│       └── middleware/
│           └── auth.rs                ← session token validation
│
├── frontend/                          ← React + Vite
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── pages/
│       │   ├── GeneratorPage.tsx
│       │   └── JobStatusPage.tsx
│       └── components/
│           ├── LoaderConfig.tsx        ← tipe loader, enkripsi, delivery
│           ├── OpsecFeatures.tsx       ← 15 toggle OPSEC dengan deskripsi
│           └── AppDomainConfig.tsx     ← CLR version, target process, entry point
│       └── pages/
│           └── LoginPage.tsx           ← form login username + password
│
└── templates/
    └── appdomain.config.tera          ← AppDomain XML config template
```

---

## OPSEC Techniques — Modern Standard 2024/2025

### Eksekusi Shellcode (No RWX)
```
LAMA (ScareCrow): VirtualAlloc(RWX) → copy → execute  ← flagged by semua EDR
BARU (DefCrow):
  1. NtAllocateVirtualMemory(RW)     ← alokasi tanpa execute permission
  2. memcpy shellcode ke region
  3. NtProtectVirtualMemory(RW→RX)   ← via indirect syscall
  4. Fiber execution (CreateFiber/SwitchToFiber)  ← bukan thread baru
```

### Syscall Method
```
LAMA: Direct syscall (SSN hardcoded + inline asm jump)  ← EDR monitor SSN
BARU: Indirect syscall
  1. Resolve SSN dari ntdll di runtime (bukan hardcode)
  2. Set RIP ke ntdll stub (bukan shellcode) sebelum syscall
  3. Call stack terlihat datang dari ntdll yang legit
```

### API Resolution
```
LAMA: Import table (IAT) — semua API visible di PE header
BARU: API Hashing
  - Semua WinAPI di-resolve via djb2/FNV hash di runtime
  - IAT kosong / stomped setelah load
  - Tidak ada string API name di binary
```

### Threadless Injection
```
LAMA: CreateRemoteThread → flagged oleh semua EDR
BARU: TpAllocWork callback trampoline
  1. Alokasi memori di proses target
  2. Tulis shellcode + trampoline
  3. TpAllocWork(callback=trampoline) → eksekusi via thread pool
  4. Tidak ada thread baru yang dibuat
```

### AMSI / ETW Bypass
```
LAMA: WriteProcessMemory patch (memory IOC — mudah di-scan)
BARU: Hardware Breakpoint (DR0-DR3)
  - Set DR0 = address AmsiScanBuffer / EtwEventWrite
  - VEH handler: intercept exception, ubah return value, resume
  - ZERO modifikasi memori — tidak ada IOC
```

### Sleep Masking
```
LAMA: Tidak ada / hanya enkripsi shellcode region
BARU: Full PE masking (Ekko/Gargoyle pattern)
  - Saat sleep: enkripsi SELURUH image base (bukan hanya shellcode)
  - ROP chain via NtContinue untuk mask/unmask tanpa thread suspicious
  - PE header di-stomp setelah load
```

### AppDomain (ICLRRuntimeHost2)
```
LAMA (konsep): ICLRRuntimeHost (deprecated)
BARU: ICLRRuntimeHost2
  1. CLRCreateInstance(CLSID_CLRMetaHost)
  2. ICLRMetaHost::GetRuntime(clr_version)
  3. ICLRRuntimeInfo::GetInterface(ICLRRuntimeHost2)
  4. ICLRRuntimeHost2::SetAppDomainManager(type_name)
  5. Start() + ExecuteInDefaultAppDomain(assembly, method, arg)

.config hijacking:
  <appDomainManagerType value="Namespace.EvilManager" />
  <appDomainManagerAssembly value="EvilAssembly, Version=..." />
  → .NET runtime otomatis load custom AppDomainManager di startup
```

---

## Variabel Randomization (Mirip ScareCrow)

Tera template menggunakan fungsi custom untuk randomize identifier:

```rust
// Template helper functions (dipanggil dari .rs.tera)
fn rand_ident(len: usize) -> String  // random alphanumeric identifier
fn rand_string(s: &str) -> String    // encode string literal (hex/xor/split)
fn rand_int(min: u32, max: u32) -> u32

// Contoh template binary.rs.tera:
let {{ rand_ident(12) }}: *mut c_void = std::ptr::null_mut();
let {{ rand_ident(8) }}: usize = shellcode.len();
// → setiap build generate variabel berbeda
```

---

## Frontend ↔ Backend Communication

```
1. POST /api/auth/login  (REST, no auth required)
   Body: { username, password }
   Response: { token: "<256-bit hex session token>", expires_in: 86400 }

2. POST /api/generate  (REST, Authorization: Bearer <token>)
   Body: { loader_type, features[], encryption, shellcode_b64, pe_config, appdomain_config }
   Response: { job_id: "abc123" }   ← INSTAN

2. WebSocket: ws://host/ws/jobs/abc123
   Server push (tidak ada polling):
   {"status":"queued",    "progress":0,  "msg":"Job queued"}
   {"status":"building",  "progress":15, "msg":"Generating source from template..."}
   {"status":"building",  "progress":40, "msg":"Compiling against scaffold..."}
   {"status":"building",  "progress":75, "msg":"PE signing & metadata inject..."}
   {"status":"done",      "progress":100,"download_id":"xyz789"}
   {"status":"error",     "msg":"Build failed: <stderr>"}

3. GET /api/download/xyz789  (REST)
   → Binary stream, Content-Disposition: attachment

4. DELETE /api/jobs/abc123  (REST)
   → Hapus artifact dari server
```

---

## API Endpoints

```
POST   /api/auth/login         Login, terima session token (no auth)
POST   /api/auth/logout        Invalidate session token
POST   /api/generate           Kirim config, terima job_id (instan)
GET    /api/jobs/:id           Status snapshot: queued|building|done|error
WS     /ws/jobs/:id            Real-time progress stream
GET    /api/download/:id       Download artifact
DELETE /api/jobs/:id           Hapus artifact
GET    /api/health             Liveness check (no auth)

Header wajib (semua kecuali /login dan /health):
  Authorization: Bearer <session_token>
```

---

## Loader Types & Output

| Type | Output | Teknik Utama |
|---|---|---|
| `binary` | `.exe` | Fiber exec, no RWX, indirect syscall, sleep mask |
| `dll` | `.dll` | DllMain entry, API hash, module stomp, reflective |
| `appdomain` | `.dll` + `.config` | ICLRRuntimeHost2, custom AppDomainManager |
| `injector` | `.exe` | Threadless injection (TpAllocWork), PPID spoof |

---

## Build Speed Target

| Skenario | Waktu |
|---|---|
| Server startup (scaffold compile) | ~90 detik, sekali |
| Generate baru (dingin) | ~8-15 detik |
| Generate ulang (sccache hit) | ~1-3 detik |

---

## Authentication

### Konfigurasi (.env)
```
DEFCROW_USERNAME=admin
DEFCROW_PASSWORD_HASH=<argon2id hash dari password>
DEFCROW_SESSION_SECRET=<random 256-bit hex>
```

Password hash di-generate sekali saat setup:
```bash
# Helper CLI yang disertakan:
defcrow-cli hash-password
# → Masukkan password → output Argon2id hash → paste ke .env
```

### Login Flow
```
1. POST /api/auth/login { username, password }
2. Server: argon2id::verify(password, DEFCROW_PASSWORD_HASH)
3. Jika valid: generate 256-bit random session token
4. Simpan token di in-memory HashMap<token, expiry> (server-side)
5. Return: { token, expires_in: 86400 }
6. Frontend: simpan token di localStorage
7. Semua request berikutnya: Authorization: Bearer <token>
```

### Session Middleware (Axum)
- Setiap request ke endpoint protected → cek token di HashMap
- Token expired (>24 jam) → 401 Unauthorized
- Token tidak ada → 401 Unauthorized → frontend redirect ke /login
- POST /api/auth/logout → hapus token dari HashMap

### Frontend Auth
- `LoginPage.tsx`: form username + password, POST ke `/api/auth/login`
- Token disimpan di `localStorage`
- Axios interceptor: inject `Authorization: Bearer <token>` ke semua request
- Interceptor 401 response: clear token + redirect ke `/login`
- Protected route wrapper: cek token ada sebelum render GeneratorPage

### Password Hashing
- **Argon2id** (bukan bcrypt/sha256) — standar modern, memory-hard
- Parameter: `m=65536, t=3, p=4` (OWASP recommended)
- Crate: `argon2` (pure Rust)

---

## Out of Scope (v1)

- WScript / HTA / Excel / Macro loaders
- Garble-style full binary obfuscation (terlalu lambat untuk web UX)
- User management / multi-tenant auth
- Build queue persistence antar restart server
- GUI Windows native (web only)
