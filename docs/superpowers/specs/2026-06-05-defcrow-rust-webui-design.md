# DefCrow — Rust Loader + Web Generator UI

**Date:** 2026-06-05  
**Status:** Approved

---

## Overview

Redesign ScareCrow loader dari Go ke Rust, dilengkapi web application (Axum backend + React+Vite frontend) untuk generate loader via browser. Menambahkan fitur AppDomain injection (cross-process, generate DLL + `.config`). Semua OPSEC features dikontrol via Cargo feature flags.

---

## Architecture

### Stack

| Layer | Technology |
|---|---|
| Loader (payload) | Rust, cross-compile ke `x86_64-pc-windows-gnu` |
| Backend | Rust + Axum |
| Frontend | React + Vite (static files served dari Axum) |
| Code generation | Cargo feature flags (`--features amsi,etw,...`) |
| Template engine | Tera (untuk `.config` XML dan PE metadata) |
| Auth | API key via header `X-API-Key` |

### Monorepo Layout

```
defcrow/
├── Cargo.toml                      ← workspace root
├── loader-core/                    ← payload Rust crate
│   ├── Cargo.toml                  ← semua feature flags
│   └── src/
│       ├── main.rs                 ← binary (.exe) entry
│       ├── lib.rs                  ← DLL entry (DllMain)
│       ├── evasion/
│       │   ├── syscalls.rs         ← direct-syscall feature
│       │   ├── unhook.rs           ← unhook-disk / unhook-knowndlls
│       │   ├── module_stomp.rs     ← module-stomp
│       │   ├── sleep_encrypt.rs    ← sleep-encrypt (Ekko-style)
│       │   └── stack_spoof.rs      ← stack-spoof
│       ├── bypass/
│       │   ├── amsi.rs             ← amsi-patch / amsi-hwbp
│       │   └── etw.rs              ← etw-patch / etw-hwbp
│       ├── sandbox/
│       │   ├── domain.rs           ← sandbox-domain
│       │   └── usercheck.rs        ← sandbox-user
│       ├── inject/
│       │   ├── process_inject.rs   ← VirtualAllocEx + WriteProcessMemory
│       │   ├── ppid_spoof.rs       ← ppid-spoof
│       │   └── appdomain.rs        ← appdomain feature
│       └── crypto/
│           ├── aes.rs              ← AES-256-CBC
│           └── chacha20.rs         ← ChaCha20-Poly1305
├── web-server/                     ← Axum backend
│   ├── Cargo.toml
│   ├── build.rs                    ← jalankan `npm run build` saat compile
│   └── src/
│       ├── main.rs
│       ├── api/
│       │   ├── generate.rs         ← POST /api/generate
│       │   ├── jobs.rs             ← GET /api/jobs/:id
│       │   └── download.rs         ← GET /api/download/:id + DELETE
│       ├── builder/
│       │   ├── cargo_builder.rs    ← invoke cargo build async
│       │   ├── config_gen.rs       ← render appdomain .config via Tera
│       │   └── pe_sign.rs          ← PE metadata + cert cloning
│       └── middleware/
│           └── auth.rs             ← X-API-Key validation
├── frontend/                       ← React + Vite
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── pages/
│       │   ├── GeneratorPage.tsx
│       │   └── JobStatusPage.tsx
│       └── components/
│           ├── LoaderConfig.tsx     ← tipe loader, enkripsi, delivery
│           ├── OpsecFeatures.tsx    ← toggle 15 fitur OPSEC
│           └── AppDomainConfig.tsx  ← CLR version, target process, entry point
└── templates/
    └── appdomain.config.tera       ← AppDomain XML config template
```

---

## Cargo Feature Flags (loader-core)

| Feature | Teknik |
|---|---|
| `direct-syscall` | SysWhispers3-style SSN syscall langsung |
| `unhook-disk` | Baca clean ntdll dari disk |
| `unhook-knowndlls` | Baca clean ntdll dari KnownDLLs namespace |
| `module-stomp` | Map ke memori modul legit (non-MEM_PRIVATE) |
| `sleep-encrypt` | Enkripsi shellcode region saat sleep (Ekko) |
| `stack-spoof` | Return address / call stack spoofing |
| `heap-encrypt` | Enkripsi heap saat idle |
| `sandbox-domain` | Hanya eksekusi jika domain-joined |
| `sandbox-user` | Cek mouse movement, proses, RAM, uptime |
| `ppid-spoof` | Parent process ID spoofing |
| `amsi-patch` | Patch AmsiScanBuffer di memori |
| `amsi-hwbp` | Hardware breakpoint bypass AMSI (stealth) |
| `etw-patch` | Patch EtwEventWrite |
| `etw-hwbp` | Hardware breakpoint bypass ETW |
| `pe-spoof` | Fake PE metadata + cert cloning |
| `string-obfu` | Compile-time string encryption via proc-macro |
| `staged` | Download payload dari URL saat runtime |
| `appdomain` | CLR hosting + AppDomain cross-process injection |

---

## Loader Types

| Type | Output | Catatan |
|---|---|---|
| `binary` | `.exe` | Standalone, shellcode dalam proses sendiri |
| `dll` | `.dll` | Export: DllRegisterServer, DllGetClassObject |
| `appdomain` | `.dll` + `.config` | CLR hosting, inject ke proses eksternal |
| `injector` | `.exe` | Remote process injection (VirtualAllocEx) |

---

## AppDomain Injection — Detail

### Output Files
- `loader.dll` — DLL yang mengandung CLR hosting code
- `loader.config` — AppDomain configuration XML

### Alur Eksekusi (di target machine)
1. `OpenProcess(PROCESS_ALL_ACCESS, target_pid)`
2. `VirtualAllocEx` → alokasi memori di proses target
3. `WriteProcessMemory` → tulis CLR hosting stub
4. `CreateRemoteThread` → eksekusi stub di proses target
5. Stub: `CLRCreateInstance` → `ICLRMetaHost::GetRuntime(clr_version)` → `ICLRRuntimeHost::Start()`
6. `ExecuteInDefaultAppDomain(assembly_bytes, type_name, method_name, argument)`

### Template `appdomain.config.tera`
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="{{ clr_version }}" sku=".NETFramework,Version={{ net_version }}" />
  </startup>
  <runtime>
    <AppDomainManagerType value="{{ appdomain_name }}" />
  </runtime>
</configuration>
```

### Web UI Input (AppDomainConfig.tsx)
- Target process name atau PID
- CLR version: `v2.0.50727` / `v4.0.30319`
- .NET assembly: upload file atau staged URL
- Entry point: `Namespace.Class::Method`
- AppDomain name

---

## API Endpoints

```
POST   /api/generate          Kirim config JSON, terima job_id
GET    /api/jobs/:id           Poll status: queued | building | done | error
GET    /api/download/:id       Download artifact (binary stream)
DELETE /api/jobs/:id           Hapus artifact dari server
GET    /api/health             Liveness check (no auth)
```

**Header wajib** (semua endpoint kecuali `/health`):
```
X-API-Key: <token>
```

### Request Body `/api/generate`
```json
{
  "loader_type": "appdomain",
  "features": ["direct-syscall", "sleep-encrypt", "amsi-hwbp", "etw-hwbp"],
  "encryption": "aes256",
  "shellcode": "<base64>",
  "pe_config": {
    "company": "Microsoft Corporation",
    "clone_cert": "<base64 cert>",
    "sign": true
  },
  "appdomain_config": {
    "clr_version": "v4.0.30319",
    "target_process": "explorer.exe",
    "assembly": "<base64 .NET assembly>",
    "entry_point": "Namespace.Class::Run",
    "appdomain_name": "DefaultDomain"
  }
}
```

---

## Build Flow (cargo_builder.rs)

```
1. Buat temp dir: /tmp/defcrow-jobs/{job_id}/
2. Tulis shellcode.bin ke temp dir
3. Render .config via Tera (jika appdomain)
4. Set env: SHELLCODE_PATH, SHELLCODE_KEY, STAGING_URL, dll
5. Jalankan:
   cargo build
     --target x86_64-pc-windows-gnu
     --manifest-path loader-core/Cargo.toml
     --features "{features}"
     --release
     -Z build-std=std,panic_abort
6. Copy artifact ke /tmp/defcrow-jobs/{job_id}/output/
7. Jalankan pe_sign.rs (inject PE metadata + cert)
8. Update job status → done
```

---

## Frontend Pages

### GeneratorPage
- Upload shellcode (drag & drop)
- Pilih loader type (Binary / DLL / AppDomain / Injector)
- Toggle OPSEC features (15 toggle switch dengan deskripsi)
- AppDomainConfig section (muncul jika tipe AppDomain dipilih)
- PE spoofing config (company name, clone cert upload)
- Tombol Generate → poll status → tampilkan download link

### JobStatusPage
- Real-time polling setiap 2 detik
- Progress indicator: queued → building → done/error
- Build log streaming (opsional)
- Download button + Delete job button

---

## Authentication

- API key disimpan di `.env`: `DEFCROW_API_KEY=<random-256bit-hex>`
- Axum middleware membaca header `X-API-Key` per request
- Mismatch → 401 Unauthorized
- Frontend menyimpan key di `localStorage` (bukan cookie)
- Tidak ada multi-user / session management

---

## Out of Scope

- Fitur yang tidak dimasukkan dalam versi ini:
  - Garble/obfuscasi seluruh binary (terlalu lambat untuk web UX)
  - WScript / HTA / Excel loader (tidak diminta)
  - User management / multi-tenant
  - Build queue persistence (restart server = reset queue)
