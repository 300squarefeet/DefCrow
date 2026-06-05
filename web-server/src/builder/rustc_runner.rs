use anyhow::Result;
use std::process::Command;
use tokio::sync::watch;
use crate::builder::job_store::JobStatus;

pub fn compile_loader(
    source_path:   &str,
    scaffold_rlib: &str,
    output_path:   &str,
    crate_type:    &str,
    tx:            &watch::Sender<JobStatus>,
) -> Result<String> {
    let _ = tx.send(JobStatus::Building {
        progress: 20,
        msg: "Invoking rustc...".into(),
    });

    let args = vec![
        source_path.to_string(),
        "--edition".into(), "2021".into(),
        "--target".into(), "x86_64-pc-windows-gnu".into(),
        "--extern".into(), format!("scaffold={}", scaffold_rlib),
        "-o".into(), output_path.to_string(),
        "--crate-type".into(), crate_type.to_string(),
        "-C".into(), "opt-level=2".into(),
        "-C".into(), "panic=abort".into(),
    ];

    let output = Command::new("rustc").args(&args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = tx.send(JobStatus::Error { msg: stderr.clone() });
        anyhow::bail!("rustc failed:\n{}", stderr);
    }

    let _ = tx.send(JobStatus::Building {
        progress: 85,
        msg: "Compilation successful".into(),
    });

    Ok(output_path.to_string())
}
