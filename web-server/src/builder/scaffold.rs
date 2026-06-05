use anyhow::Result;
use std::process::Command;
use tracing::info;

pub fn build_scaffold_rlib(workspace_root: &str) -> Result<String> {
    info!("Building libscaffold.rlib (one-time, ~90s)...");
    let output = Command::new("cargo")
        .args([
            "build", "--release",
            "-p", "loader-scaffold",
            "--target", "x86_64-pc-windows-gnu",
        ])
        .current_dir(workspace_root)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("scaffold build failed:\n{}", stderr);
    }

    let rlib_path = format!(
        "{}/target/x86_64-pc-windows-gnu/release/libscaffold.rlib",
        workspace_root
    );
    if !std::path::Path::new(&rlib_path).exists() {
        anyhow::bail!("libscaffold.rlib not found at {}", rlib_path);
    }
    info!("libscaffold.rlib ready at {}", rlib_path);
    Ok(rlib_path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rlib_path_format() {
        let path = format!("{}/target/x86_64-pc-windows-gnu/release/libscaffold.rlib", "/workspace");
        assert!(path.ends_with("libscaffold.rlib"));
        assert!(path.contains("x86_64-pc-windows-gnu"));
    }
}
