use anyhow::Result;
use std::process::Command;
use tracing::info;

pub fn build_scaffold_rlib(workspace_root: &str) -> Result<String> {
    let rlib_path = format!(
        "{}/target/x86_64-pc-windows-gnu/release/libloader_scaffold.rlib",
        workspace_root
    );

    // Skip build if rlib already exists (e.g., pre-built or previously compiled).
    if std::path::Path::new(&rlib_path).exists() {
        info!("libloader_scaffold.rlib already present at {}", rlib_path);
        return Ok(rlib_path);
    }

    info!("Building libloader_scaffold.rlib (one-time, ~90s)...");

    // Prefer the rustup nightly cargo that has the windows-gnu target installed.
    // Fall back to the PATH cargo if the nightly wrapper is not found.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let nightly_cargo = format!(
        "{}/.rustup/toolchains/nightly-2025-01-25-aarch64-apple-darwin/bin/cargo",
        home
    );
    let cargo_bin = if std::path::Path::new(&nightly_cargo).exists() {
        nightly_cargo
    } else {
        "cargo".into()
    };

    // Build the rlib with size-optimised release + embedded bitcode so the
    // loader's final rustc invocation can run LTO across both crates.
    // (linker-plugin-lto requires bitcode in every rlib; the windows-gnu
    // stdlib bundled with rustup does NOT ship bitcode, but as long as our
    // OWN scaffold rlib carries bitcode, `-C lto=fat` on the loader works.)
    let output = Command::new(&cargo_bin)
        .args([
            "build", "--release",
            "-p", "loader-scaffold",
            "--target", "x86_64-pc-windows-gnu",
        ])
        .env("CARGO_PROFILE_RELEASE_LTO",           "off")
        .env("CARGO_PROFILE_RELEASE_OPT_LEVEL",     "z")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env("RUSTFLAGS",                           "-C embed-bitcode=yes")
        .env(
            "RUSTC",
            format!(
                "{}/.rustup/toolchains/nightly-2025-01-25-aarch64-apple-darwin/bin/rustc",
                std::env::var("HOME").unwrap_or_else(|_| "/root".into())
            ),
        )
        .current_dir(workspace_root)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("scaffold build failed:\n{}", stderr);
    }

    if !std::path::Path::new(&rlib_path).exists() {
        anyhow::bail!("libloader_scaffold.rlib not found at {}", rlib_path);
    }
    info!("libloader_scaffold.rlib ready at {}", rlib_path);
    Ok(rlib_path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rlib_path_format() {
        let path = format!("{}/target/x86_64-pc-windows-gnu/release/libloader_scaffold.rlib", "/workspace");
        assert!(path.ends_with("libloader_scaffold.rlib"));
        assert!(path.contains("x86_64-pc-windows-gnu"));
    }
}
