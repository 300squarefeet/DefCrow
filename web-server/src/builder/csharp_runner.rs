use std::path::Path;
use std::process::Command;

/// Compile a single C# source file into a .NET DLL using csc.exe / mcs / dotnet
/// (whichever is found first on PATH).
///
/// `cs_path` — path to the input `.cs` source file.
/// `out_dll` — path where the compiled DLL should be written.
pub fn compile_csharp(cs_path: &str, out_dll: &str) -> Result<(), String> {
    let compiler = which::which("csc")
        .or_else(|_| which::which("mcs"))
        .or_else(|_| which::which("dotnet"))
        .map_err(|_| "neither csc.exe nor mcs (mono) nor dotnet found in PATH".to_string())?;

    let mut cmd = Command::new(&compiler);
    cmd.arg(format!("/out:{}", out_dll))
        .arg("/target:library")
        .arg("/reference:System.Configuration.Install.dll")
        .arg("/reference:System.dll")
        .arg("/optimize+")
        .arg(cs_path);

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "csc compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !Path::new(out_dll).exists() {
        return Err(format!("output not created: {}", out_dll));
    }
    Ok(())
}
