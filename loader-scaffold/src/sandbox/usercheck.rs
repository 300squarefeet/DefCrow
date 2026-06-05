#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO,
};

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

    true
}
