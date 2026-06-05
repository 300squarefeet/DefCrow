#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};

#[cfg(target_os = "windows")]
pub unsafe fn looks_real() -> bool {
    let uptime_ms = GetTickCount64();
    if uptime_ms < 30 * 60 * 1000 { return false; }

    let mut mem_status: MEMORYSTATUSEX = core::mem::zeroed();
    mem_status.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut mem_status);
    if mem_status.ullTotalPhys < 2u64 * 1024 * 1024 * 1024 { return false; }

    true
}
