#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetGetJoinInformation, NetApiBufferFree, NetSetupDomainName,
};

#[cfg(target_os = "windows")]
pub unsafe fn is_domain_joined() -> bool {
    let mut name_buf: *mut u16 = core::ptr::null_mut();
    let mut join_status: i32 = 0;
    let result = NetGetJoinInformation(
        core::ptr::null(),
        &mut name_buf,
        &mut join_status,
    );
    if result == 0 && !name_buf.is_null() {
        NetApiBufferFree(name_buf as _);
    }
    join_status == NetSetupDomainName
}
