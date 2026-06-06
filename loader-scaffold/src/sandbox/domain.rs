/// Check domain join by looking for USERDNSDOMAIN= in the PEB environment block.
/// This env var is only set when the machine is joined to a Windows domain — no netapi32 IAT.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn is_domain_joined() -> bool {
    let peb: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    let proc_params = *((peb + 0x20) as *const usize);
    let env_ptr = *((proc_params + 0x80) as *const usize) as *const u16;
    if env_ptr.is_null() { return false; }
    // "USERDNSDOMAIN=" as wide chars
    let prefix = [85u16, 83, 69, 82, 68, 78, 83, 68, 79, 77, 65, 73, 78, 61];
    let mut ptr = env_ptr;
    loop {
        if *ptr == 0 { break; }
        let mut m = true;
        for (i, &c) in prefix.iter().enumerate() {
            if *ptr.add(i) != c { m = false; break; }
        }
        if m { return *ptr.add(prefix.len()) != 0; }
        while *ptr != 0 { ptr = ptr.add(1); }
        ptr = ptr.add(1);
    }
    false
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub unsafe fn is_domain_joined() -> bool {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetGetJoinInformation, NetApiBufferFree, NetSetupDomainName,
    };
    let mut name_buf: *mut u16 = core::ptr::null_mut();
    let mut join_status: i32 = 0;
    let result = NetGetJoinInformation(core::ptr::null(), &mut name_buf, &mut join_status);
    if result == 0 && !name_buf.is_null() { NetApiBufferFree(name_buf as _); }
    join_status == NetSetupDomainName
}
