/// Query NtQueryInformationProcess with an arbitrary ProcessInformationClass.
/// Returns (status, value): status==0 means success.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn nqip_usize(class: usize) -> (i32, usize) {
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;
    let (ssn, tramp) = match get_ssn_h(h::NT_QI_PROC) {
        Some(v) => v,
        None => return (-1, 0),
    };
    let mut value: usize = 0;
    let mut return_len: u32 = 0;
    let status = crate::evasion::syscalls::indirect_syscall(
        ssn, tramp,
        usize::MAX, // -1 = current process
        class,
        &mut value as *mut usize as usize,
        core::mem::size_of::<usize>() as usize,
        &mut return_len as *mut u32 as usize,
        0,
    );
    (status, value)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn is_debugged() -> bool {
    // PEB.BeingDebugged via GS register (no API call)
    let being_debugged: u32;
    core::arch::asm!(
        "mov rax, gs:[0x60]",
        "movzx {0:e}, byte ptr [rax + 0x2]",
        out(reg) being_debugged,
        options(nostack, pure, readonly),
    );
    if being_debugged != 0 { return true; }

    // PEB.NtGlobalFlag bits 0x70: heap debug flags set by debugger
    let nt_global_flag: u32;
    core::arch::asm!(
        "mov rax, gs:[0x60]",
        "mov {:e}, dword ptr [rax + 0xBC]",
        out(reg) nt_global_flag,
        options(nostack, pure, readonly),
    );
    if nt_global_flag & 0x70 != 0 { return true; }

    // ProcessDebugPort (7): non-zero → kernel debugger or user-mode debugger attached
    let (s1, port) = nqip_usize(7);
    if s1 == 0 && port != 0 { return true; }

    // ProcessDebugFlags (0x1F): value 0 → being debugged (inverse logic)
    let (s2, flags) = nqip_usize(0x1F);
    if s2 == 0 && flags == 0 { return true; }

    // ProcessDebugObjectHandle (0x1E): non-null handle → debugger attached
    let (s3, handle) = nqip_usize(0x1E);
    if s3 == 0 && handle != 0 { return true; }

    false
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn is_debugged() -> bool {
    false
}
