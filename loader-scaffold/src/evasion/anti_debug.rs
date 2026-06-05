#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn is_debugged() -> bool {
    // Read PEB.BeingDebugged directly from GS segment (offset 0x60 → PEB, then +0x02)
    let being_debugged: u8;
    core::arch::asm!(
        "mov rax, gs:[0x60]",
        "movzx {0:e}, byte ptr [rax + 0x2]",
        out(reg) being_debugged,
        options(nostack, pure, readonly),
    );
    if being_debugged != 0 {
        return true;
    }

    // Check PEB.NtGlobalFlag (offset 0xBC): heap debug flags 0x70 set by debugger
    let nt_global_flag: u32;
    core::arch::asm!(
        "mov rax, gs:[0x60]",
        "mov {:e}, dword ptr [rax + 0xBC]",
        out(reg) nt_global_flag,
        options(nostack, pure, readonly),
    );
    if nt_global_flag & 0x70 != 0 {
        return true;
    }

    false
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn is_debugged() -> bool {
    false
}
