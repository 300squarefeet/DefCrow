#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

#[cfg(target_os = "windows")]
pub unsafe fn get_ssn(function_name: &[u8]) -> Option<(u16, *const u8)> {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
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
