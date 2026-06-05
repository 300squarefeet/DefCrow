#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        LibraryLoader::GetModuleHandleA,
        Memory::VirtualProtect,
    },
};

/// Zero-out the PE headers of the current process image.
/// This removes the MZ/PE signature and section table from memory,
/// making memory forensics and process dumps unable to reconstruct the loader.
#[cfg(target_os = "windows")]
pub unsafe fn wipe_pe_headers() {
    let base = GetModuleHandleA(core::ptr::null()) as *mut u8;
    if base.is_null() { return; }

    // PE offset at base+0x3C; SizeOfHeaders at PE+0x54
    // Layout: PE sig (4B) + COFF (20B) = Optional Header at PE+0x18
    // SizeOfHeaders in PE32+ Optional Header is at offset 0x3C from Optional Header start
    // => PE+0x18+0x3C = PE+0x54
    let e_lfanew = core::ptr::read_unaligned(base.add(0x3C) as *const u32) as usize;
    let pe_base  = base.add(e_lfanew);
    let size_of_headers = core::ptr::read_unaligned(pe_base.add(0x54) as *const u32) as usize;
    if size_of_headers == 0 || size_of_headers > 0x10000 { return; }

    // PAGE_READWRITE = 0x04
    let mut old: u32 = 0;
    let r = VirtualProtect(base as _, size_of_headers, 0x04, &mut old);
    if r != 0 {
        core::ptr::write_bytes(base, 0u8, size_of_headers);
        VirtualProtect(base as _, size_of_headers, old, &mut old);
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn wipe_pe_headers() {}
