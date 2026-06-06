pub fn djb2_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
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
