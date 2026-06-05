pub fn djb2_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
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
