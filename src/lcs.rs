//! LCRustdesk LAN-only build helpers.
//!
//! Everything LCS-specific that is plain logic lives here so it can be unit tested:
//! address parsing for direct connections, the signed-name check, the per-user
//! store of pinned peer keys, and the DPAPI-protected shared viewer password.

use hbb_common::config::LocalConfig;
use std::collections::HashMap;

pub const APP_NAME: &str = "LCRustdesk";
/// TCP port the service listens on for direct connections, and the default for typed addresses.
pub const DIRECT_PORT: u16 = 21118;
/// UDP port for LAN discovery (stock RustDesk uses 21119; we stay off it so both can run).
pub const DISCOVERY_PORT: u16 = 21120;

/// Custom-client "hard" settings normally supplied by a signed custom.txt.
pub const HARD: &[(&str, &str)] = &[("disable-account", "Y"), ("disable-ab", "Y")];
/// Custom-client "built-in" settings normally supplied by a signed custom.txt.
pub const BUILTIN: &[(&str, &str)] = &[
    ("hide-remote-printer-settings", "Y"),
    ("hide-server-settings", "Y"),
    ("hide-proxy-settings", "Y"),
    ("hide-websocket-settings", "Y"),
    ("hide-help-cards", "Y"),
    ("hide-stop-service", "Y"),
];

/// Marker that prefixes the service's long-term signing public key in the first
/// handshake message of a direct connection. Versioned so a future format can coexist.
pub const PK_MARKER: &[u8] = b"LCPK1";

const OPTION_PINNED_KEYS: &str = "lcs-pinned-keys";
const OPTION_SHARED_PASSWORD: &str = "lcs-shared-password";

/// Splits `input` into (host, port). Bracketed IPv6 has its brackets removed.
/// Returns None for a malformed port. A bare IPv6 address has no port.
fn split_host_port(input: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if after.is_empty() {
            return Some((host.to_owned(), None));
        }
        let port = after.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host.to_owned(), Some(port)));
    }
    if input.matches(':').count() > 1 {
        // Bare IPv6 literal.
        return Some((input.to_owned(), None));
    }
    match input.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), Some(port.parse::<u16>().ok()?))),
        None => Some((input.to_owned(), None)),
    }
}

/// Normalizes whatever the admin typed (IP, computer name or FQDN, optional port)
/// into a `host:port` socket address string, defaulting to [`DIRECT_PORT`].
pub fn lan_target(input: &str) -> Option<String> {
    let input = input.trim();
    if !crate::common::is_valid_untrusted_peer_id(input) {
        return None;
    }
    let (host, port) = split_host_port(input)?;
    let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
    if host.is_empty() {
        return None;
    }
    let port = port.unwrap_or(DIRECT_PORT);
    if host.contains(':') {
        Some(format!("[{host}]:{port}"))
    } else {
        Some(format!("{host}:{port}"))
    }
}

/// True when the computer name the peer signed is acceptable for what was typed.
/// Typed IPs accept any name; typed names must match the signed name's first label.
pub fn signed_name_ok(typed: &str, signed: &str) -> bool {
    let Some((host, _)) = split_host_port(typed.trim()) else {
        return false;
    };
    let host = host.strip_suffix('.').unwrap_or(&host);
    if hbb_common::is_ip_str(host) {
        return true;
    }
    let typed_label = host.split('.').next().unwrap_or_default();
    let signed_label = signed.trim().trim_end_matches('.').split('.').next().unwrap_or_default();
    !typed_label.is_empty() && typed_label.eq_ignore_ascii_case(signed_label)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinResult {
    FirstSeen,
    Match,
    Mismatch,
}

/// Trust-on-first-use check of a peer's long-term key, keyed by lowercased computer name.
pub fn check_pin(store: &mut HashMap<String, String>, name: &str, key_b64: &str) -> PinResult {
    let name = name.trim().to_ascii_lowercase();
    match store.get(&name) {
        None => {
            store.insert(name, key_b64.to_owned());
            PinResult::FirstSeen
        }
        Some(k) if k == key_b64 => PinResult::Match,
        Some(_) => PinResult::Mismatch,
    }
}

pub fn forget_pin(store: &mut HashMap<String, String>, name: &str) -> bool {
    store.remove(&name.trim().to_ascii_lowercase()).is_some()
}

pub fn load_pins() -> HashMap<String, String> {
    serde_json::from_str(&LocalConfig::get_option(OPTION_PINNED_KEYS)).unwrap_or_default()
}

pub fn save_pins(pins: &HashMap<String, String>) {
    let v = if pins.is_empty() {
        String::new()
    } else {
        serde_json::to_string(pins).unwrap_or_default()
    };
    LocalConfig::set_option(OPTION_PINNED_KEYS.to_owned(), v);
}

/// Encrypts `plain` for the current Windows user with DPAPI; base64 of the blob.
#[cfg(windows)]
pub fn protect(plain: &str) -> Option<String> {
    dpapi(plain.as_bytes(), true).map(crate::common::encode64)
}

/// Reverses [`protect`]. None for anything that isn't a blob this user can decrypt.
#[cfg(windows)]
pub fn unprotect(b64: &str) -> Option<String> {
    let blob = crate::common::decode64(b64).ok()?;
    String::from_utf8(dpapi(&blob, false)?).ok()
}

#[cfg(windows)]
fn dpapi(input: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    let mut data = input.to_vec();
    let mut in_blob = DATA_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &mut in_blob,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        } else {
            CryptUnprotectData(
                &mut in_blob,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        }
    };
    if ok == 0 || out_blob.pbData.is_null() {
        return None;
    }
    let out = unsafe {
        let v = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(out_blob.pbData as _);
        v
    };
    Some(out)
}

/// The shared viewer password, if this Windows user saved one.
#[cfg(windows)]
pub fn get_shared_password() -> Option<String> {
    let v = LocalConfig::get_option(OPTION_SHARED_PASSWORD);
    if v.is_empty() {
        return None;
    }
    unprotect(&v).filter(|p| !p.is_empty())
}

#[cfg(not(windows))]
pub fn get_shared_password() -> Option<String> {
    None
}

#[cfg(windows)]
pub fn set_shared_password(p: &str) {
    if let Some(v) = protect(p) {
        LocalConfig::set_option(OPTION_SHARED_PASSWORD.to_owned(), v);
    }
}

#[cfg(not(windows))]
pub fn set_shared_password(_p: &str) {}

pub fn forget_shared_password() {
    LocalConfig::set_option(OPTION_SHARED_PASSWORD.to_owned(), String::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_target_cases() {
        assert_eq!(lan_target("192.0.2.13").as_deref(), Some("192.0.2.13:21118"));
        assert_eq!(lan_target("192.0.2.13:5000").as_deref(), Some("192.0.2.13:5000"));
        assert_eq!(lan_target("Pc01").as_deref(), Some("Pc01:21118"));
        assert_eq!(
            lan_target("pc01.example.org").as_deref(),
            Some("pc01.example.org:21118")
        );
        assert_eq!(
            lan_target("pc01.example.org.").as_deref(),
            Some("pc01.example.org:21118")
        );
        assert_eq!(lan_target("host:21118").as_deref(), Some("host:21118"));
        assert_eq!(lan_target("fe80::1").as_deref(), Some("[fe80::1]:21118"));
        assert_eq!(lan_target("[fe80::1]:21118").as_deref(), Some("[fe80::1]:21118"));
        assert_eq!(lan_target("  Pc01 ").as_deref(), Some("Pc01:21118"));
        assert_eq!(lan_target(""), None);
        assert_eq!(lan_target("a/b"), None);
        assert_eq!(lan_target("host:99999"), None);
    }

    #[test]
    fn signed_name_cases() {
        assert!(signed_name_ok("Pc01", "PC01"));
        assert!(signed_name_ok("pc01.example.org:21118", "PC01"));
        assert!(signed_name_ok("PC01.EXAMPLE.ORG.", "pc01"));
        assert!(!signed_name_ok("Pc01", "LAB2"));
        assert!(signed_name_ok("192.0.2.13", "LAB2"));
        assert!(signed_name_ok("[fe80::1]:21118", "ANY"));
    }

    #[test]
    fn pin_cases() {
        let mut s = HashMap::new();
        assert_eq!(check_pin(&mut s, "Pc01", "K1"), PinResult::FirstSeen);
        assert_eq!(check_pin(&mut s, "PC01", "K1"), PinResult::Match);
        assert_eq!(check_pin(&mut s, "pc01", "K2"), PinResult::Mismatch);
        assert!(forget_pin(&mut s, "Pc01"));
        assert_eq!(check_pin(&mut s, "pc01", "K2"), PinResult::FirstSeen);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip() {
        let b = protect("S3cret-Test!").unwrap();
        assert!(!b.contains("S3cret"));
        assert_eq!(unprotect(&b).as_deref(), Some("S3cret-Test!"));
        assert_eq!(unprotect("not-base64!"), None);
    }
}
