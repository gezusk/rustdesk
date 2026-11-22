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

/// Reconnecting to a PC within this many seconds of a key-changed refusal, and seeing the
/// same new key again, trusts that new key.
pub const KEY_CHANGE_WINDOW_SECS: u64 = 120;
const OPTION_PENDING_KEYS: &str = "lcs-pending-keys";

#[derive(Debug, PartialEq, Eq)]
pub enum KeyChange {
    /// First sighting of this new key: refuse and remember it.
    Pending,
    /// Same new key seen again within the window: it replaced the pin.
    Accepted,
}

/// Handles a pin mismatch. The new key is only trusted on a deliberate second attempt
/// that presents the exact key seen in the refused attempt, within the window.
pub fn key_change(
    pins: &mut HashMap<String, String>,
    pending: &mut HashMap<String, (String, u64)>,
    name: &str,
    key_b64: &str,
    now_secs: u64,
) -> KeyChange {
    let name = name.trim().to_ascii_lowercase();
    match pending.get(&name) {
        Some((k, seen)) if k == key_b64 && now_secs.saturating_sub(*seen) <= KEY_CHANGE_WINDOW_SECS => {
            pending.remove(&name);
            pins.insert(name, key_b64.to_owned());
            KeyChange::Accepted
        }
        _ => {
            pending.insert(name, (key_b64.to_owned(), now_secs));
            KeyChange::Pending
        }
    }
}

fn load_pending_keys() -> HashMap<String, (String, u64)> {
    serde_json::from_str(&LocalConfig::get_option(OPTION_PENDING_KEYS)).unwrap_or_default()
}

fn save_pending_keys(pending: &HashMap<String, (String, u64)>) {
    let v = if pending.is_empty() {
        String::new()
    } else {
        serde_json::to_string(pending).unwrap_or_default()
    };
    LocalConfig::set_option(OPTION_PENDING_KEYS.to_owned(), v);
}

/// Recent entries (other than `current_id` and favorites) that belong to the same PC,
/// i.e. reported the same computer name. Names that don't identify a PC are never merged.
pub fn duplicate_recent_ids(
    current_id: &str,
    hostname: &str,
    peers: &[(String, String)],
    favorites: &[String],
) -> Vec<String> {
    let host = hostname.trim().trim_end_matches('.');
    if host.is_empty() || host.eq_ignore_ascii_case("unknown") || host.eq_ignore_ascii_case("localhost") {
        return vec![];
    }
    peers
        .iter()
        .filter(|(id, peer_host)| {
            id != current_id
                && !favorites.contains(id)
                && peer_host.trim().trim_end_matches('.').eq_ignore_ascii_case(host)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// After a successful login, keep one Recent card per PC: remove the other entries that
/// reported the same computer name (the card for the address used now is kept).
pub fn consolidate_recent(current_id: &str, hostname: &str) {
    use hbb_common::config::PeerConfig;
    let peers: Vec<(String, String)> = PeerConfig::peers(None)
        .into_iter()
        .map(|(id, _, cfg)| (id, cfg.info.hostname))
        .collect();
    for id in duplicate_recent_ids(current_id, hostname, &peers, &LocalConfig::get_fav()) {
        hbb_common::log::info!("LCS: removing duplicate recent entry {id} (same PC as {current_id})");
        PeerConfig::remove(&id);
    }
}

/// Online dots: one ICMP echo per peer (IPv4), all in parallel. A peer is online only if
/// the PC itself replied; names are resolved with Windows DNS like a connection would be.
pub async fn ping_states(ids: Vec<String>) -> (Vec<String>, Vec<String>) {
    let tasks: Vec<_> = ids
        .into_iter()
        .map(|id| {
            hbb_common::tokio::task::spawn_blocking(move || {
                let up = resolve_ipv4(&id).map(|ip| ping_ipv4(ip, 1000)).unwrap_or(false);
                (id, up)
            })
        })
        .collect();
    let (mut onlines, mut offlines) = (Vec::new(), Vec::new());
    for t in tasks {
        if let Ok((id, up)) = t.await {
            if up {
                onlines.push(id);
            } else {
                offlines.push(id);
            }
        }
    }
    (onlines, offlines)
}

fn resolve_ipv4(id: &str) -> Option<std::net::Ipv4Addr> {
    use std::net::{SocketAddr, ToSocketAddrs};
    lan_target(id)?
        .to_socket_addrs()
        .ok()?
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
}

#[cfg(windows)]
pub fn ping_ipv4(ip: std::net::Ipv4Addr, timeout_ms: u32) -> bool {
    use std::ffi::c_void;
    // winapi 0.3 has no icmpapi bindings, so declare the three iphlpapi functions directly.
    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            handle: *mut c_void,
            destination: u32,
            request_data: *mut c_void,
            request_size: u16,
            request_options: *mut c_void,
            reply_buffer: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }
    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() || handle as isize == -1 {
        return false;
    }
    let mut payload = *b"lcrustdesk-ping";
    // ICMP_ECHO_REPLY (40 bytes on x64) + echoed payload + 8 bytes for an ICMP error, per docs.
    let mut reply = vec![0u8; 128];
    let n = unsafe {
        IcmpSendEcho(
            handle,
            u32::from_ne_bytes(ip.octets()),
            payload.as_mut_ptr() as _,
            payload.len() as u16,
            std::ptr::null_mut(),
            reply.as_mut_ptr() as _,
            reply.len() as u32,
            timeout_ms,
        )
    };
    // ICMP_ECHO_REPLY starts with Address (IPAddr, u32) then Status (u32); IP_SUCCESS is 0.
    // Requiring Address == target ignores "unreachable" replies sent by a router.
    let ok = n > 0 && {
        let address = u32::from_ne_bytes([reply[0], reply[1], reply[2], reply[3]]);
        let status = u32::from_ne_bytes([reply[4], reply[5], reply[6], reply[7]]);
        status == 0 && address == u32::from_ne_bytes(ip.octets())
    };
    unsafe { IcmpCloseHandle(handle) };
    ok
}

#[cfg(not(windows))]
pub fn ping_ipv4(_ip: std::net::Ipv4Addr, _timeout_ms: u32) -> bool {
    false
}

/// Viewer side of the direct-connection handshake. Reads the service's long-term signing
/// key, verifies its signed identity with it, checks the signed computer name against what
/// was typed, pins the key on first contact, then keys `conn` with RustDesk's normal key
/// exchange. Every failure is an error: there is no unencrypted fallback.
/// Returns the peer's signed computer name.
pub async fn secure_direct(typed: &str, conn: &mut hbb_common::Stream) -> hbb_common::ResultType<String> {
    use base::message_proto::{message, Message, PublicKey};
    use hbb_common::{
        anyhow::anyhow,
        bail,
        config::{CONNECT_TIMEOUT, READ_TIMEOUT},
        protobuf::Message as _,
        sodiumoxide::crypto::sign,
        tcp, timeout,
    };

    async fn next_signed_id(conn: &mut hbb_common::Stream) -> hbb_common::ResultType<Vec<u8>> {
        let bytes = timeout(READ_TIMEOUT, conn.next())
            .await?
            .ok_or_else(|| anyhow!("Reset by the peer"))??;
        match Message::parse_from_bytes(&bytes)?.union {
            Some(message::Union::SignedId(si)) => Ok(si.id.to_vec()),
            _ => bail!("Handshake failed: unexpected message (is the remote PC running LCRustdesk?)"),
        }
    }

    let raw = next_signed_id(conn).await?;
    if raw.len() != PK_MARKER.len() + sign::PUBLICKEYBYTES || !raw.starts_with(PK_MARKER) {
        bail!("Handshake failed: the remote PC is not running LCRustdesk");
    }
    let mut pk = [0u8; sign::PUBLICKEYBYTES];
    pk.copy_from_slice(&raw[PK_MARKER.len()..]);
    let sign_pk = sign::PublicKey(pk);

    let signed = next_signed_id(conn).await?;
    let (name, their_pk_b, _, kx_version) = crate::common::decode_id_pk_dtls(&signed, &sign_pk)?;
    if !signed_name_ok(typed, &name) {
        bail!("Connected to {name}, expected {typed}");
    }

    let mut pins = load_pins();
    let key_b64 = crate::common::encode64(pk);
    match check_pin(&mut pins, &name, &key_b64) {
        PinResult::FirstSeen => save_pins(&pins),
        PinResult::Match => {}
        PinResult::Mismatch => {
            let mut pending = load_pending_keys();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            let outcome = key_change(&mut pins, &mut pending, &name, &key_b64, now);
            save_pending_keys(&pending);
            match outcome {
                KeyChange::Accepted => {
                    save_pins(&pins);
                    hbb_common::log::warn!("LCS: trusted new key for {name} after reconnect");
                }
                KeyChange::Pending => bail!(
                    "{name}'s key has changed since your last connection. If this PC was \
                     reimaged or LCRustdesk was reinstalled, connect again within 2 minutes to \
                     trust the new key. If not, don't connect and report it."
                ),
            }
        }
    }

    let (asymmetric_value, symmetric_value, key) = crate::common::create_symmetric_key_msg(their_pk_b);
    let picked = tcp::kx_version_for(kx_version);
    let mut msg_out = Message::new();
    msg_out.set_public_key(PublicKey {
        asymmetric_value: asymmetric_value.clone(),
        symmetric_value,
        kx_version: picked,
        ..Default::default()
    });
    timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
    conn.set_negotiated_key(
        key,
        true,
        &tcp::KxTranscript {
            initiator_pk: &asymmetric_value,
            responder_pk: &their_pk_b,
            advertised: kx_version,
            picked,
        },
    )?;
    hbb_common::log::info!("LCS: encrypted direct connection to {name} ({typed})");
    Ok(name)
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

    #[test]
    fn key_change_cases() {
        let mut pins = HashMap::from([("pc01".to_owned(), "OLD".to_owned())]);
        let mut pending = HashMap::new();
        // First sighting of a new key: refused and remembered, pin untouched.
        assert_eq!(key_change(&mut pins, &mut pending, "PC01", "NEW", 1000), KeyChange::Pending);
        assert_eq!(pins["pc01"], "OLD");
        // A different new key on reconnect: still refused (restarts the window).
        assert_eq!(key_change(&mut pins, &mut pending, "pc01", "OTHER", 1010), KeyChange::Pending);
        assert_eq!(pins["pc01"], "OLD");
        // Same key, but after the window: refused.
        assert_eq!(key_change(&mut pins, &mut pending, "pc01", "OTHER", 1010 + 121), KeyChange::Pending);
        // Same key again within the window: accepted, pin replaced, pending cleared.
        assert_eq!(key_change(&mut pins, &mut pending, "pc01", "OTHER", 1131 + 60), KeyChange::Accepted);
        assert_eq!(pins["pc01"], "OTHER");
        assert!(pending.is_empty());
    }

    #[test]
    fn duplicate_recent_cases() {
        let peers = vec![
            ("pc01".to_owned(), "PC01".to_owned()),
            ("192.0.2.13".to_owned(), "pc01".to_owned()),
            ("pc01.example.org".to_owned(), "pc01".to_owned()),
            ("pc02".to_owned(), "pc02".to_owned()),
            ("192.0.2.99".to_owned(), "unknown".to_owned()),
        ];
        let favs = vec!["pc01.example.org".to_owned()];
        // Same PC under another address is removed; the current entry, favorites and other PCs stay.
        assert_eq!(duplicate_recent_ids("pc01", "pc01", &peers, &favs), vec!["192.0.2.13".to_owned()]);
        // Names that don't identify a PC never merge anything.
        assert!(duplicate_recent_ids("192.0.2.99", "unknown", &peers, &[]).is_empty());
        assert!(duplicate_recent_ids("x", "", &peers, &[]).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn ping_loopback() {
        assert!(ping_ipv4(std::net::Ipv4Addr::LOCALHOST, 1000));
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
