use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAGIC_HEADER_TLS: [u8; 3] = [0x16, 0x03, 0x01]; // TLS 1.2 Record Header (standard ClientHello)
pub const MAX_PAYLOAD_SIZE: usize = 16384; // 16KB standard TLS record limit
pub const MAX_PADDING_SIZE: u16 = 1024; // Upper bound for anti-DPI padding per frame
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 4 + TAG_LEN;

// Tunnel Command types
pub const CMD_CONNECT: u8 = 0x11;
pub const CMD_UDP_ASSOCIATE: u8 = 0x12;

pub struct CryptoKeys {
    pub client_enc_key: [u8; 32],
    pub server_enc_key: [u8; 32],
}

// =============== Dynamic TLS Fingerprint Profile ===============

/// Describes a full TLS ClientHello fingerprint: cipher suite order,
/// extension composition, supported groups, ALPN, signature algorithms,
/// padding range, etc. The builder uses GREASE (RFC 8701) to insert
/// random values at profile-defined positions.
#[derive(Debug, Clone)]
pub struct TlsFingerprintProfile {
    pub name: &'static str,
    /// Cipher suites excluding the GREASE sentinel.
    pub cipher_suites: &'static [u16],
    /// Index at which a GREASE cipher suite will be inserted.
    pub grease_cipher_position: usize,
    /// Supported groups excluding the GREASE sentinel.
    pub groups: &'static [u16],
    /// Index at which a GREASE group will be inserted.
    pub grease_group_position: usize,
    /// Supported TLS versions excluding the GREASE sentinel.
    pub supported_versions: &'static [u16],
    /// Index at which a GREASE version will be inserted.
    pub grease_version_position: usize,
    /// ALPN protocols in order, as raw byte strings (e.g. b"h2").
    pub alpn_protocols: &'static [&'static [u8]],
    /// TLS signature algorithms in client order.
    pub signature_algorithms: &'static [u16],
    /// EC point formats (e.g. uncompressed = [0x00]).
    pub point_formats: &'static [u8],
    pub include_extended_master_secret: bool,
    pub include_renegotiation_info: bool,
    pub include_session_ticket: bool,
    pub include_ocsp_status_request: bool,
    pub include_signed_certificate_timestamp: bool,
    pub include_psk_key_exchange_modes: bool,
    pub include_compress_certificate: bool,
    pub include_application_settings: bool,
    /// Minimum padding target for the Padding extension (bytes).
    pub padding_min: usize,
    /// Maximum padding target for the Padding extension (bytes).
    pub padding_max: usize,
}

/// Chrome 124+ profile that matches the existing hardcoded behaviour.
/// It can be used as the default when no custom profile is desired.
pub fn chrome_124_profile() -> TlsFingerprintProfile {
    TlsFingerprintProfile {
        name: "chrome_124",
        cipher_suites: &[
            0x1301, 0x1302, 0x1303, // TLS 1.3 AEADs
            0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDSA/RSA GCM suites
            0xcca9, 0xcca8, // ChaCha20 suites
            0xc013, 0xc014, // CBC suites
            0x009c, 0x009d, 0x002f, 0x0035, // RSA fallback
        ],
        grease_cipher_position: 0,
        groups: &[0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
        grease_group_position: 0,
        supported_versions: &[0x0304, 0x0303], // TLS 1.3, TLS 1.2
        grease_version_position: 0,
        alpn_protocols: &[b"h2", b"http/1.1"],
        signature_algorithms: &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        point_formats: &[0x00],
        include_extended_master_secret: true,
        include_renegotiation_info: true,
        include_session_ticket: true,
        include_ocsp_status_request: true,
        include_signed_certificate_timestamp: true,
        include_psk_key_exchange_modes: true,
        include_compress_certificate: true,
        include_application_settings: true,
        padding_min: 560,
        padding_max: 680,
    }
}

const REPLAY_SHARDS: usize = 32;

struct ReplayShard {
    seen: HashMap<[u8; 16], Instant>,
    last_cleanup: Instant,
}

/// Thread-safe sharded sliding-window replay attack filter.
/// 32 independent mutex shards eliminate lock contention under high concurrency.
pub struct ReplayFilter {
    shards: Vec<Mutex<ReplayShard>>,
    ttl: Duration,
}

impl ReplayFilter {
    pub fn new(ttl_secs: u64) -> Self {
        let now = Instant::now();
        let mut shards = Vec::with_capacity(REPLAY_SHARDS);
        for _ in 0..REPLAY_SHARDS {
            shards.push(Mutex::new(ReplayShard {
                seen: HashMap::new(),
                last_cleanup: now,
            }));
        }
        Self {
            shards,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    #[inline]
    fn shard_index(token: &[u8; 16]) -> usize {
        // FNV-1a over the full token. The token's first 8 bytes are a big-endian
        // Unix timestamp (whose high bytes are near-constant within a session
        // window), so hashing only a prefix would collapse every token onto a
        // single shard. Hashing the whole 16-byte token (timestamp + random salt)
        // yields a uniform distribution across all shards.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in token.iter() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (h % REPLAY_SHARDS as u64) as usize
    }

    pub fn check_and_record(&self, token: &[u8; 16]) -> bool {
        let idx = Self::shard_index(token);
        let now = Instant::now();
        let mut shard = match self.shards[idx].lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Perform table cleanup at most once every 30 seconds per shard (amortized O(1))
        if now.duration_since(shard.last_cleanup) > Duration::from_secs(30) {
            let ttl = self.ttl;
            shard
                .seen
                .retain(|_, inserted_at| now.duration_since(*inserted_at) < ttl);
            shard.last_cleanup = now;
        }

        if shard.seen.contains_key(token) {
            return false; // Replay attack detected
        }

        shard.seen.insert(*token, now);
        true
    }
}

pub fn derive_master_key(secret: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("NOVL-v1-MASTER-KEY");
    hasher.update(secret.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn generate_auth_session_id(master_key: &[u8; 32]) -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut salt = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut data = [0u8; 16];
    BigEndian::write_u64(&mut data[0..8], now);
    data[8..16].copy_from_slice(&salt);

    let mut keyed_hasher = blake3::Hasher::new_keyed(master_key);
    keyed_hasher.update(&data);
    let mac = keyed_hasher.finalize();

    let mut session_id = [0u8; 32];
    session_id[0..16].copy_from_slice(&data);
    session_id[16..32].copy_from_slice(&mac.as_bytes()[0..16]);
    session_id
}

pub fn verify_auth_session_id(
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    replay_filter: &ReplayFilter,
) -> bool {
    let ts = BigEndian::read_u64(&session_id[0..8]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check sliding window of +/- 90 seconds
    if ts.abs_diff(now) > 90 {
        return false;
    }

    let mut keyed_hasher = blake3::Hasher::new_keyed(master_key);
    keyed_hasher.update(&session_id[0..16]);
    let mac = keyed_hasher.finalize();

    // Constant-time comparison
    let expected = &mac.as_bytes()[0..16];
    let actual = &session_id[16..32];
    if !subtle_eq(expected, actual) {
        return false;
    }

    // Check against replay filter
    let mut token = [0u8; 16];
    token.copy_from_slice(&session_id[0..16]);
    replay_filter.check_and_record(&token)
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

pub fn derive_session_keys(master_key: &[u8; 32], session_id: &[u8; 32]) -> CryptoKeys {
    let mut c2s_hasher = blake3::Hasher::new_derive_key("NOVL-v1-C2S-SESSION-KEY");
    c2s_hasher.update(master_key);
    c2s_hasher.update(session_id);
    let client_key = *c2s_hasher.finalize().as_bytes();

    let mut s2c_hasher = blake3::Hasher::new_derive_key("NOVL-v1-S2C-SESSION-KEY");
    s2c_hasher.update(master_key);
    s2c_hasher.update(session_id);
    let server_key = *s2c_hasher.finalize().as_bytes();

    CryptoKeys {
        client_enc_key: client_key,
        server_enc_key: server_key,
    }
}

const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Builds an authentic TLS 1.3 ClientHello using the supplied fingerprint
/// profile, with authenticated Session ID, GREASE extensions/ciphers, ALPN,
/// KeyShare, and AmneziaWG-style dynamic padding jitter.
pub fn build_chameleon_client_hello(
    profile: &TlsFingerprintProfile,
    master_key: &[u8; 32],
    sni: &str,
) -> Vec<u8> {
    let session_id = generate_auth_session_id(master_key);
    let mut rng = rand::thread_rng();

    let grease_cipher = GREASE_VALUES[rng.gen_range(0..16)];
    let grease_group = GREASE_VALUES[rng.gen_range(0..16)];
    let grease_version = GREASE_VALUES[rng.gen_range(0..16)];

    // 32-byte client random
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    // TLS ClientHello Body
    let mut body = Vec::with_capacity(600);

    // Client Version: TLS 1.2 legacy (0x03, 0x03)
    body.extend_from_slice(&[0x03, 0x03]);
    // Random (32)
    body.extend_from_slice(&random);
    // Legacy Session ID (Length 32)
    body.push(32);
    body.extend_from_slice(&session_id);

    // Cipher Suites: profile order with GREASE inserted at configured position
    let mut ciphers: Vec<u16> = profile.cipher_suites.to_vec();
    let insert_pos = profile.grease_cipher_position.min(ciphers.len());
    ciphers.insert(insert_pos, grease_cipher);

    let mut cipher_bytes = Vec::with_capacity(ciphers.len() * 2);
    for suite in &ciphers {
        cipher_bytes.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);

    // Compression Methods: 1 method, 0x00 (null)
    body.extend_from_slice(&[0x01, 0x00]);

    // Extensions in profile-defined composition/order
    let mut extensions = Vec::with_capacity(512);

    // 1. Server Name Indication (SNI) (0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes()); // list len
    sni_ext.push(0x00); // host_name type
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // 2. Extended Master Secret (0x0017) - optional
    if profile.include_extended_master_secret {
        extensions.extend_from_slice(&0x0017u16.to_be_bytes());
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    }

    // 3. Renegotiation Info (0xff01) - optional
    if profile.include_renegotiation_info {
        extensions.extend_from_slice(&0xff01u16.to_be_bytes());
        extensions.extend_from_slice(&0x0001u16.to_be_bytes());
        extensions.push(0x00);
    }

    // 4. Supported Groups (0x000a) - profile order + GREASE
    let mut groups: Vec<u16> = profile.groups.to_vec();
    let insert_group = profile.grease_group_position.min(groups.len());
    groups.insert(insert_group, grease_group);

    let mut groups_data = Vec::new();
    for grp in &groups {
        groups_data.extend_from_slice(&grp.to_be_bytes());
    }
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&(groups_data.len() as u16).to_be_bytes());
    groups_ext.extend_from_slice(&groups_data);
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&(groups_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&groups_ext);

    // 5. EC Point Formats (0x000b) - from profile
    let mut point_formats_ext = Vec::new();
    point_formats_ext.push(profile.point_formats.len() as u8);
    point_formats_ext.extend_from_slice(profile.point_formats);
    extensions.extend_from_slice(&0x000bu16.to_be_bytes());
    extensions.extend_from_slice(&(point_formats_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&point_formats_ext);

    // 6. Session Ticket (0x0023) - optional
    if profile.include_session_ticket {
        extensions.extend_from_slice(&0x0023u16.to_be_bytes());
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    }

    // 7. ALPN (0x0010) - profile order and protocols
    let mut alpn_payload = Vec::new();
    let mut alpn_list_len: usize = 0;
    for proto in profile.alpn_protocols {
        alpn_list_len += 1 + proto.len();
    }
    alpn_payload.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
    for proto in profile.alpn_protocols {
        alpn_payload.push(proto.len() as u8);
        alpn_payload.extend_from_slice(proto);
    }
    extensions.extend_from_slice(&0x0010u16.to_be_bytes());
    extensions.extend_from_slice(&(alpn_payload.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&alpn_payload);

    // 8. Status Request (OCSP) (0x0005) - optional
    if profile.include_ocsp_status_request {
        let ocsp = [0x01, 0x00, 0x00, 0x00, 0x00];
        extensions.extend_from_slice(&0x0005u16.to_be_bytes());
        extensions.extend_from_slice(&(ocsp.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ocsp);
    }

    // 9. Signature Algorithms (0x000d) - from profile
    let mut sig_data = Vec::new();
    for alg in profile.signature_algorithms {
        sig_data.extend_from_slice(&alg.to_be_bytes());
    }
    let mut sig_ext = Vec::new();
    sig_ext.extend_from_slice(&(sig_data.len() as u16).to_be_bytes());
    sig_ext.extend_from_slice(&sig_data);
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    extensions.extend_from_slice(&(sig_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sig_ext);

    // 10. Signed Certificate Timestamp (0x0012) - optional
    if profile.include_signed_certificate_timestamp {
        extensions.extend_from_slice(&0x0012u16.to_be_bytes());
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    }

    // 11. Key Share (0x0033) - GREASE + x25519 (profile groups influence possible future KEM)
    let mut client_key_share = [0u8; 32];
    rng.fill_bytes(&mut client_key_share);
    let mut ks_data = Vec::new();
    ks_data.extend_from_slice(&grease_group.to_be_bytes());
    ks_data.extend_from_slice(&1u16.to_be_bytes());
    ks_data.push(0x00);
    ks_data.extend_from_slice(&0x001du16.to_be_bytes());
    ks_data.extend_from_slice(&32u16.to_be_bytes());
    ks_data.extend_from_slice(&client_key_share);

    let mut ks_ext = Vec::new();
    ks_ext.extend_from_slice(&(ks_data.len() as u16).to_be_bytes());
    ks_ext.extend_from_slice(&ks_data);
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ks_ext);

    // 12. PSK Key Exchange Modes (0x002d) - optional
    if profile.include_psk_key_exchange_modes {
        let psk_modes = [0x01, 0x01];
        extensions.extend_from_slice(&0x002du16.to_be_bytes());
        extensions.extend_from_slice(&(psk_modes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&psk_modes);
    }

    // 13. Supported Versions (0x002b) - profile order + GREASE
    let mut sup_versions = profile.supported_versions.to_vec();
    let insert_ver = profile.grease_version_position.min(sup_versions.len());
    sup_versions.insert(insert_ver, grease_version);
    let mut sup_data = Vec::new();
    for v in &sup_versions {
        sup_data.extend_from_slice(&v.to_be_bytes());
    }
    let mut sup_ext = Vec::new();
    sup_ext.push(sup_data.len() as u8);
    sup_ext.extend_from_slice(&sup_data);
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(sup_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sup_ext);

    // 14. Compress Certificate (0x001b) - optional
    if profile.include_compress_certificate {
        let comp_data = [0x02, 0x00, 0x02];
        extensions.extend_from_slice(&0x001bu16.to_be_bytes());
        extensions.extend_from_slice(&(comp_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&comp_data);
    }

    // 15. Application Settings (ALPS) (0x4469) - optional (h2)
    if profile.include_application_settings {
        // Use first ALPN protocol if available; here we always emulate h2
        let alps_data = [0x00, 0x03, 0x02, b'h', b'2'];
        extensions.extend_from_slice(&0x4469u16.to_be_bytes());
        extensions.extend_from_slice(&(alps_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alps_data);
    }

    // 16. Padding extension with randomized jitter from profile range
    let current_total = 5 + 4 + body.len() + 2 + extensions.len();
    if profile.padding_min < profile.padding_max {
        let pad_range = profile.padding_max - profile.padding_min;
        let extra = rng.gen_range(0..=pad_range);
        let target_total = profile.padding_min + extra;
        if target_total > current_total + 4 {
            let pad_len = target_total - (current_total + 4);
            let padding = vec![0u8; pad_len];
            extensions.extend_from_slice(&0x0015u16.to_be_bytes());
            extensions.extend_from_slice(&(pad_len as u16).to_be_bytes());
            extensions.extend_from_slice(&padding);
        }
    }

    // Extensions length + extensions
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // Handshake header: 0x01 (ClientHello), 3 bytes length
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    let blen = body.len() as u32;
    handshake.push(((blen >> 16) & 0xff) as u8);
    handshake.push(((blen >> 8) & 0xff) as u8);
    handshake.push((blen & 0xff) as u8);
    handshake.extend_from_slice(&body);

    // TLS Record Header: 0x16 0x03 0x01 + 2 bytes record len
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.extend_from_slice(&MAGIC_HEADER_TLS);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Locates the byte range of the SNI hostname inside a TLS ClientHello record
pub fn locate_sni_offset(client_hello: &[u8], sni: &str) -> Option<(usize, usize)> {
    if sni.is_empty() {
        return None;
    }
    let sni_bytes = sni.as_bytes();
    client_hello
        .windows(sni_bytes.len())
        .position(|window| window == sni_bytes)
        .map(|idx| (idx, idx + sni_bytes.len()))
}

/// Parses the 32-byte Session ID out of an incoming TLS ClientHello
pub fn extract_session_id(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() < 5 + 4 + 2 + 32 + 1 + 32 {
        return None;
    }
    // Must start with TLS Handshake Record
    if buf[0] != 0x16 {
        return None;
    }
    // Handshake message type must be ClientHello (0x01)
    if buf[5] != 0x01 {
        return None;
    }

    // Skip record header (5) + Handshake type (1) + length (3) + client_version (2) + random (32)
    let pos = 5 + 1 + 3 + 2 + 32;
    let session_id_len = buf[pos] as usize;
    if session_id_len != 32 || buf.len() < pos + 1 + 32 {
        return None;
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&buf[pos + 1..pos + 1 + 32]);
    Some(session_id)
}

/// Disguised ServerHello response with realistic TLS 1.3 KeyShare and Middlebox CCS
pub fn build_chameleon_server_hello() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut server_random = [0u8; 32];
    rng.fill_bytes(&mut server_random);

    // Handshake body
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
    body.extend_from_slice(&server_random);
    body.push(0x00); // legacy session ID len 0
    body.extend_from_slice(&[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256
    body.push(0x00); // compression null

    let mut extensions = Vec::new();

    // Supported versions ext (TLS 1.3)
    let sup_versions = [0x03, 0x04];
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(sup_versions.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sup_versions);

    // Key Share ext (x25519)
    let mut server_key_share = [0u8; 32];
    rng.fill_bytes(&mut server_key_share);
    let mut ks_ext = Vec::new();
    ks_ext.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
    ks_ext.extend_from_slice(&32u16.to_be_bytes());
    ks_ext.extend_from_slice(&server_key_share);

    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ks_ext);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(0x02); // ServerHello
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xff) as u8);
    hs.push(((blen >> 8) & 0xff) as u8);
    hs.push((blen & 0xff) as u8);
    hs.extend_from_slice(&body);

    // Record: 0x16 0x03 0x03
    let mut out = Vec::new();
    out.extend_from_slice(&[0x16, 0x03, 0x03]);
    out.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    out.extend_from_slice(&hs);

    // ChangeCipherSpec fake record (RFC 8446 middlebox compatibility)
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out
}

pub struct StreamCipher {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

impl StreamCipher {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
            nonce_counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..12], self.nonce_counter);
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypts a payload into a framed buffer with authenticated length/padding headers (AEAD AAD)
    pub fn encrypt_frame(&mut self, payload: &[u8], pad_len: u16) -> Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            bail!("Payload exceeds maximum allowed frame size");
        }
        if pad_len > MAX_PADDING_SIZE {
            bail!("Padding exceeds maximum allowed frame padding");
        }

        let mut aad = [0u8; 4];
        BigEndian::write_u16(&mut aad[0..2], payload.len() as u16);
        BigEndian::write_u16(&mut aad[2..4], pad_len);

        let nonce = self.next_nonce();
        let ciphertext = if pad_len == 0 {
            self.cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: payload,
                        aad: &aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?
        } else {
            let total_raw = payload.len() + pad_len as usize;
            let mut raw = Vec::with_capacity(total_raw);
            raw.extend_from_slice(payload);
            let start = raw.len();
            raw.resize(total_raw, 0);
            rand::thread_rng().fill_bytes(&mut raw[start..]);
            self.cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: &raw,
                        aad: &aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?
        };

        let mut frame = Vec::with_capacity(4 + ciphertext.len());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }

    /// Decrypts a frame with cryptographic verification of length/padding headers (AEAD AAD)
    pub fn decrypt_frame(
        &mut self,
        payload_len: u16,
        pad_len: u16,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if (payload_len as usize) > MAX_PAYLOAD_SIZE || pad_len > MAX_PADDING_SIZE {
            bail!("Frame length fields exceed maximum bounds");
        }

        let expected_ct_len = (payload_len as usize) + (pad_len as usize) + TAG_LEN;
        if ciphertext.len() != expected_ct_len {
            bail!(
                "Ciphertext length mismatch: expected {}, got {}",
                expected_ct_len,
                ciphertext.len()
            );
        }

        let mut aad = [0u8; 4];
        BigEndian::write_u16(&mut aad[0..2], payload_len);
        BigEndian::write_u16(&mut aad[2..4], pad_len);

        let nonce = self.next_nonce();
        let decrypted = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))?;

        let mut data = decrypted;
        data.truncate(payload_len as usize);
        Ok(data)
    }
}

/// Reads and decrypts an AEAD frame asynchronously from any AsyncRead source
pub async fn read_decrypted_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    decryptor: &mut StreamCipher,
) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let payload_len = u16::from_be_bytes([header[0], header[1]]);
    let pad_len = u16::from_be_bytes([header[2], header[3]]);

    if (payload_len as usize) > MAX_PAYLOAD_SIZE || pad_len > MAX_PADDING_SIZE {
        bail!("Frame dimensions exceed bounds");
    }

    let total_ct_len = (payload_len as usize) + (pad_len as usize) + TAG_LEN;
    let mut ct = vec![0u8; total_ct_len];
    reader.read_exact(&mut ct).await?;

    decryptor.decrypt_frame(payload_len, pad_len, &ct)
}

/// Configures standard TCP keepalive probes (idle 30s, interval 10s) to keep long-running streams (like Telegram MTProto) alive
pub fn configure_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let sock_ref = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}

/// Hex encode helper
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Hex decode helper
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let input = s.as_bytes();
    if !input.len().is_multiple_of(2) {
        return None;
    }

    fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    for pair in input.as_chunks::<2>().0 {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

/// Builds an HTTP/1.1 WebSocket Upgrade request with auth in Sec-WebSocket-Key
pub fn build_http_upgrade_request(
    path: &str,
    host: &str,
    master_key: &[u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let session_id = generate_auth_session_id(master_key);
    let hex_key = to_hex(&session_id);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, hex_key
    );
    (req.into_bytes(), session_id)
}

/// Extracts authenticated session ID from Sec-WebSocket-Key or X-Novl-Auth header
pub fn extract_http_auth(buf: &[u8]) -> Option<[u8; 32]> {
    let text = String::from_utf8_lossy(buf);
    for line in text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("sec-websocket-key:") || lower.starts_with("x-novl-auth:") {
            let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
            if parts.len() == 2 {
                let val = parts[1].trim();
                if let Some(bytes) = from_hex(val) {
                    if bytes.len() == 32 {
                        let mut sid = [0u8; 32];
                        sid.copy_from_slice(&bytes);
                        return Some(sid);
                    }
                }
            }
        }
    }
    None
}

pub const HTTP_UPGRADE_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_auth_session_id() {
        let master_key = derive_master_key("test-secret-uuid");
        let replay = ReplayFilter::new(90);
        let session_id = generate_auth_session_id(&master_key);
        assert!(verify_auth_session_id(&master_key, &session_id, &replay));

        // Tampered session ID must fail
        let mut tampered = session_id;
        tampered[20] ^= 0xff;
        let replay2 = ReplayFilter::new(90);
        assert!(!verify_auth_session_id(&master_key, &tampered, &replay2));
    }

    #[test]
    fn test_replay_protection() {
        let master_key = derive_master_key("replay-test-secret");
        let replay = ReplayFilter::new(90);
        let session_id = generate_auth_session_id(&master_key);

        // First verification succeeds
        assert!(verify_auth_session_id(&master_key, &session_id, &replay));

        // Second verification with same session ID must fail (replay attack blocked)
        assert!(!verify_auth_session_id(&master_key, &session_id, &replay));
    }

    #[test]
    fn test_sharded_replay_filter_concurrency() {
        let filter = Arc::new(ReplayFilter::new(60));
        let num_threads = 32;
        let ops_per_thread = 500;
        let mut handles = Vec::new();

        // 1. Concurrent insertions of unique tokens across 32 threads
        for t in 0..num_threads {
            let filter_clone = Arc::clone(&filter);
            handles.push(thread::spawn(move || {
                for i in 0..ops_per_thread {
                    let mut token = [0u8; 16];
                    token[0] = t as u8;
                    token[1] = (i >> 8) as u8;
                    token[2] = (i & 0xff) as u8;
                    token[3] = 0xaa;
                    let accepted = filter_clone.check_and_record(&token);
                    assert!(accepted, "Unique token must be accepted");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // 2. Concurrent contention on the same set of colliding tokens
        let contested_filter = Arc::new(ReplayFilter::new(60));
        let accepted_count = Arc::new(AtomicUsize::new(0));
        let mut race_handles = Vec::new();

        for _ in 0..16 {
            let filter_clone = Arc::clone(&contested_filter);
            let counter_clone = Arc::clone(&accepted_count);
            race_handles.push(thread::spawn(move || {
                let shared_token = [42u8; 16];
                if filter_clone.check_and_record(&shared_token) {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in race_handles {
            h.join().unwrap();
        }

        // Exactly one thread must have successfully recorded the token
        assert_eq!(
            accepted_count.load(Ordering::SeqCst),
            1,
            "Exactly one thread must win race on colliding token"
        );
    }

    #[test]
    fn test_client_hello_chameleon() {
        let master_key = derive_master_key("my-secret-key-123");
        let sni = "addons.mozilla.org";
        let profile = chrome_124_profile();
        let client_hello = build_chameleon_client_hello(&profile, &master_key, sni);

        assert_eq!(&client_hello[0..3], &MAGIC_HEADER_TLS);
        let extracted_sid =
            extract_session_id(&client_hello).expect("Session ID must be extracted");
        let replay = ReplayFilter::new(90);
        assert!(verify_auth_session_id(&master_key, &extracted_sid, &replay));
    }

    #[test]
    fn test_frame_crypto_with_aad() {
        let master_key = derive_master_key("secret");
        let session_id = generate_auth_session_id(&master_key);
        let keys = derive_session_keys(&master_key, &session_id);

        let mut enc = StreamCipher::new(&keys.client_enc_key);
        let mut dec = StreamCipher::new(&keys.client_enc_key);

        let original = b"Hello, Project NOVL! Ultra-fast anti-censorship tunnel.";
        let frame = enc
            .encrypt_frame(original, 24)
            .expect("encryption succeeds");

        let payload_len = u16::from_be_bytes([frame[0], frame[1]]);
        let pad_len = u16::from_be_bytes([frame[2], frame[3]]);
        let decrypted = dec
            .decrypt_frame(payload_len, pad_len, &frame[4..])
            .expect("decryption succeeds");

        assert_eq!(original.as_slice(), decrypted.as_slice());

        // Tampering with payload_len or pad_len MUST fail due to AAD authentication
        let mut tampered_dec = StreamCipher::new(&keys.client_enc_key);
        assert!(tampered_dec
            .decrypt_frame(payload_len + 1, pad_len.saturating_sub(1), &frame[4..])
            .is_err());
    }

    #[test]
    fn test_tamper_ciphertext_bitflips() {
        let key = [0x55u8; 32];
        let mut enc = StreamCipher::new(&key);
        let original = b"Sensitive payload data for tamper verification";
        let frame = enc.encrypt_frame(original, 8).expect("encryption ok");

        let payload_len = u16::from_be_bytes([frame[0], frame[1]]);
        let pad_len = u16::from_be_bytes([frame[2], frame[3]]);
        let ciphertext = &frame[4..];

        // 1. Bit-flip in ciphertext body
        let mut corrupted_ct = ciphertext.to_vec();
        corrupted_ct[5] ^= 0x01;
        let mut dec1 = StreamCipher::new(&key);
        assert!(
            dec1.decrypt_frame(payload_len, pad_len, &corrupted_ct)
                .is_err(),
            "Ciphertext body corruption must be rejected by AEAD"
        );

        // 2. Bit-flip in Poly1305 authentication tag (last 16 bytes)
        let mut tag_corrupted_ct = ciphertext.to_vec();
        let tag_idx = tag_corrupted_ct.len() - 1;
        tag_corrupted_ct[tag_idx] ^= 0x80;
        let mut dec2 = StreamCipher::new(&key);
        assert!(
            dec2.decrypt_frame(payload_len, pad_len, &tag_corrupted_ct)
                .is_err(),
            "Tag corruption must be rejected by AEAD"
        );

        // 3. Truncated ciphertext (< TAG_LEN)
        let truncated = &ciphertext[..10];
        let mut dec3 = StreamCipher::new(&key);
        assert!(
            dec3.decrypt_frame(payload_len, pad_len, truncated).is_err(),
            "Truncated ciphertext must be rejected"
        );
    }

    #[test]
    fn test_stream_cipher_nonce_desync() {
        let key = [0x77u8; 32];
        let mut enc = StreamCipher::new(&key);
        let mut dec = StreamCipher::new(&key);

        let frame1 = enc.encrypt_frame(b"frame 1", 0).unwrap();
        let frame2 = enc.encrypt_frame(b"frame 2", 0).unwrap();

        // Skip frame 1 on decryptor, attempt decrypting frame 2
        let p_len2 = u16::from_be_bytes([frame2[0], frame2[1]]);
        let pad_len2 = u16::from_be_bytes([frame2[2], frame2[3]]);
        assert!(
            dec.decrypt_frame(p_len2, pad_len2, &frame2[4..]).is_err(),
            "Nonce desynchronization must cause AEAD authentication failure"
        );

        // If decryptor decrypts frame1 first, then frame2 succeeds
        let mut dec_in_order = StreamCipher::new(&key);
        let p_len1 = u16::from_be_bytes([frame1[0], frame1[1]]);
        let pad_len1 = u16::from_be_bytes([frame1[2], frame1[3]]);
        assert!(dec_in_order
            .decrypt_frame(p_len1, pad_len1, &frame1[4..])
            .is_ok());
        assert!(dec_in_order
            .decrypt_frame(p_len2, pad_len2, &frame2[4..])
            .is_ok());
    }

    #[test]
    fn test_max_frame_bounds() {
        let key = [0x88u8; 32];
        let mut enc = StreamCipher::new(&key);

        // Payload exceeding MAX_PAYLOAD_SIZE must error
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(enc.encrypt_frame(&oversized, 0).is_err());

        // Max payload size exactly must succeed
        let max_payload = vec![0xaa; MAX_PAYLOAD_SIZE];
        let frame = enc
            .encrypt_frame(&max_payload, 512)
            .expect("Max payload must encrypt");
        let mut dec = StreamCipher::new(&key);
        let p_len = u16::from_be_bytes([frame[0], frame[1]]);
        let pad_len = u16::from_be_bytes([frame[2], frame[3]]);
        let dec_data = dec
            .decrypt_frame(p_len, pad_len, &frame[4..])
            .expect("Max payload must decrypt");
        assert_eq!(dec_data.len(), MAX_PAYLOAD_SIZE);
        assert_eq!(dec_data, max_payload);
    }

    #[test]
    fn test_http_upgrade_auth_and_probing() {
        let master_key = derive_master_key("http-probe-secret");
        let replay = ReplayFilter::new(60);

        // 1. Legitimate HTTP upgrade request
        let (req_bytes, session_id) =
            build_http_upgrade_request("/ws-endpoint", "my-cdn.com", &master_key);
        assert!(req_bytes.starts_with(b"GET /ws-endpoint HTTP/1.1\r\n"));

        let extracted =
            extract_http_auth(&req_bytes).expect("Must extract auth key from Sec-WebSocket-Key");
        assert_eq!(extracted, session_id);
        assert!(verify_auth_session_id(&master_key, &extracted, &replay));

        // Replay of the same HTTP upgrade must fail
        assert!(!verify_auth_session_id(&master_key, &extracted, &replay));

        // 2. Active probe simulation: standard Nginx/DPI scanner GET request
        let probe_req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_auth(probe_req), None);

        // 3. Probing with invalid hex key
        let fake_req = b"GET /novl HTTP/1.1\r\nSec-WebSocket-Key: not-valid-hex-token\r\n\r\n";
        assert_eq!(extract_http_auth(fake_req), None);
    }

    #[tokio::test]
    async fn test_read_decrypted_frame_stream() {
        let key = [0x33u8; 32];
        let mut enc = StreamCipher::new(&key);
        let mut dec = StreamCipher::new(&key);

        let (mut client, mut server) = tokio::io::duplex(65536);

        let messages: Vec<&[u8]> = vec![
            b"First small message",
            b"",
            b"A slightly longer message with randomized padding to break fingerprinting",
            &[0x42; 4096],
        ];

        // Send encrypted frames over the duplex stream
        for (i, msg) in messages.iter().enumerate() {
            let pad = (i * 17) as u16 % 200;
            let frame = enc.encrypt_frame(msg, pad).unwrap();
            client.write_all(&frame).await.unwrap();
        }
        drop(client);

        // Receive and decrypt frames sequentially
        for expected in &messages {
            let decrypted = read_decrypted_frame(&mut server, &mut dec).await.unwrap();
            assert_eq!(&decrypted, expected);
        }
    }

    #[tokio::test]
    async fn test_read_decrypted_frame_bounds_enforcement() {
        let key = [0x11u8; 32];
        let mut dec = StreamCipher::new(&key);

        // 1. Header claiming payload > MAX_PAYLOAD_SIZE
        let mut bad_header = [0u8; 4];
        let oversized = (MAX_PAYLOAD_SIZE + 1) as u16;
        BigEndian::write_u16(&mut bad_header[0..2], oversized);
        BigEndian::write_u16(&mut bad_header[2..4], 0);

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        writer.write_all(&bad_header).await.unwrap();

        let res = read_decrypted_frame(&mut reader, &mut dec).await;
        assert!(res.is_err(), "Must reject oversized payload header");

        // 2. Header claiming padding > 1024
        let mut bad_pad_header = [0u8; 4];
        BigEndian::write_u16(&mut bad_pad_header[0..2], 100);
        BigEndian::write_u16(&mut bad_pad_header[2..4], 1025);

        let (mut writer2, mut reader2) = tokio::io::duplex(1024);
        writer2.write_all(&bad_pad_header).await.unwrap();

        let res2 = read_decrypted_frame(&mut reader2, &mut dec).await;
        assert!(res2.is_err(), "Must reject oversized padding header");
    }
}
