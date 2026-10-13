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

// =============== Protocol v2: ECDH + server auth ===============

/// Protocol version carried inside the auth token MAC binding. The version byte
/// is hashed together with the transcript so a downgrade attempt (v2 client
/// hello replayed as v1) fails MAC verification without any explicit
/// negotiation round-trip.
pub const PROTOCOL_VERSION_V1: u8 = 1;
pub const PROTOCOL_VERSION_V2: u8 = 2;

pub const EPH_PUB_LEN: usize = 32;

pub struct CryptoKeys {
    pub client_enc_key: [u8; 32],
    pub server_enc_key: [u8; 32],
}

/// Ephemeral X25519 keypair generated per connection by the client.
pub struct ClientEphemeral {
    esk: x25519_dalek::EphemeralSecret,
    pub epk: [u8; 32],
}

pub fn generate_client_ephemeral() -> ClientEphemeral {
    let esk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let epk: [u8; 32] = x25519_dalek::PublicKey::from(&esk).to_bytes();
    ClientEphemeral { esk, epk }
}

impl ClientEphemeral {
    /// ECDH shared secret with the server's ephemeral public key.
    /// Consumes the ephemeral secret (single-use by design).
    pub fn diffie_hellman(self, server_epk: &[u8; 32]) -> Result<[u8; 32]> {
        let pk = x25519_dalek::PublicKey::from(*server_epk);
        let shared = self.esk.diffie_hellman(&pk);
        if !shared.was_contributory() {
            bail!("X25519 shared secret is not contributory (peer key rejected)");
        }
        Ok(shared.to_bytes())
    }
}

/// Computes the shared secret and derives the v2 transport keys.
/// Both peers must end up with identical keys or the session is torn down.
pub fn derive_v2_session_keys(
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    client_epk: &[u8; 32],
    server_epk: &[u8; 32],
    shared: &[u8; 32],
) -> Result<CryptoKeys> {
    let zero = [0u8; 32];
    if *shared == zero {
        bail!("X25519 all-zero shared secret (peer key rejected)");
    }

    let mut kdf = blake3::Hasher::new_derive_key("NOVL-v2-SESSION-KEYS");
    kdf.update(master_key);
    kdf.update(session_id);
    kdf.update(client_epk);
    kdf.update(server_epk);
    kdf.update(shared);
    let okm = *kdf.finalize().as_bytes();

    let mut c2s = blake3::Hasher::new_derive_key("NOVL-v2-C2S-SESSION-KEY");
    c2s.update(&okm);
    let client_enc_key = *c2s.finalize().as_bytes();

    let mut s2c = blake3::Hasher::new_derive_key("NOVL-v2-S2C-SESSION-KEY");
    s2c.update(&okm);
    let server_enc_key = *s2c.finalize().as_bytes();

    Ok(CryptoKeys {
        client_enc_key,
        server_enc_key,
    })
}

/// Server proof carried in the ServerHello random: first 16 bytes are a keyed
/// hash over the transcript, bound to a secret only the real server (PSK
/// holder) can compute. The client verifies it BEFORE sending any user data,
/// closing MitM and reflection vectors.
pub fn compute_server_proof(
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    client_epk: &[u8; 32],
    server_epk: &[u8; 32],
) -> [u8; 16] {
    let mut kdf = blake3::Hasher::new_derive_key("NOVL-v2-PROOF");
    kdf.update(master_key);
    kdf.update(session_id);
    kdf.update(client_epk);
    kdf.update(server_epk);
    let okm = kdf.finalize();
    let mut proof = [0u8; 16];
    proof.copy_from_slice(&okm.as_bytes()[0..16]);
    proof
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
    generate_auth_session_id_v2(master_key, None)
}

/// v1 token: MAC over (timestamp || salt) only. Used by 0.1.x peers.
pub fn generate_auth_session_id_v1(master_key: &[u8; 32]) -> [u8; 32] {
    let (data, _) = token_data();
    let mac = token_mac_v1(master_key, &data);
    assemble_token(&data, &mac)
}

/// v2 token: MAC over (version || timestamp || salt || optional client
/// ephemeral public key). Binding the ephemeral key into the token MAC makes a
/// downgraded/replayed hello fail verification before any cipher is engaged.
pub fn generate_auth_session_id_v2(
    master_key: &[u8; 32],
    client_epk: Option<&[u8; 32]>,
) -> [u8; 32] {
    let (data, version) = token_data();
    let mac = token_mac_v2(master_key, &data, version, client_epk);
    assemble_token(&data, &mac)
}

fn token_data() -> ([u8; 16], u8) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut salt = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut data = [0u8; 16];
    BigEndian::write_u64(&mut data[0..8], now);
    data[8..16].copy_from_slice(&salt);
    (data, PROTOCOL_VERSION_V2)
}

fn token_mac_v1(master_key: &[u8; 32], data: &[u8; 16]) -> [u8; 16] {
    let mut keyed_hasher = blake3::Hasher::new_keyed(master_key);
    keyed_hasher.update(data);
    let mac = keyed_hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.as_bytes()[0..16]);
    out
}

fn token_mac_v2(
    master_key: &[u8; 32],
    data: &[u8; 16],
    version: u8,
    client_epk: Option<&[u8; 32]>,
) -> [u8; 16] {
    let mut keyed_hasher = blake3::Hasher::new_keyed(master_key);
    keyed_hasher.update(&[version]);
    keyed_hasher.update(data);
    if let Some(epk) = client_epk {
        keyed_hasher.update(epk);
    }
    let mac = keyed_hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.as_bytes()[0..16]);
    out
}

fn assemble_token(data: &[u8; 16], mac: &[u8; 16]) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    session_id[0..16].copy_from_slice(data);
    session_id[16..32].copy_from_slice(mac);
    session_id
}

/// Outcome of token verification: which protocol version the peer speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVersion {
    V1,
    V2,
}

pub fn verify_auth_session_id(
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    replay_filter: &ReplayFilter,
) -> bool {
    verify_auth_session_id_versioned(master_key, session_id, replay_filter, None).is_some()
}

/// Verifies the token trying v2 first (with the extracted key share as
/// binding), then v1, and reports the negotiated version. Returns `None` when
/// neither version verifies (wrong PSK, stale token, tampered hello) — the
/// caller treats this as unauthenticated traffic.
pub fn verify_auth_session_id_versioned(
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    replay_filter: &ReplayFilter,
    client_epk: Option<&[u8; 32]>,
) -> Option<AuthVersion> {
    let ts = BigEndian::read_u64(&session_id[0..8]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check sliding window of +/- 90 seconds
    if ts.abs_diff(now) > 90 {
        return None;
    }

    let mut data = [0u8; 16];
    data.copy_from_slice(&session_id[0..16]);
    let actual = &session_id[16..32];

    // v2: MAC(version || data || client_epk?) — always attempted; the MAC
    // includes the epk when one is supplied, so a bound token verifies only
    // against its own hello.
    let v2_mac = token_mac_v2(master_key, &data, PROTOCOL_VERSION_V2, client_epk);
    if subtle_eq(&v2_mac, actual) {
        if replay_check(replay_filter, &data) {
            return Some(AuthVersion::V2);
        }
        return None;
    }

    // v1: MAC(data) — legacy 0.1.x clients always carry a key_share-looking
    // extension with random bytes, so their hello arrives with a non-None
    // client_epk too. A v1 token never carries an epk binding: the MAC is
    // computed without it. Verifying the bare v1 MAC here is safe — a v2-bound
    // token can never match it, and an attacker replaying a captured v1 token
    // is still stopped by the replay filter.
    let v1_mac = token_mac_v1(master_key, &data);
    if subtle_eq(&v1_mac, actual) && replay_check(replay_filter, &data) {
        return Some(AuthVersion::V1);
    }

    None
}

fn replay_check(replay_filter: &ReplayFilter, data: &[u8; 16]) -> bool {
    let mut token = [0u8; 16];
    token.copy_from_slice(data);
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
    build_chameleon_client_hello_v2(profile, master_key, sni, None)
}

/// v2 hello: the auth token MAC binds the client ephemeral X25519 public key
/// and the key_share extension carries that real key instead of random bytes,
/// enabling ECDH-based PFS and server authentication while staying
/// byte-compatible with a genuine Chrome ClientHello.
pub fn build_chameleon_client_hello_v2(
    profile: &TlsFingerprintProfile,
    master_key: &[u8; 32],
    sni: &str,
    client_epk: Option<&[u8; 32]>,
) -> Vec<u8> {
    let session_id = match client_epk {
        Some(epk) => generate_auth_session_id_v2(master_key, Some(epk)),
        None => generate_auth_session_id_v1(master_key),
    };
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

    // 11. Key Share (0x0033) - GREASE + x25519. In v2 this carries the real
    // ephemeral X25519 public key used for the session ECDH; externally it is
    // indistinguishable from a genuine Chrome key share.
    let mut client_key_share = [0u8; 32];
    match client_epk {
        Some(epk) => client_key_share.copy_from_slice(epk),
        None => rng.fill_bytes(&mut client_key_share),
    }
    // Genuine Chrome emits a GREASE entry shaped exactly like a real key share
    // entry: [grease_group u16][41 u16][43 random bytes]. Anything shorter is a
    // parser-visible anomaly.
    let mut grease_entry = Vec::with_capacity(4 + 41);
    grease_entry.extend_from_slice(&grease_group.to_be_bytes());
    grease_entry.extend_from_slice(&41u16.to_be_bytes());
    let mut grease_key = [0u8; 41];
    rng.fill_bytes(&mut grease_key);
    grease_entry.extend_from_slice(&grease_key);

    let mut x25519_entry = Vec::with_capacity(4 + 32);
    x25519_entry.extend_from_slice(&0x001du16.to_be_bytes());
    x25519_entry.extend_from_slice(&32u16.to_be_bytes());
    x25519_entry.extend_from_slice(&client_key_share);

    let mut shares = Vec::with_capacity(grease_entry.len() + x25519_entry.len());
    shares.extend_from_slice(&grease_entry);
    shares.extend_from_slice(&x25519_entry);

    // ext data = [client_shares_len u16][entries...] — single length wrapper,
    // matching a genuine Chrome key_share extension.
    let mut ks_ext = Vec::with_capacity(2 + shares.len());
    ks_ext.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    ks_ext.extend_from_slice(&shares);
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

/// Parses the 32-byte X25519 key share out of an incoming TLS ClientHello by
/// walking the extension list (robust against variable padding/SNI lengths).
pub fn extract_client_key_share(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() < 43 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }
    let hs_len = BigEndian::read_u24(&buf[6..9]) as usize;
    let end = (9 + hs_len).min(buf.len());
    let mut pos = 9 + 2 + 32; // version + random
    if pos >= end {
        return None;
    }
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len; // session id
    if pos + 2 > end {
        return None;
    }
    let cs_len = BigEndian::read_u16(&buf[pos..pos + 2]) as usize;
    pos += 2 + cs_len; // cipher suites vector
    if pos + 1 >= end {
        return None;
    }
    pos += 1 + buf[pos] as usize; // compression methods
    if pos + 2 > end {
        return None;
    }
    let ext_total = BigEndian::read_u16(&buf[pos..pos + 2]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(end);

    while pos + 4 <= ext_end {
        let etype = BigEndian::read_u16(&buf[pos..pos + 2]);
        let elen = BigEndian::read_u16(&buf[pos + 2..pos + 4]) as usize;
        let edata = pos + 4;
        if edata + elen > ext_end {
            return None;
        }
        if etype == 0x0033 && elen >= 2 {
            // client_share list: [list_len u16][entry: group u16][klen u16][key..];
            // the first entry may be GREASE, so walk until x25519(0x001d).
            let list_len = BigEndian::read_u16(&buf[edata..edata + 2]) as usize;
            let list_end = (edata + 2 + list_len).min(edata + elen);
            let mut off = edata + 2;
            while off + 4 <= list_end {
                let group = BigEndian::read_u16(&buf[off..off + 2]);
                let klen = BigEndian::read_u16(&buf[off + 2..off + 4]) as usize;
                if group == 0x001d && klen == 32 && off + 4 + 32 <= list_end {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&buf[off + 4..off + 4 + 32]);
                    return Some(out);
                }
                off += 4 + klen;
            }
            return None;
        }
        pos = edata + elen;
    }
    None
}

fn read_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

/// Parses a chameleon ServerHello and verifies the v2 server proof against the
/// transcript. Returns the server ephemeral X25519 public key on success.
pub fn parse_and_verify_server_hello(
    buf: &[u8],
    master_key: &[u8; 32],
    session_id: &[u8; 32],
    client_epk: &[u8; 32],
) -> Option<[u8; 32]> {
    // Record header (5) + handshake header (4) + version (2) + random (32)
    if buf.len() < 5 + 4 + 2 + 32 + 1 + 2 + 2 || buf[0] != 0x16 || buf[5] != 0x02 {
        return None;
    }
    let random = &buf[5 + 4 + 2..5 + 4 + 2 + 32];
    let proof = &random[0..16];
    let server_epk = extract_server_key_share(buf)?;

    let expected = compute_server_proof(master_key, session_id, client_epk, &server_epk);
    if !subtle_eq(proof, &expected) {
        return None;
    }
    Some(server_epk)
}

/// Extracts the x25519 key share from a ServerHello by walking its extensions.
pub fn extract_server_key_share(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() < 5 + 4 + 2 + 32 + 1 + 2 + 2 || buf[0] != 0x16 || buf[5] != 0x02 {
        return None;
    }
    let hs_len = read_u24(&buf[6..9]) as usize;
    let end = (9 + hs_len).min(buf.len());
    let mut pos = 9 + 2 + 32; // version + random
    if pos >= end {
        return None;
    }
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len; // session id
    pos += 2; // cipher suites
    if pos + 1 >= end {
        return None;
    }
    pos += 1 + buf[pos] as usize; // compression
    if pos + 2 > end {
        return None;
    }
    let ext_total = BigEndian::read_u16(&buf[pos..pos + 2]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(end);

    while pos + 4 <= ext_end {
        let etype = BigEndian::read_u16(&buf[pos..pos + 2]);
        let elen = BigEndian::read_u16(&buf[pos + 2..pos + 4]) as usize;
        let edata = pos + 4;
        if edata + elen > ext_end {
            return None;
        }
        if etype == 0x0033 && elen >= 36 {
            // server_share: group(2) + len(2) + key(32)
            let group = BigEndian::read_u16(&buf[edata..edata + 2]);
            let klen = BigEndian::read_u16(&buf[edata + 2..edata + 4]) as usize;
            if group == 0x001d && klen == 32 && elen >= 4 + klen {
                let mut out = [0u8; 32];
                out.copy_from_slice(&buf[edata + 4..edata + 4 + 32]);
                return Some(out);
            }
            return None;
        }
        pos = edata + elen;
    }
    None
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
    let mut epk = [0u8; 32];
    rng.fill_bytes(&mut epk);
    build_chameleon_server_hello_v2(None, None, None, &epk)
}

/// v2 ServerHello: the random field carries [proof(16) || server_ephemeral(16..48)]
/// where proof is a keyed hash over the transcript — the client verifies it
/// before sending data. Falls back to pure randomness for v1 sessions.
pub fn build_chameleon_server_hello_v2(
    master_key: Option<&[u8; 32]>,
    session_id: Option<&[u8; 32]>,
    client_epk: Option<&[u8; 32]>,
    server_epk: &[u8; 32],
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut server_random = [0u8; 32];
    rng.fill_bytes(&mut server_random);

    if let (Some(mk), Some(sid), Some(cepks)) = (master_key, session_id, client_epk) {
        let proof = compute_server_proof(mk, sid, cepks, server_epk);
        server_random[0..16].copy_from_slice(&proof);
    }

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

    // Key Share ext (x25519) — real ephemeral public key (v2) or random (v1)
    let server_key_share: [u8; 32] = *server_epk;
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

// =============== v2 TLS-record wire codec ===============
//
// v1 frames are [len u16][pad u16][ct] — an instantly recognizable
// "fully encrypted" signature after the hello. v2 wraps each frame into a
// realistic TLS application-data record (0x17 0x03 0x03, length <= 16KB) and
// pads the payload to a 64-byte multiple so wire sizes leak less about the
// inner traffic (DNS packets etc.).

pub const TLS_REC_HEADER_LEN: usize = 5;
pub const TLS_REC_MAX: usize = 16384 + 256; // max record we may emit
pub const PAD_TO_MULTIPLE: usize = 64;

/// Encrypts a payload and wraps it into a TLS application-data record.
/// v2 header: [0x17,0x03,0x03][len u16][inner_len u16][pad u16][ct...]
pub fn encrypt_tls_frame(
    encryptor: &mut StreamCipher,
    payload: &[u8],
    force_pad: Option<u16>,
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        bail!("Payload exceeds maximum allowed frame size");
    }
    // Pad to 64-byte multiple (plus random extra up to 192) unless forced.
    let pad = match force_pad {
        Some(p) => p.min(MAX_PADDING_SIZE),
        None => {
            let padded_len = payload.len().div_ceil(PAD_TO_MULTIPLE) * PAD_TO_MULTIPLE;
            let base = padded_len - payload.len();
            let extra = rand::thread_rng().gen_range(0..4) * PAD_TO_MULTIPLE;
            (base + extra) as u16
        }
    };

    let frame = encryptor.encrypt_frame(payload, pad)?;
    // frame = [inner_len u16][pad u16][ct]
    let mut rec = Vec::with_capacity(TLS_REC_HEADER_LEN + frame.len());
    rec.extend_from_slice(&[0x17, 0x03, 0x03]);
    rec.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    rec.extend_from_slice(&frame);
    Ok(rec)
}

/// Reads one TLS record, validates the v2 header, decrypts the inner frame.
pub async fn read_tls_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    decryptor: &mut StreamCipher,
) -> Result<Vec<u8>> {
    let mut header = [0u8; TLS_REC_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    if header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 {
        bail!("unexpected record type in v2 stream: {:02x}", header[0]);
    }
    let rec_len = BigEndian::read_u16(&header[3..5]) as usize;
    if rec_len < 4 + TAG_LEN || rec_len > TLS_REC_MAX {
        bail!("record length out of bounds: {}", rec_len);
    }
    let mut rec = vec![0u8; rec_len];
    reader.read_exact(&mut rec).await?;

    let inner_len = BigEndian::read_u16(&rec[0..2]) as usize;
    let pad_len = BigEndian::read_u16(&rec[2..4]) as usize;
    if inner_len > MAX_PAYLOAD_SIZE || pad_len > MAX_PADDING_SIZE as usize {
        bail!("frame length fields exceed maximum bounds");
    }
    decryptor.decrypt_frame(
        inner_len as u16,
        pad_len as u16,
        &rec[4..],
    )
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

/// Hex decode helper.
///
/// Parses the input byte-by-byte as ASCII hex, so it never slices a multi-byte
/// UTF-8 character (which would panic) and works on any input, including
/// strings with arbitrary Unicode content.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let input = s.as_bytes();
    if input.len() % 2 != 0 {
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
    let mut i = 0;
    while i < input.len() {
        let hi = hex_val(input[i])?;
        let lo = hex_val(input[i + 1])?;
        bytes.push((hi << 4) | lo);
        i += 2;
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

    // =============== v2 protocol tests ===============

    #[test]
    fn v2_ecdh_key_agreement_roundtrip() {
        let mk = derive_master_key("e2e-secret");
        let sid = generate_auth_session_id_v2(&mk, None);

        let client = generate_client_ephemeral();
        let client_epk = client.epk;
        let mut server_esk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_esk_bytes);
        let server_esk = x25519_dalek::StaticSecret::from(server_esk_bytes);
        let server_epk = x25519_dalek::PublicKey::from(&server_esk).to_bytes();

        let shared_c = client.diffie_hellman(&server_epk).unwrap();
        let shared_s = server_esk
            .diffie_hellman(&x25519_dalek::PublicKey::from(client_epk))
            .to_bytes();

        let kc =
            derive_v2_session_keys(&mk, &sid, &client_epk, &server_epk, &shared_c).unwrap();
        let ks = derive_v2_session_keys(&mk, &sid, &client_epk, &server_epk, &shared_s).unwrap();
        assert_eq!(kc.client_enc_key, ks.client_enc_key);
        assert_eq!(kc.server_enc_key, ks.server_enc_key);
    }

    #[test]
    fn v2_server_proof_verifies_and_rejects() {
        let mk = derive_master_key("proof-secret");
        let sid = generate_auth_session_id_v2(&mk, None);
        let client = generate_client_ephemeral();
        let mut server_epk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_epk);

        let hello = build_chameleon_server_hello_v2(Some(&mk), Some(&sid), Some(&client.epk), &server_epk);
        let parsed = parse_and_verify_server_hello(&hello, &mk, &sid, &client.epk);
        assert_eq!(parsed, Some(server_epk));

        // Wrong client key (MitM substitution) must fail.
        let other = generate_client_ephemeral();
        assert_eq!(parse_and_verify_server_hello(&hello, &mk, &sid, &other.epk), None);

        // Plain v1 hello (random proof) must fail.
        let v1_hello = build_chameleon_server_hello();
        assert_eq!(parse_and_verify_server_hello(&v1_hello, &mk, &sid, &client.epk), None);
    }

    #[test]
    fn v2_token_rejects_downgrade_and_v1_backcompat() {
        let mk = derive_master_key("downgrade-secret");
        let filter = ReplayFilter::new(120);

        // v2 token with epk binding: verifying without epk must fail on both versions.
        let client = generate_client_ephemeral();
        let sid = generate_auth_session_id_v2(&mk, Some(&client.epk));
        assert_eq!(verify_auth_session_id_versioned(&mk, &sid, &filter, None), None);
        assert_eq!(
            verify_auth_session_id_versioned(&mk, &sid, &filter, Some(&client.epk)),
            Some(AuthVersion::V2)
        );

        // v1 token still verifies as v1 (server accepts old 0.1.x clients).
        let sid_v1 = generate_auth_session_id_v1(&mk);
        assert_eq!(
            verify_auth_session_id_versioned(&mk, &sid_v1, &filter, None),
            Some(AuthVersion::V1)
        );
        // A v1 token verifies even when a key share was extracted (legacy
        // clients always carry one); it still cannot impersonate v2.
        // Fresh filter: tokens are single-use by design.
        let filter2 = ReplayFilter::new(120);
        assert_eq!(
            verify_auth_session_id_versioned(&mk, &sid_v1, &filter2, Some(&client.epk)),
            Some(AuthVersion::V1)
        );
        let filter3 = ReplayFilter::new(120);
        assert_ne!(
            verify_auth_session_id_versioned(&mk, &sid, &filter3, Some(&client.epk)),
            Some(AuthVersion::V1)
        );
    }

    #[tokio::test]
    async fn v2_bidirectional_streams_independent_nonces() {
        // c2s and s2c directions use different keys; interleaved frames must
        // decrypt with the matching per-direction cipher only.
        let keys = CryptoKeys {
            client_enc_key: derive_master_key("c2s-key"),
            server_enc_key: derive_master_key("s2c-key"),
        };
        let mut c_enc = StreamCipher::new(&keys.client_enc_key);
        let mut s_dec = StreamCipher::new(&keys.client_enc_key);
        let mut s_enc = StreamCipher::new(&keys.server_enc_key);
        let mut c_dec = StreamCipher::new(&keys.server_enc_key);

        let up = b"client->server payload";
        let down = b"server->client response";
        let mut up_wire = encrypt_tls_frame(&mut c_enc, up, None).unwrap();
        let down_wire = encrypt_tls_frame(&mut s_enc, down, None).unwrap();
        up_wire.extend_from_slice(&down_wire);

        let mut cur = std::io::Cursor::new(up_wire);
        let got_up = read_tls_frame(&mut cur, &mut s_dec).await.unwrap();
        let got_down = read_tls_frame(&mut cur, &mut c_dec).await.unwrap();
        assert_eq!(got_up, up);
        assert_eq!(got_down, down);
    }

    #[tokio::test]
    async fn v2_tls_frame_roundtrip_and_padding() {
        let keys = CryptoKeys {
            client_enc_key: derive_master_key("frame-k1"),
            server_enc_key: derive_master_key("frame-k2"),
        };
        let mut enc = StreamCipher::new(&keys.client_enc_key);
        // Same-direction frames share the same key on both peers (client->server).
        let mut dec = StreamCipher::new(&keys.client_enc_key);

        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let wire = encrypt_tls_frame(&mut enc, &payload, None).unwrap();

        // TLS application-data record header
        assert_eq!(&wire[0..3], &[0x17, 0x03, 0x03]);
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert_eq!(wire.len(), 5 + rec_len);

        // (1000 bytes + pad) + 4 header + 16 tag must be padded to 64-multiple
        let ct_len = rec_len - 4;
        let raw_len = ct_len - 16; // payload + pad
        assert_eq!(raw_len % 64, 0, "payload+padding must be 64-aligned");

        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = read_tls_frame(&mut cursor, &mut dec).await.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn v2_client_hello_carries_real_key_share() {
        let mk = derive_master_key("hello-secret");
        let client = generate_client_ephemeral();
        let hello = build_chameleon_client_hello_v2(
            &chrome_124_profile(),
            &mk,
            "example.com",
            Some(&client.epk),
        );
        assert_eq!(extract_client_key_share(&hello), Some(client.epk));

        // Token must bind this epk: verification with the same epk succeeds.
        let sid = extract_session_id(&hello).unwrap();
        let filter = ReplayFilter::new(120);
        assert_eq!(
            verify_auth_session_id_versioned(&mk, &sid, &filter, Some(&client.epk)),
            Some(AuthVersion::V2)
        );
    }
}
