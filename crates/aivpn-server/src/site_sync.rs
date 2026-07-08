//! Site-to-site VPN — connects two or more AIVPN servers so end-hosts on each
//! site can reach each other without any VPN client software.
//!
//! ## How it works
//! Each peer uses the same crypto infrastructure as pool sync: per-link
//! `sync_key` plus DIRECTIONAL sub-keys (roles assigned by lexicographic
//! order of the two site names — the smaller name sends with the pair's c2s
//! sub-key, the larger with s2c — so the two directions never share an AEAD
//! key).  `local_name` is REQUIRED for sending: with counter-derived nonces a
//! shared symmetric key in both directions would collide in the same
//! (key, nonce) space, so the legacy symmetric fallback only registers the
//! receive session and never transmits.  Peers exchange subnet advertisements
//! via `ControlPayload::RouteSync` (0x13) and the gateway installs kernel
//! routes when it receives them.
//!
//! ## Counter / nonce model (must mirror `pool_sync.rs` and the gateway)
//! The receiving gateway recovers the send counter from the resonance tag
//! (`Session::validate_tag`) and rebuilds the AEAD nonce deterministically as
//! `nonce[..8] = counter.to_le_bytes()` (`Gateway::compute_nonce`).  The
//! synthetic receive session (`SessionManager::create_site_peer_session`)
//! centers its expected-tag window on `unix_ms / 5_000`.  The sender therefore
//! MUST (a) seed and clamp its send counter to the same 5-second wall-clock
//! bucket so its tags land inside the receiver's window, and (b) build the
//! nonce from that exact counter — a random nonce can never be reconstructed
//! by the receiver and every packet would fail AEAD authentication.
//!
//! Because the per-link send key is static across restarts (derived from the
//! long-lived `sync_key`), the send counter's high-water mark is persisted to
//! disk (like `pool_sync_counter.state`) so a fast restart inside the same
//! 5-second bucket can never reuse a (key, nonce) pair.
//!
//! ## server.json
//! ```json
//! {
//!   "site_to_site": {
//!     "local_subnets": ["192.168.1.0/24"],
//!     "peers": [
//!       {
//!         "name": "office-b",
//!         "endpoint": "office-b.example.com:443",
//!         "sync_key": "<base64 32-byte key>",
//!         "remote_subnets": ["192.168.2.0/24"]
//!       }
//!     ]
//!   }
//! }
//! ```

use portable_atomic::{AtomicBool, AtomicU64};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{atomic::Ordering, Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{info, warn};

/// Caps to bound deserialization and subprocess spawning.
const MAX_SUBNETS_JSON_BYTES: usize = 4096;
const MAX_SUBNETS_PER_MSG: usize = 64;

/// Stored once at startup so `handle_route_sync` can authenticate senders.
static SITE_CONFIG: OnceLock<SiteToSiteConfig> = OnceLock::new();

use aivpn_common::crypto::{
    self, encrypt_payload, SessionKeys, DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};

use crate::session::SessionManager;

const ROUTE_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Resonance-counter time bucket in milliseconds.  MUST equal the `5_000`
/// used by `SessionManager::create_site_peer_session` /
/// `create_pool_peer_session` / `refresh_pool_peer_tags` and by
/// `pool_sync.rs` — sender and receiver only agree on expected tags because
/// both compute `unix_ms / 5_000`.
pub(crate) const COUNTER_BUCKET_MS: u64 = 5_000;

/// Default directory for send-counter high-water state files (the server
/// already keeps its mask store under `/var/lib/aivpn`).  Persistence is
/// best-effort: on failure a warning is logged and protection degrades to
/// the time-bucket floor (safe except for a restart inside the same
/// 5-second bucket).
pub(crate) const DEFAULT_STATE_DIR: &str = "/var/lib/aivpn";

// ---------------------------------------------------------------------------
// Send-counter helpers — shared with `chain_forwarder.rs`.
// Semantics mirror `pool_sync.rs` (`read_counter_file` / `write_counter_file`
// / seed at `max(persisted + 1, wall_clock_bucket)` / durably bump the floor
// BEFORE a counter value is used as an AEAD nonce).
// ---------------------------------------------------------------------------

/// Read the persisted send-counter high-water mark (same format as
/// `pool_sync::read_counter_file`).
pub(crate) fn read_counter_file(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Durably persist `counter` via write-then-rename (same crash-safety scheme
/// as `pool_sync::write_counter_file`).
pub(crate) fn write_counter_file(path: &Path, counter: u64) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp_path, counter.to_string())?;
    std::fs::rename(&tmp_path, path)
}

/// Seed a send counter exactly like `PeerSyncer::new`:
/// `max(persisted_high_water + 1, current 5-second wall-clock bucket)`,
/// persisting the seed immediately so even a crash before the first send
/// leaves the floor in place.
pub(crate) fn seed_send_counter(state_path: &Path, label: &str) -> u64 {
    let wall_clock_bucket = crypto::current_timestamp_ms() / COUNTER_BUCKET_MS;
    let resume_from = read_counter_file(state_path)
        .map(|c| c.saturating_add(1))
        .unwrap_or(0);
    let start_counter = resume_from.max(wall_clock_bucket);
    if let Err(e) = write_counter_file(state_path, start_counter) {
        warn!(
            "{}: failed to persist initial send counter to {} \
             (restart nonce-reuse protection degraded): {}",
            label,
            state_path.display(),
            e
        );
    }
    start_counter
}

/// Take the next send-counter value: strictly monotonic AND clamped up to the
/// current 5-second wall-clock bucket.
///
/// `pool_sync` can use a plain `fetch_add(1)` because it sends exactly one
/// packet per 5-second interval, so its counter tracks the wall clock on its
/// own.  Site sync sends every 30 s (counter would fall 5 buckets behind per
/// interval and drift out of a freshly restarted receiver's ±255 window
/// within ~25 minutes) and chain forwarding is bursty (idle gaps).  Clamping
/// to `max(previous + 1, bucket)` keeps the counter aligned with the
/// receiver's wall-clock-centred window after any idle period while never
/// repeating a value within a run.
pub(crate) fn next_send_counter(counter: &AtomicU64) -> u64 {
    let bucket = crypto::current_timestamp_ms() / COUNTER_BUCKET_MS;
    let prev = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |stored| {
            Some(stored.max(bucket).saturating_add(1))
        })
        .expect("fetch_update closure never returns None");
    prev.max(bucket)
}

/// Ensure the on-disk high-water mark strictly exceeds `used_counter`
/// (mirrors `PeerSyncer::persist_counter_floor`).  `stride` amortises disk
/// writes for high-rate senders: when a write is needed, the floor is bumped
/// to `used_counter + stride`, covering the next `stride - 1` sends without
/// touching the disk.  The floor is only ever ABOVE counters already used,
/// so a restart resuming at `floor + 1` can never reuse a (key, nonce) pair.
pub(crate) fn persist_counter_floor(
    state_path: &Path,
    high_water: &Mutex<u64>,
    used_counter: u64,
    stride: u64,
    warned: &AtomicBool,
    label: &str,
) {
    let mut hw = high_water.lock();
    if *hw > used_counter {
        return; // Already durably covered.
    }
    let new_floor = used_counter.saturating_add(stride.max(1));
    match write_counter_file(state_path, new_floor) {
        Ok(()) => {
            *hw = new_floor;
            warned.store(false, Ordering::Relaxed);
        }
        Err(e) => {
            // Warn once per failure streak — chain forwarding calls this on
            // the data path and must not spam the log at line rate.
            if !warned.swap(true, Ordering::Relaxed) {
                warn!(
                    "{}: failed to persist send counter high-water mark to {}: {}",
                    label,
                    state_path.display(),
                    e
                );
            }
        }
    }
}

/// State-file name for one site peer link, with the peer name sanitised so it
/// is always a single safe path component.
fn site_counter_state_path(state_dir: &Path, peer_name: &str) -> PathBuf {
    let sanitized: String = peer_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    state_dir.join(format!("site_sync_counter_{}.state", sanitized))
}

/// Configuration for one site-to-site peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitePeerConfig {
    pub name: String,
    /// VPN endpoint `host:port` — must be the same port the VPN listens on.
    pub endpoint: String,
    /// 32-byte BLAKE3 key (base64).  Must match the peer's config exactly.
    pub sync_key: String,
    /// Subnets the remote site will advertise; pre-installed at startup.
    #[serde(default)]
    pub remote_subnets: Vec<String>,
}

/// Top-level site-to-site block (`"site_to_site"` in `server.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiteToSiteConfig {
    /// Identifier of THIS site — must be exactly the `name` the remote peers
    /// use for this node in their own `peers` lists.  Enables directional
    /// AEAD keys per link: roles are assigned by lexicographic order of the
    /// two names (smaller name sends with the pair's c2s sub-key, larger
    /// with s2c), so the two directions never share a (key, nonce) space.
    /// Both ends of a link must be updated and configured together.  When
    /// absent, the legacy single symmetric key is used (with a warning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    /// Local subnets advertised to all peers.
    #[serde(default)]
    pub local_subnets: Vec<String>,
    #[serde(default)]
    pub peers: Vec<SitePeerConfig>,
}

/// Compute the (send_root, recv_root) key material for the link with
/// `peer_name`.  With a configured `local_name` the roots are directional
/// (derived via `crypto::derive_directional_peer_keys`, roles assigned by
/// lexicographic name order); without one, both roots fall back to the raw
/// shared `sync_key` (legacy symmetric mode).  Colliding names return `None`
/// — the link must be REFUSED, not silently degraded to a key both directions
/// share (counter-derived AEAD nonces on one key = (key, nonce) reuse).
fn directional_roots(
    raw_sync_key: &[u8; 32],
    local_name: Option<&str>,
    peer_name: &str,
) -> Option<([u8; 32], [u8; 32])> {
    match local_name {
        Some(local) => match crypto::derive_directional_peer_keys(raw_sync_key, local, peer_name) {
            Ok(roots) => Some(roots),
            Err(e) => {
                warn!(
                    "site_sync: peer '{}' — directional keys unavailable, link disabled: {}",
                    peer_name, e
                );
                None
            }
        },
        None => Some((*raw_sync_key, *raw_sync_key)),
    }
}

/// Derive the wire `SessionKeys` from a (directional) root key.  Must stay
/// identical to the derivation in `SessionManager::create_site_peer_session`.
fn site_session_keys(root: &[u8; 32]) -> SessionKeys {
    SessionKeys {
        session_key: blake3::derive_key("aivpn-pool-enc-v1", root),
        session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", root),
        tag_secret: blake3::derive_key("aivpn-pool-tag-v1", root),
        prng_seed: blake3::derive_key("aivpn-pool-prng-v1", root),
    }
}

struct SitePeer {
    cfg: SitePeerConfig,
    local_subnets: Vec<String>,
    session_keys: SessionKeys,
    /// Send counter — doubles as the AEAD nonce (`nonce[..8] = counter`) and
    /// as the resonance-tag counter, exactly like `pool_sync.rs`.  Seeded via
    /// `seed_send_counter` (max of persisted high-water + 1 and the current
    /// 5-second wall-clock bucket — NEVER 0: the receiver's tag window is
    /// centred on `unix_ms / 5_000`, so counters near 0 would be dropped at
    /// tag lookup before decryption is even attempted).
    send_counter: AtomicU64,
    /// On-disk high-water file guaranteeing restart nonce-uniqueness under
    /// the static per-link send key.
    counter_state_path: PathBuf,
    /// Last value durably written to `counter_state_path`.
    persisted_high_water: Mutex<u64>,
    /// Set while persistence is failing, to avoid repeated warnings.
    persist_warned: AtomicBool,
}

impl SitePeer {
    fn new(
        cfg: SitePeerConfig,
        local_subnets: Vec<String>,
        local_name: Option<&str>,
        state_dir: &Path,
    ) -> Option<Arc<Self>> {
        let raw: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&cfg.sync_key)
            .ok()
            .and_then(|b| b.try_into().ok())?;

        if raw == [0u8; 32] {
            warn!("site_sync: peer {} has zero sync_key — skipped", cfg.name);
            return None;
        }

        // Directional keys are REQUIRED for sending: the AEAD nonce is now
        // derived from the wall-clock-seeded counter, so if both directions
        // of a link shared one symmetric key (legacy mode) the two ends —
        // whose counters both sit near the same time bucket — would collide
        // in the same (key, nonce) space.  With random nonces this fallback
        // was merely undecryptable; with counter nonces it would be unsafe.
        let local = match local_name {
            Some(l) if l != cfg.name => l,
            _ => {
                warn!(
                    "site_sync: peer '{}' — outbound RouteSync disabled: directional \
                     keys require site_to_site.local_name to be set and distinct from \
                     the peer name (legacy symmetric mode cannot use counter-derived \
                     AEAD nonces safely)",
                    cfg.name
                );
                return None;
            }
        };

        // Encrypt outbound traffic with the SEND-direction root of this link;
        // the peer registers its receive session from the same root. `None`
        // (colliding names) fails closed: the link stays down.
        let (send_root, _recv_root) = directional_roots(&raw, Some(local), &cfg.name)?;
        let session_keys = site_session_keys(&send_root);

        // Seed the counter at max(persisted + 1, current 5-second bucket) so
        // (a) tags land inside the receiver's wall-clock-centred window and
        // (b) no counter/nonce value from a previous run is ever reused
        // under the static link key.
        let counter_state_path = site_counter_state_path(state_dir, &cfg.name);
        let start_counter = seed_send_counter(&counter_state_path, "site_sync");
        let send_counter = AtomicU64::new(start_counter);
        let persisted_high_water = Mutex::new(start_counter);

        Some(Arc::new(Self {
            cfg,
            local_subnets,
            session_keys,
            send_counter,
            counter_state_path,
            persisted_high_water,
            persist_warned: AtomicBool::new(false),
        }))
    }

    fn start(self: Arc<Self>) {
        // Pre-install statically-declared remote routes.
        for subnet in &self.cfg.remote_subnets {
            install_route(subnet, &self.cfg.endpoint);
        }
        tokio::spawn(async move { self.outbound_loop().await });
    }

    async fn outbound_loop(self: Arc<Self>) {
        let peer_addr: SocketAddr = match self.cfg.endpoint.parse() {
            Ok(a) => a,
            Err(_) => {
                warn!("site_sync: invalid endpoint: {}", self.cfg.endpoint);
                return;
            }
        };

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("site_sync: bind failed for {}: {}", self.cfg.name, e);
                return;
            }
        };

        info!(
            "site_sync: peer {} → {} ({} local subnets)",
            self.cfg.name,
            self.cfg.endpoint,
            self.local_subnets.len()
        );

        let mut ticker = tokio::time::interval(ROUTE_SYNC_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(e) = self.send_advert(&socket, peer_addr).await {
                warn!("site_sync: send to {} failed: {}", self.cfg.name, e);
            }
        }
    }

    async fn send_advert(&self, socket: &UdpSocket, peer: SocketAddr) -> Result<()> {
        let subnets_json = serde_json::to_vec(&self.local_subnets)
            .map_err(|e| Error::Session(format!("site_sync serialize: {}", e)))?;
        let pkt = self.build_packet(&ControlPayload::RouteSync { subnets_json })?;
        socket
            .send_to(&pkt, peer)
            .await
            .map_err(|e| Error::Session(format!("site_sync udp: {}", e)))?;
        Ok(())
    }

    fn build_packet(&self, payload: &ControlPayload) -> Result<Vec<u8>> {
        let encoded = payload.encode()?;
        let mut inner = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        }
        .encode()
        .to_vec();
        inner.extend_from_slice(&encoded);

        // Strictly monotonic, wall-clock-clamped counter.  It is BOTH the
        // resonance-tag counter and the AEAD nonce: the receiving gateway
        // recovers it from the tag (`validate_tag`) and rebuilds this exact
        // nonce via `compute_nonce(counter)` — a random nonce here would make
        // every packet fail Poly1305 authentication on the peer.
        let counter = next_send_counter(&self.send_counter);

        // Durably bump the on-disk floor BEFORE the counter is used as a
        // nonce (stride 1 — route adverts go out once per 30 s, so a write
        // per packet is negligible, matching pool_sync's per-packet persist).
        persist_counter_floor(
            &self.counter_state_path,
            &self.persisted_high_water,
            counter,
            1,
            &self.persist_warned,
            "site_sync",
        );

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());

        let pad_len: u16 = 16;
        let mut padded = Vec::with_capacity(2 + inner.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner);
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        let ciphertext = encrypt_payload(&self.session_keys.session_key, &nonce, &padded)?;
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = crypto::generate_resonance_tag(&self.session_keys.tag_secret, counter, tw);

        // Fixed, mask-independent cluster framing — the receiving gateway
        // decodes `is_site_peer` sessions with exactly this layout (see
        // `pool_sync::CLUSTER_MDH_LEN`).
        let mdh = crate::pool_sync::cluster_mdh_bytes();
        let mut pkt = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        pkt.extend_from_slice(&tag);
        pkt.extend_from_slice(&mdh);
        pkt.extend_from_slice(&ciphertext);
        Ok(pkt)
    }
}

/// Start outbound route advertisement to all configured peers.
///
/// `session_manager` is used to register a synthetic session per peer so that
/// inbound `RouteSync` packets (encrypted with the peer's `sync_key`) are
/// authenticated by the normal tag-lookup path and reach `handle_route_sync`
/// with `session.is_site_peer = true`.
pub fn start(config: &SiteToSiteConfig, session_manager: Arc<SessionManager>) {
    // Store config so handle_route_sync can verify subnets and allowlists.
    SITE_CONFIG.get_or_init(|| config.clone());

    let local_name = config
        .local_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if local_name.is_none() {
        warn!(
            "site_sync: site_to_site.local_name not configured — outbound RouteSync is \
             DISABLED (counter-derived AEAD nonces require directional keys; a legacy \
             shared symmetric key would collide in the same (key, nonce) space). \
             Set local_name on both ends (must equal the `name` the peer uses for this \
             node). Inbound sessions are still registered with the legacy key."
        );
    }

    for peer_cfg in &config.peers {
        if local_name == Some(peer_cfg.name.as_str()) {
            warn!(
                "site_sync: peer '{}' has the same name as this node's local_name — \
                 directional roles need distinct names; outbound RouteSync to this \
                 peer is disabled",
                peer_cfg.name
            );
        }

        // Register a synthetic session so the gateway can decrypt inbound RouteSync.
        let raw_key: Option<[u8; 32]> = base64::engine::general_purpose::STANDARD
            .decode(&peer_cfg.sync_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .filter(|k: &[u8; 32]| k != &[0u8; 32]);

        if let Some(raw) = raw_key {
            // Use a placeholder addr; actual source is matched by tag on receipt.
            // The session is keyed by the RECEIVE-direction root of the link —
            // exactly what the peer encrypts with when sending to us. A name
            // collision yields no roots (fail closed): no session, no link.
            if let Some((_send_root, recv_root)) =
                directional_roots(&raw, local_name, &peer_cfg.name)
            {
                let sentinel: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
                session_manager.create_site_peer_session(&recv_root, sentinel, &peer_cfg.name);
            }
        } else {
            warn!(
                "site_sync: peer '{}' has missing or zero sync_key — session not registered",
                peer_cfg.name
            );
        }

        if let Some(peer) = SitePeer::new(
            peer_cfg.clone(),
            config.local_subnets.clone(),
            local_name,
            Path::new(DEFAULT_STATE_DIR),
        ) {
            peer.start();
        }
    }
    info!(
        "site_sync: active ({} peers, {} local subnets)",
        config.peers.len(),
        config.local_subnets.len()
    );
}

/// Handle an incoming `RouteSync` control message.
///
/// `from_addr` must be the full `IP:port` string of the sending socket so we
/// can match it against configured peer endpoints.  Any of these conditions
/// causes a silent drop with a warning:
/// - No site-to-site config loaded
/// - Sender not in the configured peers list
/// - Payload exceeds 4 KiB
/// - More than 64 subnets in one message
/// - A subnet that is not in the peer's declared `remote_subnets` allowlist
/// - A subnet that is a default route, loopback, or link-local prefix
pub fn handle_route_sync(subnets_json: &[u8], from_addr: &str) {
    // 1. Authenticate: sender must be a configured peer endpoint.
    let config = match SITE_CONFIG.get() {
        Some(c) => c,
        None => {
            warn!("site_sync: RouteSync received but site-to-site not configured — dropping");
            return;
        }
    };
    // Match by IP only — the sending peer's outbound socket uses an ephemeral source port,
    // so the received source port will not match the configured endpoint port.
    let from_socket: std::net::SocketAddr = match from_addr.parse() {
        Ok(a) => a,
        Err(_) => {
            warn!(
                "site_sync: unparseable sender address {} — dropping",
                from_addr
            );
            return;
        }
    };
    let peer_cfg = match config.peers.iter().find(|p| {
        p.endpoint
            .parse::<std::net::SocketAddr>()
            .map_or(false, |ep| ep.ip() == from_socket.ip())
    }) {
        Some(p) => p,
        None => {
            warn!(
                "site_sync: RouteSync from unconfigured peer {} — dropping",
                from_addr
            );
            return;
        }
    };

    // 2. Size guard before deserialization.
    if subnets_json.len() > MAX_SUBNETS_JSON_BYTES {
        warn!(
            "site_sync: RouteSync payload too large ({} bytes) from {} — dropping",
            subnets_json.len(),
            peer_cfg.name
        );
        return;
    }

    let subnets: Vec<String> = match serde_json::from_slice(subnets_json) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "site_sync: invalid RouteSync payload from {}: {}",
                peer_cfg.name, e
            );
            return;
        }
    };

    if subnets.len() > MAX_SUBNETS_PER_MSG {
        warn!(
            "site_sync: RouteSync has {} subnets (max {}) from {} — dropping",
            subnets.len(),
            MAX_SUBNETS_PER_MSG,
            peer_cfg.name
        );
        return;
    }

    for subnet_str in &subnets {
        // 3. Allowlist: only install routes the peer is declared to advertise.
        if !peer_cfg.remote_subnets.iter().any(|a| a == subnet_str) {
            warn!(
                "site_sync: subnet {} not in allowlist for peer {} — skipped",
                subnet_str, peer_cfg.name
            );
            continue;
        }
        // 4. Safety: reject dangerous prefixes.
        if !is_safe_subnet(subnet_str) {
            warn!(
                "site_sync: unsafe subnet {} from peer {} — skipped",
                subnet_str, peer_cfg.name
            );
            continue;
        }
        info!(
            "site_sync: installing route {} (peer: {})",
            subnet_str, peer_cfg.name
        );
        install_route(subnet_str, from_addr);
    }
}

/// Reject default routes, loopback, and link-local prefixes.
fn is_safe_subnet(s: &str) -> bool {
    let (addr_str, prefix_len) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().unwrap_or(0)),
        None => return false,
    };
    if prefix_len == 0 {
        return false; // 0.0.0.0/0 or ::/0 — default route
    }
    let addr = match IpAddr::from_str(addr_str) {
        Ok(a) => a,
        Err(_) => return false,
    };
    if addr.is_loopback() {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => {
            // Reject overly broad prefixes that could hijack major internet blocks or
            // overlap the server's own VPN subnet range.
            if prefix_len < 8 {
                return false;
            }
            !v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            if prefix_len < 16 {
                return false;
            }
            (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::crypto::decrypt_payload;

    fn test_sync_key_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    fn test_peer_cfg(name: &str) -> SitePeerConfig {
        SitePeerConfig {
            name: name.to_string(),
            endpoint: "127.0.0.1:443".to_string(),
            sync_key: test_sync_key_b64(),
            remote_subnets: vec!["192.168.2.0/24".to_string()],
        }
    }

    /// Build the SitePeer for the side named `local` talking to `peer`, with
    /// its counter state in a private tempdir.
    fn make_peer(local: &str, peer: &str) -> (tempfile::TempDir, Arc<SitePeer>) {
        let dir = tempfile::tempdir().unwrap();
        let sp = SitePeer::new(
            test_peer_cfg(peer),
            vec!["192.168.1.0/24".to_string()],
            Some(local),
            dir.path(),
        )
        .unwrap();
        (dir, sp)
    }

    /// End-to-end receiver round-trip — the exact double bug this module was
    /// broken by: (1) the AEAD nonce must be reconstructible from the counter
    /// recovered via the resonance tag (it used to be random), and (2) the
    /// counter must sit at the receiver's wall-clock bucket (it used to start
    /// at 0, outside the tag window).  Site A builds a RouteSync packet; the
    /// "receiver" (site B) rebuilds the nonce from the counter exactly like
    /// `Gateway::compute_nonce` and decrypts with the RECV-direction keys its
    /// `create_site_peer_session` registration derives.
    #[test]
    fn route_sync_packet_round_trips_between_sites() {
        let (_da, a) = make_peer("site-a", "site-b");

        let bucket_before = crypto::current_timestamp_ms() / COUNTER_BUCKET_MS;
        let pkt = a
            .build_packet(&ControlPayload::RouteSync {
                subnets_json: br#"["192.168.1.0/24"]"#.to_vec(),
            })
            .unwrap();
        // next_send_counter stores used + 1, so the used value is stored - 1.
        let counter = a.send_counter.load(Ordering::Relaxed) - 1;

        // The counter must be pinned to the wall-clock bucket the receiver's
        // tag window is centred on — never a small 0-based value.
        assert!(
            counter >= bucket_before,
            "send counter ({counter}) must be at/above the current 5-second \
             bucket ({bucket_before}), not seeded from 0"
        );

        // Receiver side (B, local_name = "site-b", peer = "site-a"): the
        // session registered by site_sync::start is keyed by B's
        // RECV-direction root for this link.
        let raw = [7u8; 32];
        let (_b_send, b_recv_root) =
            directional_roots(&raw, Some("site-b"), "site-a").expect("distinct names");
        let recv_keys = site_session_keys(&b_recv_root);

        // Gateway::compute_nonce: nonce[..8] = counter.to_le_bytes().
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        let ciphertext = &pkt[TAG_SIZE + crate::pool_sync::CLUSTER_MDH_LEN..];
        let plaintext = decrypt_payload(&recv_keys.session_key, &nonce, ciphertext)
            .expect("receiver must decrypt with counter-derived nonce and recv-direction key");

        // Plaintext layout: [pad_len u16][InnerHeader][ControlPayload][padding].
        let pad_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
        let inner = &plaintext[2..plaintext.len() - pad_len];
        let header = InnerHeader::decode(inner).unwrap();
        assert_eq!(header.inner_type, InnerType::Control);
        match ControlPayload::decode(&inner[4..]).unwrap() {
            ControlPayload::RouteSync { subnets_json } => {
                assert_eq!(subnets_json, br#"["192.168.1.0/24"]"#.to_vec());
            }
            other => panic!("expected RouteSync, got {:?}", other),
        }

        // The resonance tag must be generated from the SAME counter, so the
        // receiver can recover it (this is how the nonce above is obtained).
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected_tag = crypto::generate_resonance_tag(&a.session_keys.tag_secret, counter, tw);
        assert_eq!(&pkt[..TAG_SIZE], &expected_tag[..]);

        // A12 directionality intact: the REVERSE-direction key (B→A, which is
        // also what A itself receives with) must NOT decrypt A→B traffic.
        let (_a_send, a_recv_root) =
            directional_roots(&raw, Some("site-a"), "site-b").expect("distinct names");
        let reverse_keys = site_session_keys(&a_recv_root);
        assert_ne!(recv_keys.session_key, reverse_keys.session_key);
        assert!(
            decrypt_payload(&reverse_keys.session_key, &nonce, ciphertext).is_err(),
            "reverse-direction key must not decrypt A→B traffic"
        );
    }

    /// A12 regression guard: A's send keys must equal B's recv keys for the
    /// same link, while A→B and B→A never share an AEAD key.
    #[test]
    fn directional_roles_mirror_between_two_sites() {
        let (_da, a) = make_peer("site-a", "site-b");
        let (_db, b) = make_peer("site-b", "site-a");

        let raw = [7u8; 32];
        let (_s, b_recv_root) =
            directional_roots(&raw, Some("site-b"), "site-a").expect("distinct names");
        let (_s2, a_recv_root) =
            directional_roots(&raw, Some("site-a"), "site-b").expect("distinct names");

        assert_eq!(
            a.session_keys.session_key,
            site_session_keys(&b_recv_root).session_key
        );
        assert_eq!(
            b.session_keys.session_key,
            site_session_keys(&a_recv_root).session_key
        );
        assert_ne!(
            a.session_keys.session_key, b.session_keys.session_key,
            "A→B and B→A must encrypt under different AEAD keys"
        );
    }

    /// Legacy symmetric mode (no `local_name`) must not create a sender:
    /// with counter-derived nonces both directions of a shared key would
    /// collide in the same (key, nonce) space.
    #[test]
    fn legacy_symmetric_mode_disables_sender() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SitePeer::new(test_peer_cfg("site-b"), vec![], None, dir.path()).is_none());
        // Same-name collision falls back to symmetric roots → also disabled.
        assert!(
            SitePeer::new(test_peer_cfg("site-b"), vec![], Some("site-b"), dir.path()).is_none()
        );
    }

    /// Restart nonce-reuse regression (same guarantee as
    /// `pool_sync::restart_never_reuses_a_send_counter_value`): the per-link
    /// send key is static across restarts, so a second SitePeer constructed
    /// against the same state dir — worst case, inside the same 5-second
    /// wall-clock bucket — must resume PAST every counter already used.
    #[test]
    fn restart_never_reuses_a_send_counter_value() {
        let dir = tempfile::tempdir().unwrap();
        let peer1 = SitePeer::new(
            test_peer_cfg("site-b"),
            vec!["192.168.1.0/24".to_string()],
            Some("site-a"),
            dir.path(),
        )
        .unwrap();

        let payload = ControlPayload::RouteSync {
            subnets_json: b"[]".to_vec(),
        };
        let mut last_used = 0u64;
        for _ in 0..5 {
            peer1.build_packet(&payload).unwrap();
            last_used = peer1.send_counter.load(Ordering::Relaxed) - 1;
        }

        let peer2 = SitePeer::new(
            test_peer_cfg("site-b"),
            vec!["192.168.1.0/24".to_string()],
            Some("site-a"),
            dir.path(),
        )
        .unwrap();
        let resumed = peer2.send_counter.load(Ordering::Relaxed);
        assert!(
            resumed > last_used,
            "restarted site peer must never reuse a counter (last used = \
             {last_used}, resumed at = {resumed})"
        );
    }

    #[test]
    fn counter_file_round_trip_and_sanitised_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = site_counter_state_path(dir.path(), "office/b:443");
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .eq("site_sync_counter_office_b_443.state"));

        assert_eq!(read_counter_file(&path), None);
        write_counter_file(&path, 42).unwrap();
        assert_eq!(read_counter_file(&path), Some(42));
        write_counter_file(&path, 43).unwrap();
        assert_eq!(read_counter_file(&path), Some(43));
    }
}

/// Install a kernel route via `ip route add`.
fn install_route(subnet: &str, via: &str) {
    let gateway = via.split(':').next().unwrap_or(via);
    match std::process::Command::new("ip")
        .args(["route", "add", subnet, "via", gateway])
        .status()
    {
        Ok(s) if s.success() => info!("site_sync: route {} via {} OK", subnet, gateway),
        Ok(s) => warn!("site_sync: ip route add exit {}", s),
        Err(e) => warn!("site_sync: ip route add: {}", e),
    }
}
