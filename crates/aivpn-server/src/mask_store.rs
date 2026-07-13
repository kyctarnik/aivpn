//! Mask Store — Storage and Rating System for Auto-Generated Masks
//!
//! Stores MaskProfile + MaskStats pairs with automatic deactivation
//! when success rate drops below threshold. Persists to disk.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use aivpn_common::error::Result;
use aivpn_common::mask::{verify_mask_artifact, MaskProfile, MaskVerifyDetail, MaskVerifyMode};

use crate::gateway::MaskCatalog;

/// Success rate threshold — masks below this are deactivated
const DEACTIVATION_THRESHOLD: f32 = 0.80;

/// Minimum usages before deactivation can trigger
const MIN_USAGES_FOR_DEACTIVATION: u64 = 100;

/// Mask statistics for rating system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskStats {
    pub mask_id: String,
    pub times_used: u64,
    pub times_failed: u64,
    pub success_rate: f32,
    pub confidence: f32,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: u64,
    pub last_used: Option<u64>,
}

/// Combined mask profile + statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskEntry {
    pub profile: MaskProfile,
    pub stats: MaskStats,
}

/// Mask store with rating system and disk persistence
pub struct MaskStore {
    /// All masks (mask_id → MaskEntry)
    masks: DashMap<String, MaskEntry>,
    /// Reference to the gateway's mask catalog for registration
    catalog: Arc<MaskCatalog>,
    /// Storage directory for mask files
    storage_dir: PathBuf,
    /// Monotonic version of the selectable mask set, bumped on add/delete.
    /// The gateway pushes a fresh client-facing `MaskCatalog` whenever this
    /// moves past what a session was last sent, so newly auto-generated masks
    /// reach connected clients live (see gateway Keepalive handler).
    version: portable_atomic::AtomicU64,
    /// R2 Phase B: operator Ed25519 signing key. When `Some`, freshly
    /// generated masks (`mask_gen::generate_and_store_mask`) are signed with
    /// it after the KS self-test passes. `None` = generate unsigned (legacy).
    signing_key: Option<ed25519_dalek::SigningKey>,
    /// R2 Phase B: operator Ed25519 verifying (public) key used to check the
    /// embedded `MaskProfile.signature` of masks loaded from disk.
    operator_pubkey: Option<[u8; 32]>,
    /// R2 Phase B: config-gated verification level for disk loads
    /// (off | warn | enforce). Default `warn`.
    verify_mode: MaskVerifyMode,
}

impl MaskStore {
    /// Create a new mask store.
    ///
    /// `signing_key` — operator mask-signing key (signs newly generated masks).
    /// `operator_pubkey` — operator verifying key for disk-load verification.
    /// `verify_mode` — off | warn (default) | enforce, applied in
    /// `load_from_disk`.
    pub fn new(
        catalog: Arc<MaskCatalog>,
        storage_dir: PathBuf,
        signing_key: Option<ed25519_dalek::SigningKey>,
        operator_pubkey: Option<[u8; 32]>,
        verify_mode: MaskVerifyMode,
    ) -> Self {
        let store = Self {
            masks: DashMap::new(),
            catalog,
            storage_dir,
            // Start at 1 so a session that has never been sent a catalog
            // (version_sent = 0) always receives one.
            version: portable_atomic::AtomicU64::new(1),
            signing_key,
            operator_pubkey,
            verify_mode,
        };
        // Load masks only from disk — no hardcoded presets
        store.load_from_disk();
        store
    }

    /// Operator mask-signing key, if configured (R2 Phase B sign side).
    pub fn operator_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.signing_key.as_ref()
    }

    /// Add a new mask entry
    pub fn add_mask(&self, entry: MaskEntry) -> Result<()> {
        let mask_id = entry.stats.mask_id.clone();
        info!(
            "Storing mask '{}' (confidence: {:.2})",
            mask_id, entry.stats.confidence
        );

        // Save to disk
        self.save_to_disk(&mask_id, &entry);

        // Register in catalog for neural resonance
        self.catalog.register_mask(entry.profile.clone());

        // Insert into in-memory store
        self.masks.insert(mask_id, entry);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Current version of the selectable mask set (bumped on add/delete).
    pub fn catalog_version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Register mask in the gateway catalog
    pub fn register_in_catalog(&self, mask_id: &str) -> Result<()> {
        if let Some(entry) = self.masks.get(mask_id) {
            self.catalog.register_mask(entry.value().profile.clone());
        }
        Ok(())
    }

    /// Record successful usage of a mask
    pub fn record_usage(&self, mask_id: &str) {
        if let Some(mut entry) = self.masks.get_mut(mask_id) {
            entry.stats.times_used += 1;
            entry.stats.success_rate = if entry.stats.times_used > 0 {
                1.0 - entry.stats.times_failed as f32 / entry.stats.times_used as f32
            } else {
                1.0
            };
            entry.stats.last_used = Some(current_unix_secs());
            self.save_stats_to_disk(mask_id, &entry.stats);
        }
    }

    /// Record a failure (DPI block detected)
    pub fn record_failure(&self, mask_id: &str) {
        if let Some(mut entry) = self.masks.get_mut(mask_id) {
            entry.stats.times_used += 1;
            entry.stats.times_failed += 1;
            entry.stats.success_rate = if entry.stats.times_used > 0 {
                1.0 - entry.stats.times_failed as f32 / entry.stats.times_used as f32
            } else {
                1.0
            };

            // Auto-deactivation check
            if entry.stats.success_rate < DEACTIVATION_THRESHOLD
                && entry.stats.times_used > MIN_USAGES_FOR_DEACTIVATION
            {
                entry.stats.is_active = false;
                self.catalog.remove_mask(mask_id);
                warn!(
                    "Mask '{}' deactivated: success={:.1}% ({}/{} failures)",
                    mask_id,
                    entry.stats.success_rate * 100.0,
                    entry.stats.times_failed,
                    entry.stats.times_used
                );
            }
            self.save_stats_to_disk(mask_id, &entry.stats);
        }
    }

    /// List all masks with their stats
    pub fn list_masks(&self) -> Vec<MaskEntry> {
        self.masks.iter().map(|e| e.value().clone()).collect()
    }

    /// Get a specific mask entry
    pub fn get_mask(&self, mask_id: &str) -> Option<MaskEntry> {
        self.masks.get(mask_id).map(|e| e.value().clone())
    }

    /// Delete a mask
    pub fn delete_mask(&self, mask_id: &str) {
        self.masks.remove(mask_id);
        self.catalog.remove_mask(mask_id);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Remove disk files (guarded so a crafted mask_id can't escape the dir).
        if let Some(json_path) = self.safe_mask_path(mask_id, "json") {
            let _ = std::fs::remove_file(&json_path);
        }
        if let Some(stats_path) = self.safe_mask_path(mask_id, "stats") {
            let _ = std::fs::remove_file(&stats_path);
        }
        info!("Deleted mask '{}'", mask_id);
    }

    /// Build the on-disk path for a mask file, or `None` when `mask_id` is not a
    /// safe single path component. This is a defence-in-depth guard: mask IDs
    /// derived from recording service names are already sanitised at the source
    /// (`mask_gen::sanitize_service_slug`), but validating again at the
    /// filesystem boundary ensures no future caller can trigger a path-traversal
    /// write/delete as root (`../`, absolute paths, separators are all rejected).
    fn safe_mask_path(&self, mask_id: &str, ext: &str) -> Option<PathBuf> {
        let safe = !mask_id.is_empty()
            && mask_id.len() <= 128
            && mask_id != "."
            && mask_id != ".."
            && mask_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !safe {
            error!(
                "Refusing unsafe mask_id '{}' for on-disk {} file",
                mask_id, ext
            );
            return None;
        }
        Some(self.storage_dir.join(format!("{}.{}", mask_id, ext)))
    }

    /// Make a newly stored mask available to connected clients.
    ///
    /// This does **not** push a `ControlPayload::MaskUpdate` to live sessions —
    /// `MaskStore` holds no UDP socket, session table, or per-session key
    /// material, so it cannot frame/sign/encrypt a per-session control message.
    /// It also would not be desirable to force every connected client onto a
    /// brand-new, still-unproven (`times_used = 0`) auto-generated mask.
    ///
    /// The real live-distribution path is the monotonic catalog `version`,
    /// which `add_mask` bumps when the mask is stored. The gateway compares that
    /// version against each session's `mask_catalog_version_sent` on every
    /// keepalive and pushes a fresh `MaskCatalog` (see the `Keepalive` arm in
    /// `gateway::handle_control_message`), so the mask reaches connected clients
    /// as *selectable* without any action here. Clients then opt into it via
    /// `MaskPreference`.
    ///
    /// This method only validates that the stored profile serialises cleanly
    /// (so a later catalog push cannot fail on it) and logs the outcome. It is
    /// intentionally a no-op with respect to session traffic — the log must not
    /// claim a broadcast that did not happen.
    pub async fn broadcast_mask_update(&self, mask_id: &str) -> Result<()> {
        if let Some(entry) = self.masks.get(mask_id) {
            // Validate the profile is serialisable so the catalog push can't
            // later fail on it. This does not transmit anything.
            let _profile_data = rmp_serde::to_vec(&entry.value().profile)
                .map_err(|e| aivpn_common::error::Error::Serialization(e.to_string()))?;
            info!(
                "Mask '{}' registered (catalog v{}); it will be pushed to \
                 connected clients as selectable on their next keepalive — no \
                 forced per-session MaskUpdate is sent",
                mask_id,
                self.catalog_version()
            );
        } else {
            warn!(
                "broadcast_mask_update called for unknown mask '{}' — nothing to distribute",
                mask_id
            );
        }
        Ok(())
    }

    fn save_stats_to_disk(&self, mask_id: &str, stats: &MaskStats) {
        let Some(stats_path) = self.safe_mask_path(mask_id, "stats") else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.storage_dir);
        match serde_json::to_string_pretty(stats) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&stats_path, json) {
                    error!("Failed to save mask stats {}: {}", mask_id, e);
                }
            }
            Err(e) => error!("Failed to serialize mask stats {}: {}", mask_id, e),
        }
    }

    /// Save mask entry to disk
    fn save_to_disk(&self, mask_id: &str, entry: &MaskEntry) {
        let Some(json_path) = self.safe_mask_path(mask_id, "json") else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.storage_dir);

        match serde_json::to_string_pretty(&entry.profile) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&json_path, json) {
                    error!("Failed to save mask profile {}: {}", mask_id, e);
                }
            }
            Err(e) => error!("Failed to serialize mask profile {}: {}", mask_id, e),
        }

        self.save_stats_to_disk(mask_id, &entry.stats);
    }

    /// Load masks from disk on startup
    fn load_from_disk(&self) {
        let dir = &self.storage_dir;
        if !dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let mask_id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();

                if mask_id.is_empty() {
                    continue;
                }

                // Load profile
                let profile: MaskProfile = match std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                {
                    Some(p) => p,
                    None => continue,
                };

                // R2 Phase B: config-gated operator signature verification.
                // No derived-variant exemption here — disk is not a
                // channel-authenticated path, and an attacker who can write to
                // the mask dir must not bypass `enforce` by picking a
                // `polymorphic:`-prefixed mask_id.
                let verdict =
                    verify_mask_artifact(&profile, self.operator_pubkey.as_ref(), self.verify_mode);
                if !verdict.accept {
                    error!(
                        "Mask '{}' REJECTED (mask_verify_mode=enforce): {} — file: {}",
                        mask_id,
                        verify_detail_str(verdict.detail),
                        path.display()
                    );
                    continue;
                }
                if verdict.is_failure() && self.operator_pubkey.is_some() {
                    warn!(
                        "Mask '{}' failed operator signature verification ({}) — \
                         accepted because mask_verify_mode=warn. Re-sign it or set \
                         mask_verify_mode=enforce once the corpus is signed.",
                        mask_id,
                        verify_detail_str(verdict.detail)
                    );
                }

                // Load stats
                let stats_path = dir.join(format!("{}.stats", mask_id));
                let stats: MaskStats = std::fs::read_to_string(&stats_path)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                    .unwrap_or(MaskStats {
                        mask_id: mask_id.clone(),
                        times_used: 0,
                        times_failed: 0,
                        success_rate: 1.0,
                        confidence: 0.0,
                        is_active: true,
                        created_by: "loaded".into(),
                        created_at: 0,
                        last_used: None,
                    });

                info!(
                    "Loaded mask '{}' from disk (success: {:.1}%)",
                    mask_id,
                    stats.success_rate * 100.0
                );

                // Register only active masks in the live catalog
                if stats.is_active {
                    self.catalog.register_mask(profile.clone());
                }

                self.masks.insert(mask_id, MaskEntry { profile, stats });
            }
        }
    }
}

/// Human-readable reason for mask verification log lines.
fn verify_detail_str(detail: MaskVerifyDetail) -> &'static str {
    match detail {
        MaskVerifyDetail::ModeOff => "verification disabled",
        MaskVerifyDetail::Valid => "valid operator signature",
        MaskVerifyDetail::NoOperatorKey => "no operator public key configured",
        MaskVerifyDetail::Unsigned => "unsigned (all-zero legacy signature)",
        MaskVerifyDetail::Invalid => "invalid signature",
    }
}

/// Get current Unix timestamp in seconds
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> MaskStore {
        let dir = std::env::temp_dir().join(format!("aivpn-maskstore-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        MaskStore {
            masks: DashMap::new(),
            catalog: Arc::new(MaskCatalog::new()),
            storage_dir: dir,
            version: portable_atomic::AtomicU64::new(1),
            signing_key: None,
            operator_pubkey: None,
            verify_mode: MaskVerifyMode::default(),
        }
    }

    #[test]
    fn phase_b_load_verification_modes() {
        use aivpn_common::mask::preset_masks;

        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let dir = std::env::temp_dir().join(format!(
            "aivpn-maskstore-verify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);

        let mut signed = preset_masks::all()[0].clone();
        signed.mask_id = "signed_m".into();
        signed.sign(&sk);
        std::fs::write(
            dir.join("signed_m.json"),
            serde_json::to_string(&signed).unwrap(),
        )
        .unwrap();

        let mut unsigned = preset_masks::all()[0].clone();
        unsigned.mask_id = "unsigned_m".into();
        unsigned.signature = [0u8; 64];
        std::fs::write(
            dir.join("unsigned_m.json"),
            serde_json::to_string(&unsigned).unwrap(),
        )
        .unwrap();

        // enforce: signed loads, unsigned is rejected.
        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Enforce,
        );
        assert!(store.get_mask("signed_m").is_some());
        assert!(
            store.get_mask("unsigned_m").is_none(),
            "enforce must reject the unsigned legacy mask"
        );

        // warn: both load (unsigned is logged, not rejected).
        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Warn,
        );
        assert!(store.get_mask("signed_m").is_some());
        assert!(store.get_mask("unsigned_m").is_some());

        // off: both load, no verification at all.
        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Off,
        );
        assert!(store.get_mask("signed_m").is_some());
        assert!(store.get_mask("unsigned_m").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_mask_path_rejects_traversal() {
        let store = make_store();
        assert!(store.safe_mask_path("../../etc/passwd", "json").is_none());
        assert!(store.safe_mask_path("a/b", "json").is_none());
        assert!(store.safe_mask_path("..", "stats").is_none());
        assert!(store.safe_mask_path("", "json").is_none());
    }

    #[test]
    fn safe_mask_path_accepts_normal_ids() {
        let store = make_store();
        let p = store.safe_mask_path("auto_zoom_v1", "json").unwrap();
        assert!(p.starts_with(&store.storage_dir));
        assert!(p.ends_with("auto_zoom_v1.json"));
    }
}
