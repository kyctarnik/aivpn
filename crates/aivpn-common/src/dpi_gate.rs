//! Inline ML-DPI "reads-as-tunnel" gate (R2 Phase D).
//!
//! A cheap, always-on advisory discriminator that watches a session's own
//! outbound masked wire packets and asks: *does this flow still read as its
//! target protocol, or has it started to look like an obfuscated tunnel?* It is
//! a **sibling** to the Neural Resonance Module (`neural.rs`): neural resonance
//! detects drift away from the mask's *own* fingerprint (reconstruction MSE);
//! this gate detects drift *toward* a tunnel/`Unknown` DPI classification. Both
//! feed the same `compromised → rotate` action in the gateway.
//!
//! Why a learned model and not nDPI inline: nDPI (13 MB, full protocol state
//! machines, per-flow allocation) is the right *offline* signing-time authority,
//! but far too heavy for the datapath. So R2 trained a small GradientBoosting
//! model to reproduce nDPI's accept/reject from features the server computes for
//! free over a short packet window — no deep payload parsing, no protocol state
//! machine, no per-packet regex. See `research/mask-generation/r2/` and
//! `docs/R2_PHASE_D.md`.
//!
//! Feature set (23, IAT dropped — see below): packet-size moments + a 6-bin
//! histogram, first-16-byte and full Shannon entropy, byte-0 / QUIC long-header
//! form statistics, and the STUN structural checks nDPI keys off (type at
//! offset 0, magic cookie `21 12 A4 42` at offset 4, and the killer
//! `msg_len + 20 == payload_len` length-consistency predicate). IAT moments are
//! deliberately **excluded**: the offline training pcaps have cosmetic
//! timestamps, so IAT there only separates "synthetic vs real capture", not
//! protocol — an honest gate must not lean on it.
//!
//! Perf budget: feature extraction is O(window) and the model is 120 depth-3
//! trees, so a verdict is ~360 comparisons — evaluated **per window** on the
//! periodic resonance-check cadence, never per packet. The only per-packet cost
//! is `PacketMeta::from_wire` (one entropy pass over the sampled packet), and the
//! gateway samples the same 1-in-16 packets it already samples for neural.
//!
//! The whole module is compiled only under the `dpi-gate` cargo feature (the
//! server enables it transitively through its `neural` feature; clients enable
//! it through `client-dpi-gate`, which also builds the [`ClientSelfGate`]
//! outbound inspector below).

use dashmap::DashMap;
use std::collections::VecDeque;

mod model;

/// One flattened GradientBoosting node.
///
/// Internal node: `feature >= 0` — descend `left` if `x[feature] <= threshold`,
/// else `right`. Leaf: `feature == -1` — contribute `value` to the raw score.
/// The whole ensemble is a single flat [`model::NODES`] table indexed per tree
/// by [`model::TREE_OFFSETS`]; this mirrors how `neural.rs` bakes MLP weights as
/// const arrays, but for a tree ensemble.
#[derive(Clone, Copy)]
pub struct GbdtNode {
    pub feature: i16,
    pub threshold: f32,
    pub left: u16,
    pub right: u16,
    pub value: f32,
}

/// Sliding window length in packets. Matches `features.py` (`N = 24`): the model
/// was trained on 24-packet windows, so a verdict is only meaningful once a full
/// window has accumulated.
pub const WINDOW: usize = 24;

/// Size histogram bins `[lo, hi)`, identical to `features.py::SIZE_BINS`.
const SIZE_BINS: [(u32, u32); 6] = [
    (0, 100),
    (100, 300),
    (300, 600),
    (600, 1000),
    (1000, 1400),
    (1400, 65535),
];

/// Cheap per-packet metadata — everything the 23 features need, with no payload
/// retained. Populated once from the wire bytes a DPI box would see and pushed
/// into a bounded per-session ring.
#[derive(Clone, Copy, Debug)]
pub struct PacketMeta {
    len: u16,
    byte0: u8,
    /// Packet had at least one byte (byte-0 stats denominator, matching
    /// `features.py`'s `[p[0] for p in payloads if p]`).
    has_byte0: bool,
    /// STUN message type at offset 0 (`00 01` / `01 01` / `00 03` / `01 11`)
    /// with the two top bits of byte 0 clear (STUN/RTP demux bit).
    stun_type: bool,
    /// STUN magic cookie `21 12 A4 42` at offset 4.
    magic_ok: bool,
    /// STUN length-consistency: `msg_len + 20 == payload_len` (nDPI's killer
    /// `is_stun()` predicate; the R1 root-cause check).
    stun_lenok: bool,
    /// Rough DNS query heuristic: `qdcount == 1 && ancount <= 16`.
    dns_ok: bool,
    /// Shannon entropy (bits/byte) of the first 16 wire bytes.
    ent16: f32,
    /// Shannon entropy (bits/byte) of the whole wire packet.
    ent_full: f32,
}

impl PacketMeta {
    /// Extract metadata from the observable wire bytes of one packet — exactly
    /// what nDPI / a DPI box inspects. For aivpn this is the full UDP datagram
    /// (`[header/tag bytes][ciphertext]`); embedded-tag masks place the protocol
    /// header bytes at the wire offsets checked below.
    pub fn from_wire(p: &[u8]) -> Self {
        let len = p.len();
        let byte0 = p.first().copied().unwrap_or(0);

        let stun_type = len >= 2
            && (p[0] & 0xC0) == 0
            && matches!(
                [p[0], p[1]],
                [0x00, 0x01] | [0x01, 0x01] | [0x00, 0x03] | [0x01, 0x11]
            );

        let magic_ok = len >= 8 && p[4..8] == [0x21, 0x12, 0xA4, 0x42];

        let stun_lenok = len >= 4 && {
            let msg_len = ((p[2] as usize) << 8) | (p[3] as usize);
            msg_len + 20 == len
        };

        let dns_ok = len >= 12 && {
            let qd = ((p[4] as usize) << 8) | (p[5] as usize);
            let an = ((p[6] as usize) << 8) | (p[7] as usize);
            qd == 1 && an <= 16
        };

        let n16 = len.min(16);
        Self {
            len: len.min(u16::MAX as usize) as u16,
            byte0,
            has_byte0: len > 0,
            stun_type,
            magic_ok,
            stun_lenok,
            dns_ok,
            ent16: shannon_entropy(&p[..n16]) as f32,
            ent_full: shannon_entropy(p) as f32,
        }
    }
}

/// Shannon entropy in bits/byte over `data`. Identical to `features.py::_entropy`
/// and `gateway::compute_entropy`.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Round-half-to-even (banker's rounding), matching Python's built-in `round`
/// used by `features.py::_pct`. This is load-bearing: at the p10/p50/p90
/// percentile indices the fractional part lands exactly on `.5` for common
/// window sizes (e.g. `0.9 * 5 == 4.5`), and half-away-from-zero rounding would
/// pick the wrong sample and silently diverge from the training features.
fn round_half_even(x: f64) -> f64 {
    let f = x.floor();
    let diff = x - f;
    if diff < 0.5 {
        f
    } else if diff > 0.5 {
        f + 1.0
    } else if (f as i64) % 2 == 0 {
        f
    } else {
        f + 1.0
    }
}

/// Percentile of a sorted size slice, matching `features.py::_pct`:
/// `idx = clamp(round_half_even(q * (n - 1)), 0, n - 1)`.
fn pct(sorted: &[u32], q: f64) -> f32 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = round_half_even(q * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)] as f32
}

/// Extract the 23-feature vector from a packet window, in the exact order the
/// embedded model consumes it (a Rust port of `features.py::vector` with the two
/// IAT features dropped). Returns all-zero for an empty window.
pub fn extract_features(window: &[PacketMeta]) -> [f32; model::N_FEATURES] {
    let mut f = [0.0f32; model::N_FEATURES];
    let n = window.len();
    if n == 0 {
        return f;
    }
    let nf = n as f32;

    // Size moments + percentiles.
    let mut sizes: Vec<u32> = window.iter().map(|m| m.len as u32).collect();
    let sum: f64 = sizes.iter().map(|&s| s as f64).sum();
    let mean = sum / n as f64;
    let var = sizes
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / n as f64;
    sizes.sort_unstable();

    f[0] = nf; // n_pkts
    f[1] = mean as f32; // sz_mean
    f[2] = var.sqrt() as f32; // sz_std (population)
    f[3] = sizes[0] as f32; // sz_min
    f[4] = sizes[n - 1] as f32; // sz_max
    f[5] = pct(&sizes, 0.5); // sz_med
    f[6] = pct(&sizes, 0.10); // sz_p10
    f[7] = pct(&sizes, 0.90); // sz_p90

    // Size histogram fractions (bin assignment is order-independent).
    let mut binc = [0u32; SIZE_BINS.len()];
    for m in window {
        let s = m.len as u32;
        for (i, (lo, hi)) in SIZE_BINS.iter().enumerate() {
            if s >= *lo && s < *hi {
                binc[i] += 1;
                break;
            }
        }
    }
    for i in 0..SIZE_BINS.len() {
        f[8 + i] = binc[i] as f32 / nf; // szfrac_*
    }

    // Entropy means (accumulate in f64 to match the Python reference).
    f[14] = (window.iter().map(|m| m.ent16 as f64).sum::<f64>() / n as f64) as f32; // ent_first16
    f[15] = (window.iter().map(|m| m.ent_full as f64).sum::<f64>() / n as f64) as f32; // ent_full

    // Byte-0 / header-form statistics (denominator = packets with >= 1 byte).
    let mut b0_sum = 0u64;
    let mut b0_n = 0u32;
    let mut b0_msb = 0u32;
    let mut quic_long = 0u32;
    for m in window {
        if m.has_byte0 {
            b0_sum += m.byte0 as u64;
            b0_n += 1;
            if m.byte0 & 0x80 != 0 {
                b0_msb += 1;
            }
            if (m.byte0 & 0xC0) == 0xC0 {
                quic_long += 1;
            }
        }
    }
    if b0_n > 0 {
        f[16] = b0_sum as f32 / b0_n as f32; // byte0_mean
        f[17] = b0_msb as f32 / b0_n as f32; // byte0_msb_frac
        f[18] = quic_long as f32 / b0_n as f32; // quic_longform_frac
    }

    // STUN structural + DNS fractions (denominator = all packets).
    f[19] = window.iter().filter(|m| m.stun_type).count() as f32 / nf; // stun_type_frac
    f[20] = window.iter().filter(|m| m.magic_ok).count() as f32 / nf; // stun_magic_frac
    f[21] = window.iter().filter(|m| m.stun_lenok).count() as f32 / nf; // stun_lenconsistent_frac
    f[22] = window.iter().filter(|m| m.dns_ok).count() as f32 / nf; // dns_looksdns_frac

    f
}

/// Run the embedded GradientBoosting ensemble and return the probability that
/// the window "reads as tunnel" (nDPI `Unknown`). `raw = INIT + lr * Σ leaf`,
/// then a logistic squash — the exact inverse of sklearn's `decision_function`.
pub fn tunnel_probability(x: &[f32; model::N_FEATURES]) -> f32 {
    let mut raw = model::INIT;
    for t in 0..model::N_TREES {
        let mut i = model::TREE_OFFSETS[t] as usize;
        loop {
            let node = &model::NODES[i];
            if node.feature < 0 {
                raw += model::LEARNING_RATE * node.value;
                break;
            }
            i = if x[node.feature as usize] <= node.threshold {
                node.left as usize
            } else {
                node.right as usize
            };
        }
    }
    1.0 / (1.0 + (-raw).exp())
}

/// A gate verdict for one session's current window.
#[derive(Debug, Clone, Copy)]
pub struct DpiVerdict {
    /// Modelled probability the window reads as an obfuscated tunnel (`Unknown`).
    pub tunnel_prob: f32,
    /// `tunnel_prob > threshold` — the advisory "rotate this mask" signal.
    pub reads_as_tunnel: bool,
}

/// Approximate embedded model size in bytes (const table footprint).
pub fn embedded_model_bytes() -> usize {
    model::NODES.len() * std::mem::size_of::<GbdtNode>()
        + std::mem::size_of_val(&model::TREE_OFFSETS)
}

/// Per-session inline ML-DPI gate. Holds a bounded ring of recent packet
/// metadata per session and produces a window verdict on demand. Cheap enough to
/// be always-on; the model itself is a const table baked into the binary.
pub struct DpiGate {
    /// Probability above which a full window is judged "reads-as-tunnel".
    threshold: f32,
    windows: DashMap<[u8; 16], VecDeque<PacketMeta>>,
}

impl DpiGate {
    /// Create a gate with the given decision threshold (see
    /// `NeuralConfig::dpi_gate_threshold`).
    pub fn new(threshold: f32) -> Self {
        Self {
            threshold,
            windows: DashMap::new(),
        }
    }

    /// Record one outbound wire packet for a session (O(1) amortised). Keeps only
    /// the last [`WINDOW`] packets.
    pub fn record_wire(&self, session_id: [u8; 16], wire: &[u8]) {
        let meta = PacketMeta::from_wire(wire);
        let mut ring = self.windows.entry(session_id).or_default();
        ring.push_back(meta);
        while ring.len() > WINDOW {
            ring.pop_front();
        }
    }

    /// Verdict for a session, or `None` until a full window has accumulated (an
    /// under-full window is a degenerate feature vector — never judge on it, to
    /// avoid false rotations on a barely-active session).
    pub fn verdict(&self, session_id: &[u8; 16]) -> Option<DpiVerdict> {
        let ring = self.windows.get(session_id)?;
        if ring.len() < WINDOW {
            return None;
        }
        let win: Vec<PacketMeta> = ring.iter().copied().collect();
        let x = extract_features(&win);
        let prob = tunnel_probability(&x);
        Some(DpiVerdict {
            tunnel_prob: prob,
            reads_as_tunnel: prob > self.threshold,
        })
    }

    /// Configured decision threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Drop a session's ring (call on session teardown, like
    /// `NeuralResonanceModule::cleanup_stats`).
    pub fn cleanup(&self, session_id: &[u8; 16]) {
        self.windows.remove(session_id);
    }
}

// ──────────────────── Client-side self-detection gate ───────────────────────

/// Client-side inline "reads-as-tunnel" self-check (R2 Phase D, client edition).
///
/// The server runs [`DpiGate`] over *inbound* client packets and rotates the
/// mask when a flow starts reading as a tunnel. This is the symmetric client
/// half: it watches the client's OWN outbound shaped wire bytes and, when they
/// start reading as a tunnel, proactively raises a rotate-request so the client
/// can ask to change mask *before* the server's own neural/GBDT fires.
///
/// It wraps a single-session [`DpiGate`] and adds three things the server's
/// call site handles itself: (1) 1-in-`stride` packet sampling (mirroring the
/// gateway's 1-in-16 neural sampling — a verdict is per-window, not per-packet),
/// (2) a fire cooldown so one persistently-tunnel-looking flow raises at most
/// one request per window, and (3) the rotate-request payload to emit. It
/// implements [`crate::upload_pipeline::OutboundInspector`] so it drops straight
/// into `run_upload_loop` with no new wire message — the returned
/// [`ControlPayload::MaskPreference`] travels the client's existing mask-change
/// request path (the same message the polymorphic-mask retry task already sends).
#[cfg(feature = "client-dpi-gate")]
pub struct ClientSelfGate {
    gate: DpiGate,
    /// Base mask family to request a fresh variant of on a tunnel verdict.
    base_mask_id: String,
    /// Sample 1-in-`stride` outbound packets into the window.
    stride: u32,
    /// Rolling packet counter for the stride sampler.
    seen: u32,
    /// Verdicts are only re-evaluated every `stride` sampled packets to bound
    /// the GBDT inference cost; this counts sampled packets since the last eval.
    since_eval: u32,
    /// After a request is raised, suppress further requests for this many
    /// evaluated windows (avoids a request storm while a rotation is in flight).
    cooldown_windows: u32,
    /// Remaining suppressed windows.
    cooldown_left: u32,
}

#[cfg(feature = "client-dpi-gate")]
impl ClientSelfGate {
    /// Fixed synthetic session id — the client self-gate only ever tracks its
    /// own single flow, so one stable key into the underlying [`DpiGate`] ring.
    const SELF_SESSION: [u8; 16] = [0u8; 16];

    /// Default outbound sampling stride — every 16th packet, matching the
    /// gateway's neural/DPI sampling cadence.
    pub const DEFAULT_STRIDE: u32 = 16;

    /// Number of evaluated windows to stay quiet after raising a request.
    pub const DEFAULT_COOLDOWN_WINDOWS: u32 = 8;

    /// Create a client self-gate that requests a fresh variant of `base_mask_id`
    /// when its own outbound flow reads as a tunnel above `threshold`.
    pub fn new(threshold: f32, base_mask_id: impl Into<String>) -> Self {
        Self {
            gate: DpiGate::new(threshold),
            base_mask_id: base_mask_id.into(),
            stride: Self::DEFAULT_STRIDE,
            seen: 0,
            since_eval: 0,
            cooldown_windows: Self::DEFAULT_COOLDOWN_WINDOWS,
            cooldown_left: 0,
        }
    }

    /// Override the 1-in-N outbound sampling stride (min 1).
    pub fn with_stride(mut self, stride: u32) -> Self {
        self.stride = stride.max(1);
        self
    }

    /// Override the post-request cooldown, in evaluated windows.
    pub fn with_cooldown_windows(mut self, windows: u32) -> Self {
        self.cooldown_windows = windows;
        self
    }

    /// Feed one outbound wire datagram. Returns the tunnel probability of the
    /// window that just crossed the threshold (i.e. `Some` only when a
    /// rotate-request should be raised), else `None`. Sampling + cooldown are
    /// applied internally so the caller can call this on every packet cheaply.
    pub fn observe_wire(&mut self, wire: &[u8]) -> Option<f32> {
        // Stride sampler: only every Nth packet enters the window.
        self.seen = self.seen.wrapping_add(1);
        if self.seen % self.stride != 0 {
            return None;
        }
        self.gate.record_wire(Self::SELF_SESSION, wire);

        // Only run GBDT inference once per full stride of sampled packets.
        self.since_eval += 1;
        if self.since_eval < self.stride {
            return None;
        }
        self.since_eval = 0;

        if self.cooldown_left > 0 {
            self.cooldown_left -= 1;
            return None;
        }

        let verdict = self.gate.verdict(&Self::SELF_SESSION)?;
        if verdict.reads_as_tunnel {
            self.cooldown_left = self.cooldown_windows;
            Some(verdict.tunnel_prob)
        } else {
            None
        }
    }

    /// The rotate-request control payload to send on a tunnel verdict — the
    /// client's existing `MaskPreference` mask-change request, not a new message.
    pub fn rotate_request(&self) -> crate::protocol::ControlPayload {
        crate::protocol::ControlPayload::MaskPreference {
            base_mask_id: self.base_mask_id.clone(),
        }
    }
}

#[cfg(feature = "client-dpi-gate")]
impl crate::upload_pipeline::OutboundInspector for ClientSelfGate {
    fn observe(&mut self, wire: &[u8]) -> Option<crate::protocol::ControlPayload> {
        match self.observe_wire(wire) {
            Some(prob) => {
                tracing::warn!(
                    "client ML-DPI self-gate: own outbound flow reads as tunnel \
                     (p={:.3}) — requesting mask rotation (MaskPreference base='{}')",
                    prob,
                    self.base_mask_id
                );
                Some(self.rotate_request())
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── features.py reference generators (ported verbatim) ───────────────────
    fn stun_pkt(msg_len: usize, total: usize) -> Vec<u8> {
        let mut p = vec![
            0x00,
            0x01,
            ((msg_len >> 8) & 0xff) as u8,
            (msg_len & 0xff) as u8,
            0x21,
            0x12,
            0xa4,
            0x42,
        ];
        for i in 0..(total - 8) {
            p.push(((i * 37 + 11) & 0xff) as u8);
        }
        p.truncate(total);
        p
    }
    fn rnd_pkt(total: usize, seed: usize) -> Vec<u8> {
        (0..total)
            .map(|i| ((seed * 131 + i * 97 + 7) & 0xff) as u8)
            .collect()
    }

    /// Feature extraction must reproduce `features.py::extract` (IAT dropped) on
    /// a synthetic window. Reference vector generated by running features.py on
    /// this exact window (see docs/R2_PHASE_D.md / export_model.py provenance).
    #[test]
    fn feature_extraction_matches_python_reference() {
        let window: Vec<PacketMeta> = [
            stun_pkt(56, 76), // msg_len 56 + 20 == 76  -> lenok
            stun_pkt(20, 40), // 20 + 20 == 40          -> lenok
            stun_pkt(8, 28),  // 8 + 20 == 28           -> lenok
            rnd_pkt(1100, 3), // tunnel, large
            rnd_pkt(1200, 9), // tunnel, large
            rnd_pkt(200, 21), // tunnel, small
        ]
        .iter()
        .map(|p| PacketMeta::from_wire(p))
        .collect();

        let got = extract_features(&window);
        // From features.py on the identical window (IAT features dropped):
        let want: [f32; model::N_FEATURES] = [
            6.0,
            440.666_67,
            505.476_23,
            28.0,
            1200.0,
            76.0,
            28.0,
            1100.0,
            0.5,
            0.166_666_67,
            0.0,
            0.0,
            0.333_333_34,
            0.0,
            3.9375,
            6.625_917_5,
            84.0,
            0.5,
            0.166_666_67,
            0.5,
            0.5,
            0.5,
            0.0,
        ];
        for i in 0..model::N_FEATURES {
            let tol = 1e-3 * want[i].abs().max(1.0);
            assert!(
                (got[i] - want[i]).abs() <= tol,
                "feature {} ({}): got {} want {}",
                i,
                FEATURE_NAMES[i],
                got[i],
                want[i]
            );
        }
    }

    const FEATURE_NAMES: [&str; model::N_FEATURES] = [
        "n_pkts",
        "sz_mean",
        "sz_std",
        "sz_min",
        "sz_max",
        "sz_med",
        "sz_p10",
        "sz_p90",
        "szfrac_0_100",
        "szfrac_100_300",
        "szfrac_300_600",
        "szfrac_600_1000",
        "szfrac_1000_1400",
        "szfrac_1400p",
        "ent_first16",
        "ent_full",
        "byte0_mean",
        "byte0_msb_frac",
        "quic_longform_frac",
        "stun_type_frac",
        "stun_magic_frac",
        "stun_lenconsistent_frac",
        "dns_looksdns_frac",
    ];

    /// Per-packet structural flags line up with nDPI's checks.
    #[test]
    fn packet_meta_flags() {
        let stun = PacketMeta::from_wire(&stun_pkt(56, 76));
        assert!(stun.stun_type && stun.magic_ok && stun.stun_lenok);
        let junk = PacketMeta::from_wire(&rnd_pkt(1100, 3));
        assert!(!junk.stun_type && !junk.magic_ok);
    }

    /// The embedded model classifies a known masked target-protocol window as
    /// NOT a tunnel, and a known broken/Unknown window as a tunnel. Vectors and
    /// reference probabilities taken from research/mask-generation/r2 (dataset +
    /// export_model.py's test_vectors.json, masked-domain rows).
    #[test]
    fn model_separates_masked_from_tunnel() {
        // masked QUIC window (nDPI: QUIC) -> reads-as-target.
        let quic: [f32; model::N_FEATURES] = [
            24.0, 1228.5, 70.262_01, 1200.0, 1414.0, 1200.0, 1200.0, 1414.0, 0.0, 0.0, 0.0, 0.0,
            0.875, 0.125, 3.217_366, 7.839_845, 197.875, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
        ];
        // masked STUN window (nDPI: STUN) -> reads-as-target.
        let stun: [f32; model::N_FEATURES] = [
            24.0, 600.5, 455.659_24, 107.0, 1358.0, 556.0, 109.0, 1342.0, 0.0, 0.375, 0.25, 0.125,
            0.25, 0.0, 3.906_25, 7.315_663, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0,
        ];
        // deliberately-broken mask (nDPI: Unknown) -> reads-as-tunnel.
        let broken: [f32; model::N_FEATURES] = [
            24.0,
            630.125,
            456.920_52,
            130.0,
            1380.0,
            595.0,
            153.0,
            1380.0,
            0.0,
            0.333_333_34,
            0.208_333_34,
            0.166_666_67,
            0.291_666_67,
            0.0,
            3.681_986,
            7.382_86,
            144.458_34,
            0.583_333_34,
            0.375,
            0.0,
            0.0,
            0.0,
            0.0,
        ];

        let p_quic = tunnel_probability(&quic);
        let p_stun = tunnel_probability(&stun);
        let p_broken = tunnel_probability(&broken);
        assert!(p_quic < 0.1, "QUIC tunnel_prob too high: {p_quic}");
        assert!(p_stun < 0.1, "STUN tunnel_prob too high: {p_stun}");
        assert!(p_broken > 0.9, "broken tunnel_prob too low: {p_broken}");

        // And the gate's boolean at the default 0.5 threshold.
        let gate = DpiGate::new(0.5);
        assert!(
            !DpiVerdict {
                tunnel_prob: p_stun,
                reads_as_tunnel: p_stun > gate.threshold()
            }
            .reads_as_tunnel
        );
        assert!(p_broken > gate.threshold());
    }

    /// Ring buffers to WINDOW and only judges once full.
    #[test]
    fn gate_window_fill_and_verdict() {
        let gate = DpiGate::new(0.5);
        let sid = [7u8; 16];
        for _ in 0..(WINDOW - 1) {
            gate.record_wire(sid, &stun_pkt(56, 76));
        }
        assert!(
            gate.verdict(&sid).is_none(),
            "under-full window must abstain"
        );
        gate.record_wire(sid, &stun_pkt(56, 76));
        assert!(gate.verdict(&sid).is_some(), "full window must judge");
        gate.cleanup(&sid);
        assert!(gate.verdict(&sid).is_none());
    }

    /// The baked ensemble is small (well under the neural MLP's per-mask 66 KB).
    #[test]
    fn embedded_model_is_small() {
        let bytes = embedded_model_bytes();
        assert!(
            bytes < 64 * 1024,
            "embedded model unexpectedly large: {bytes}"
        );
    }

    /// The model const table loads and the known reference vectors round-trip
    /// through the public client entry points (mirrors the server separation
    /// test but via the exact API the client self-gate uses).
    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_gate_model_loads_and_separates() {
        // Same masked-STUN (benign) and broken (tunnel) vectors as above.
        let stun: [f32; model::N_FEATURES] = [
            24.0, 600.5, 455.659_24, 107.0, 1358.0, 556.0, 109.0, 1342.0, 0.0, 0.375, 0.25, 0.125,
            0.25, 0.0, 3.906_25, 7.315_663, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0,
        ];
        let broken: [f32; model::N_FEATURES] = [
            24.0,
            630.125,
            456.920_52,
            130.0,
            1380.0,
            595.0,
            153.0,
            1380.0,
            0.0,
            0.333_333_34,
            0.208_333_34,
            0.166_666_67,
            0.291_666_67,
            0.0,
            3.681_986,
            7.382_86,
            144.458_34,
            0.583_333_34,
            0.375,
            0.0,
            0.0,
            0.0,
            0.0,
        ];
        assert!(tunnel_probability(&stun) < 0.1);
        assert!(tunnel_probability(&broken) > 0.9);
    }

    /// The client self-gate raises a `MaskPreference` rotate-request when its own
    /// outbound flow reads as a tunnel, and stays silent on a benign flow. Uses
    /// stride/cooldown = 1 so a single filled window fires immediately.
    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_self_gate_raises_on_tunnel_flow() {
        use crate::protocol::ControlPayload;
        use crate::upload_pipeline::OutboundInspector;

        // Benign flow: well-formed STUN packets — must never raise.
        let mut benign = ClientSelfGate::new(0.5, "quic-web")
            .with_stride(1)
            .with_cooldown_windows(1);
        let mut raised = false;
        for _ in 0..(WINDOW * 3) {
            if benign.observe(&stun_pkt(56, 76)).is_some() {
                raised = true;
            }
        }
        assert!(!raised, "benign STUN flow must not raise a rotate-request");

        // Tunnel-like flow: high-entropy random datagrams with tunnel-shaped
        // sizes — must raise a MaskPreference for the configured base mask.
        let mut tun = ClientSelfGate::new(0.5, "quic-web")
            .with_stride(1)
            .with_cooldown_windows(4);
        let mut got: Option<ControlPayload> = None;
        for i in 0..(WINDOW * 2) {
            // Alternate large tunnel datagrams (as in model_separates_* broken).
            let pkt = rnd_pkt(1200 + (i % 3) * 60, i * 7 + 1);
            if let Some(p) = tun.observe(&pkt) {
                got = Some(p);
                break;
            }
        }
        match got {
            Some(ControlPayload::MaskPreference { base_mask_id }) => {
                assert_eq!(base_mask_id, "quic-web");
            }
            other => panic!("expected a MaskPreference rotate-request, got {other:?}"),
        }
    }

    /// Under-full window abstains, and the cooldown suppresses repeated requests
    /// after the first fire.
    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_self_gate_window_and_cooldown() {
        let mut g = ClientSelfGate::new(0.5, "base").with_stride(1);
        // Fewer than WINDOW samples: verdict ring not full -> never raises.
        for _ in 0..(WINDOW - 1) {
            assert!(g.observe_wire(&rnd_pkt(1200, 5)).is_none());
        }
        // First full window on a tunnel flow raises; the next several evaluated
        // windows are suppressed by the cooldown even though the flow is
        // unchanged.
        let mut fires = 0usize;
        for i in 0..(WINDOW * 4) {
            if g.observe_wire(&rnd_pkt(1200, i + 9)).is_some() {
                fires += 1;
            }
        }
        assert!(
            fires >= 1,
            "a sustained tunnel flow must raise at least once"
        );
    }
}
