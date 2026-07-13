//! Offline adversarial mask-repair loop (R2 Phase C).
//!
//! A freshly-generated mask (`mask_gen`) can *fail the DPI eval-gate*: nDPI reads
//! its synthesised uplink as high-entropy `Unknown` (or, worse, flags it as an
//! obfuscated tunnel) instead of the protocol it means to mimic. Historically the
//! operator response was to discard the mask and re-author the header by hand. R2
//! Phase C replaces that manual step with a bounded, deterministic
//! **hill-climbing repair loop**: mutate the mask's *observable shape* (tag
//! layout, `header_spec` protocol fields, size envelope), synthesise a flow, ask
//! the real nDPI discriminator for a verdict, keep the mutation if the score
//! improves, and stop the moment the mask earns its target-protocol
//! classification.
//!
//! This module is the discriminator-agnostic core: the genome, the realisation of
//! a genome onto a base `MaskProfile`, the score function, and the loop. The nDPI
//! discriminator itself (which shells out to `maskpcap` + `ndpiReader`) lives in
//! the `aivpn-mask-repair` binary and is injected through the [`Discriminator`]
//! trait, so the loop is unit-testable without nDPI (see the mock in the tests
//! below).
//!
//! # Anti-overfit
//! The mutation space can only assemble bytes a *genuine* STUN/QUIC client emits
//! (real STUN type + magic cookie, real QUIC long-header form + version) — never
//! a pattern reverse-engineered purely to trip nDPI's parser. A repaired mask is
//! therefore structurally the target protocol, not an nDPI artefact. The
//! prototype cross-checked every converged mask against an independent ML
//! classifier (`research/mask-generation/r2/train.py`); the operator pipeline is
//! expected to keep that second-discriminator agreement as a guard.
//!
//! # What is preserved
//! Repair mutates *only* the observable wire shape. The base mask's learned
//! distributions — the R3 joint size↔IAT GMM (`size_iat_joint`), the R4 temporal
//! FSM (`fsm_states`), the neural `signature_vector`, IAT parameters — are cloned
//! through untouched. The embedded `signature` is zeroed because the profile
//! changed: a repaired mask MUST be re-signed by the signing pipeline (Phase B)
//! before distribution.

use aivpn_common::mask::{
    HeaderEndian, HeaderField, HeaderSpec, IdFieldMode, MaskProfile, SizeDistType,
    SizeDistribution, SpoofProtocol,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Target protocol the repair loop drives a mask toward. Mirrors the subset of
/// `SpoofProtocol` the offline nDPI eval-gate can classify structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProto {
    /// WebRTC/STUN Binding — nDPI `is_stun()` keys off type `00 01` @0, magic
    /// cookie `21 12 A4 42` @4, and the exact `msg_len + 20 == payload_len`.
    Stun,
    /// QUIC — nDPI keys off the long-header form (`byte0 & 0xC0 == 0xC0`) and a
    /// recognised version.
    Quic,
}

impl TargetProto {
    /// Derive the target from a mask's own `spoof_protocol`, so the tool is
    /// self-describing. Returns `None` for protocols the structural gate does not
    /// cover (the caller must then supply an explicit target or reject the mask).
    pub fn from_spoof(p: &SpoofProtocol) -> Option<Self> {
        match p {
            SpoofProtocol::WebRTC_STUN => Some(Self::Stun),
            SpoofProtocol::QUIC => Some(Self::Quic),
            _ => None,
        }
    }

    /// Parse an operator-supplied `--target` override.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "STUN" | "WEBRTC" | "WEBRTC_STUN" => Some(Self::Stun),
            "QUIC" => Some(Self::Quic),
            _ => None,
        }
    }

    /// nDPI protocol name a converged flow must classify as.
    pub fn ndpi_name(&self) -> &'static str {
        match self {
            Self::Stun => "STUN",
            Self::Quic => "QUIC",
        }
    }

    /// Byte offset inside the header at which the 8-byte resonance tag is embedded
    /// when the `embed` gene is on. Chosen to land in a clean carrier slot (STUN
    /// transaction-id, QUIC connection-id) so it never overwrites a protocol
    /// discriminator byte. `u16::MAX` selects the legacy tag-prefix layout.
    fn carrier_offset(&self) -> u16 {
        match self {
            // After type(2) + length(2) + magic(4): the 12-byte transaction id.
            Self::Stun => 8,
            // After byte0(1) + version(4) + dcid_len(1): the connection id.
            Self::Quic => 6,
        }
    }

    /// Length of the synthetic header template (nominal protocol header size).
    fn header_len(&self) -> usize {
        match self {
            Self::Stun => 20,
            Self::Quic => 14,
        }
    }
}

/// A genome: five boolean genes over the mask's observable shape. Each is a
/// bounded, structurally-real edit — never a change to crypto or session
/// semantics. Mirrors `research/mask-generation/r2/adv_loop.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Genome {
    /// Embedded tag layout (protocol header at wire offset 0) vs legacy
    /// tag-prefix (header shoved 8 bytes in, where nDPI never looks). The single
    /// most impactful gene — R1 proved the legacy layout forces `Unknown`.
    pub embed: bool,
    /// Correct protocol type/first-byte at offset 0 (STUN `00 01` / QUIC `0xC0`).
    pub proto_type: bool,
    /// Protocol magic present (STUN magic cookie `21 12 A4 42` / QUIC version).
    pub magic: bool,
    /// Split the id field so a clean tag-carrier slot exists.
    pub id_split: bool,
    /// Protocol-plausible size envelope (replaces the learned size distribution).
    pub sizes: bool,
}

impl Genome {
    /// The deliberately-broken start used for demos/tests: every
    /// protocol-plausibility gene off → nDPI `Unknown`.
    pub fn all_off() -> Self {
        Self {
            embed: false,
            proto_type: false,
            magic: false,
            id_split: false,
            sizes: false,
        }
    }

    /// Compact `[etmis]`-style tag of the enabled genes, for the score-curve log.
    pub fn tag(&self) -> String {
        let mut s = String::new();
        if self.embed {
            s.push('e');
        }
        if self.proto_type {
            s.push('t');
        }
        if self.magic {
            s.push('m');
        }
        if self.id_split {
            s.push('i');
        }
        if self.sizes {
            s.push('s');
        }
        if s.is_empty() {
            s.push('-');
        }
        s
    }

    fn gene_mut(&mut self, idx: usize) -> &mut bool {
        match idx {
            0 => &mut self.embed,
            1 => &mut self.proto_type,
            2 => &mut self.magic,
            3 => &mut self.id_split,
            _ => &mut self.sizes,
        }
    }
}

/// Seed a genome from a base mask's *current* observable state, so the loop
/// continues repairing from where the mask is rather than from scratch. Header
/// genes are detected conservatively; `sizes` starts off (the climb decides).
pub fn seed_genome(base: &MaskProfile, target: TargetProto) -> Genome {
    let mut g = Genome::all_off();
    g.embed = base.embedded_tag_offset().is_some();
    if let Some(HeaderSpec::Structured { fields }) = &base.header_spec {
        let type_bytes: &[u8] = match target {
            TargetProto::Stun => &[0x00, 0x01],
            TargetProto::Quic => &[0xC0],
        };
        let magic_bytes: &[u8] = match target {
            TargetProto::Stun => &[0x21, 0x12, 0xA4, 0x42],
            TargetProto::Quic => &[0x00, 0x00, 0x00, 0x01],
        };
        let fixed = |bytes: &[u8]| -> bool {
            fields.iter().any(|f| match f {
                HeaderField::Fixed { bytes: b } => b.as_slice() == bytes,
                _ => false,
            })
        };
        if let Some(HeaderField::Fixed { bytes }) = fields
            .iter()
            .find(|f| matches!(f, HeaderField::Fixed { .. }))
        {
            g.proto_type = bytes.as_slice() == type_bytes;
        }
        g.magic = fixed(magic_bytes);
        g.id_split = fields
            .iter()
            .filter(|f| matches!(f, HeaderField::Id { .. }))
            .count()
            >= 2;
    }
    g
}

/// Realise a genome as a concrete `MaskProfile` by cloning the base mask and
/// overwriting only its observable-shape fields. All learned distributions
/// (`size_iat_joint`, `fsm_states`, `signature_vector`, `iat_distribution`) are
/// preserved; the embedded signature is zeroed (the repaired profile must be
/// re-signed downstream).
pub fn realize(base: &MaskProfile, target: TargetProto, g: &Genome) -> MaskProfile {
    let mut m = base.clone();
    m.tag_offset = if g.embed {
        target.carrier_offset()
    } else {
        u16::MAX
    };
    m.header_spec = Some(HeaderSpec::Structured {
        fields: assemble_fields(target, g),
    });
    m.header_template = vec![0u8; target.header_len()];
    if g.sizes {
        m.size_distribution = plausible_sizes(target);
    }
    // The profile changed — any prior signature is now invalid. Re-signing is the
    // signing pipeline's job (Phase B), never the repair loop's.
    m.signature = [0u8; 64];
    m
}

/// Assemble the header field list for a target protocol from a genome. Only
/// structurally-real protocol bytes are emitted; a gene being off substitutes a
/// deliberately-wrong placeholder (so the flow reads as `Unknown`, not a
/// different real protocol).
fn assemble_fields(target: TargetProto, g: &Genome) -> Vec<HeaderField> {
    match target {
        TargetProto::Stun => {
            let mut fields = vec![
                HeaderField::Fixed {
                    bytes: if g.proto_type {
                        vec![0x00, 0x01] // STUN Binding Request
                    } else {
                        vec![0x59, 0x41] // wrong type
                    },
                },
                HeaderField::Length {
                    len: 2,
                    endian: HeaderEndian::Big,
                },
                HeaderField::Fixed {
                    bytes: if g.magic {
                        vec![0x21, 0x12, 0xA4, 0x42] // magic cookie
                    } else {
                        vec![0xDE, 0xAD, 0xBE, 0xEF]
                    },
                },
            ];
            if g.id_split {
                fields.push(HeaderField::Id {
                    len: 8,
                    mode: IdFieldMode::Random,
                });
                fields.push(HeaderField::Id {
                    len: 4,
                    mode: IdFieldMode::Random,
                });
            } else {
                fields.push(HeaderField::Id {
                    len: 12,
                    mode: IdFieldMode::Random,
                });
            }
            fields
        }
        TargetProto::Quic => {
            let mut fields = vec![
                HeaderField::Fixed {
                    bytes: if g.proto_type {
                        vec![0xC0] // long-header, fixed bit set
                    } else {
                        vec![0x40] // short-header form
                    },
                },
                HeaderField::Fixed {
                    bytes: if g.magic {
                        vec![0x00, 0x00, 0x00, 0x01] // QUIC v1
                    } else {
                        vec![0x00, 0x00, 0x00, 0x00] // version negotiation-ish
                    },
                },
                HeaderField::Fixed { bytes: vec![0x08] }, // dcid_len
            ];
            if g.id_split {
                fields.push(HeaderField::Id {
                    len: 4,
                    mode: IdFieldMode::Random,
                });
                fields.push(HeaderField::Id {
                    len: 4,
                    mode: IdFieldMode::Random,
                });
            } else {
                fields.push(HeaderField::Id {
                    len: 8,
                    mode: IdFieldMode::Random,
                });
            }
            fields
        }
    }
}

/// Protocol-plausible size histogram used when the `sizes` gene is on.
fn plausible_sizes(target: TargetProto) -> SizeDistribution {
    let bins = match target {
        // WebRTC/STUN control + small media: mostly small packets.
        TargetProto::Stun => vec![(64, 160, 0.6), (160, 300, 0.3), (300, 512, 0.1)],
        // QUIC bulk: a large-MTU mode plus small ack/handshake packets.
        TargetProto::Quic => vec![(1200, 1350, 0.5), (64, 200, 0.3), (300, 700, 0.2)],
    };
    SizeDistribution {
        dist_type: SizeDistType::Histogram,
        bins,
        parametric_type: None,
        parametric_params: None,
    }
}

/// A DPI verdict on a synthesised flow, as returned by a [`Discriminator`].
#[derive(Debug, Clone)]
pub struct DpiVerdict {
    /// nDPI protocol name, e.g. `"STUN"`, `"QUIC"`, `"Unknown"`.
    pub proto: String,
    /// nDPI flagged the flow as a VPN/obfuscated tunnel (OpenVPN, WireGuard,
    /// Obfuscated, Tor, …). An instant reject regardless of `proto`.
    pub tunnel_risk: bool,
    /// Smooth wire-structure signal in `[0, 1]` toward the target protocol, used
    /// only to give the hill-climb a gradient before the final gene flips.
    pub structure_score: f64,
}

/// The offline authority. The binary implements this over `maskpcap` +
/// `ndpiReader`; tests implement a mock.
pub trait Discriminator {
    /// Synthesise the mask's flow and return the DPI verdict. Errors on tooling
    /// failure (missing/broken `maskpcap` or `ndpiReader`, unparsable output).
    fn evaluate(&mut self, mask: &MaskProfile) -> Result<DpiVerdict, RepairError>;
}

/// Errors from the repair loop and its discriminator.
#[derive(Debug)]
pub enum RepairError {
    /// The discriminator (nDPI tooling) failed.
    Discriminator(String),
}

impl std::fmt::Display for RepairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepairError::Discriminator(m) => write!(f, "discriminator error: {m}"),
        }
    }
}

impl std::error::Error for RepairError {}

/// Score a verdict against the target. Accept (`1.0`) iff nDPI classifies the
/// flow as the target protocol AND raises no tunnel risk — the exact R1 gate.
/// Otherwise a smooth partial in `[0, 0.6)` from the wire-structure signal, so
/// the search has a gradient instead of a flat zero until the last gene flips.
fn score(verdict: &DpiVerdict, target: TargetProto) -> (f64, bool) {
    let classified = verdict
        .proto
        .to_ascii_uppercase()
        .contains(target.ndpi_name());
    let accepted = classified && !verdict.tunnel_risk;
    if accepted {
        (1.0, true)
    } else {
        // Cap partial < 0.6 so a true accept (1.0) always dominates.
        (0.6 * verdict.structure_score.clamp(0.0, 1.0), false)
    }
}

/// One row of the score curve.
#[derive(Debug, Clone)]
pub struct CurvePoint {
    pub iter: usize,
    pub best_score: f64,
    pub proto: String,
    pub accepted: bool,
    pub genome: Genome,
}

/// Loop configuration.
#[derive(Debug, Clone, Copy)]
pub struct RepairConfig {
    /// Bounded iteration budget.
    pub max_iters: usize,
    /// Deterministic RNG seed — the same seed reproduces the same curve exactly.
    pub seed: u64,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            max_iters: 40,
            seed: 1,
        }
    }
}

/// Result of a repair run.
#[derive(Debug, Clone)]
pub struct RepairOutcome {
    /// The best mask found (converged or not). Only trust it if `converged`.
    pub mask: MaskProfile,
    /// Whether the mask earned its target-protocol classification.
    pub converged: bool,
    /// Iteration at which acceptance first occurred.
    pub converged_iter: Option<usize>,
    /// Final accepted genome / best genome.
    pub genome: Genome,
    /// The full score curve, one row per iteration (index 0 = start).
    pub curve: Vec<CurvePoint>,
}

fn mutate(genome: &Genome, rng: &mut StdRng) -> Genome {
    let mut g = *genome;
    let idx = rng.gen_range(0..5);
    let gene = g.gene_mut(idx);
    *gene = !*gene;
    g
}

/// Run the bounded, deterministic hill-climbing repair loop.
///
/// Starting from a genome seeded off the base mask's current shape, each
/// iteration flips one gene, re-scores against the discriminator, and keeps the
/// mutation iff the score does not decrease (classic hill-climb, accepting equal
/// moves so the search can traverse plateaus). Stops on the first accept or after
/// `max_iters`. Never mutates crypto/session state.
pub fn repair(
    base: &MaskProfile,
    target: TargetProto,
    cfg: RepairConfig,
    disc: &mut dyn Discriminator,
) -> Result<RepairOutcome, RepairError> {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    let mut cur = seed_genome(base, target);
    let mut cur_verdict = disc.evaluate(&realize(base, target, &cur))?;
    let (mut cur_score, mut cur_acc) = score(&cur_verdict, target);

    let mut curve = vec![CurvePoint {
        iter: 0,
        best_score: cur_score,
        proto: cur_verdict.proto.clone(),
        accepted: cur_acc,
        genome: cur,
    }];

    let mut converged_iter = if cur_acc { Some(0) } else { None };

    if !cur_acc {
        for it in 1..=cfg.max_iters {
            let cand = mutate(&cur, &mut rng);
            let verdict = disc.evaluate(&realize(base, target, &cand))?;
            let (s, acc) = score(&verdict, target);
            if s >= cur_score {
                cur = cand;
                cur_score = s;
                cur_acc = acc;
                cur_verdict = verdict;
            }
            curve.push(CurvePoint {
                iter: it,
                best_score: cur_score,
                proto: cur_verdict.proto.clone(),
                accepted: cur_acc,
                genome: cur,
            });
            if cur_acc {
                converged_iter = Some(it);
                break;
            }
        }
    }

    Ok(RepairOutcome {
        mask: realize(base, target, &cur),
        converged: cur_acc,
        converged_iter,
        genome: cur,
        curve,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::mask::{IATDistType, IATDistribution, PaddingStrategy};

    /// Minimal base mask standing in for a gate-failing generated STUN mask.
    fn broken_stun_base() -> MaskProfile {
        MaskProfile {
            mask_id: "test_broken".into(),
            version: 1,
            created_at: 0,
            expires_at: 0,
            spoof_protocol: SpoofProtocol::WebRTC_STUN,
            header_template: vec![0u8; 8],
            eph_pub_offset: 0,
            eph_pub_length: 0,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![(64, 1400, 1.0)],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Exponential,
                params: vec![0.05],
                jitter_range_ms: (0.0, 0.0),
            },
            size_iat_joint: None,
            padding_strategy: PaddingStrategy::MatchDistribution,
            fsm_states: vec![],
            fsm_initial_state: 0,
            signature_vector: vec![0.1, 0.2, 0.3],
            reverse_profile: None,
            signature: [0u8; 64],
            header_spec: None,
            perturbation_bounds: None,
            tag_offset: u16::MAX, // legacy layout — the broken state
            generated: true,
        }
    }

    /// Mock discriminator reproducing nDPI's `is_stun()` predicate structurally:
    /// STUN iff the tag layout is embedded (header at wire offset 0), the first
    /// Fixed field is the STUN type, and a Fixed field carries the magic cookie.
    /// Otherwise `Unknown` with a graded structure score for the hill-climb.
    struct MockStunNdpi;

    impl MockStunNdpi {
        fn inspect(mask: &MaskProfile) -> (bool, bool, bool) {
            let embed = mask.embedded_tag_offset().is_some();
            let mut type_ok = false;
            let mut magic_ok = false;
            if let Some(HeaderSpec::Structured { fields }) = &mask.header_spec {
                let fixed: Vec<&[u8]> = fields
                    .iter()
                    .filter_map(|f| match f {
                        HeaderField::Fixed { bytes } => Some(bytes.as_slice()),
                        _ => None,
                    })
                    .collect();
                if let Some(first) = fixed.first() {
                    type_ok = *first == [0x00, 0x01];
                }
                magic_ok = fixed.iter().any(|b| *b == [0x21, 0x12, 0xA4, 0x42]);
            }
            (embed, type_ok, magic_ok)
        }
    }

    impl Discriminator for MockStunNdpi {
        fn evaluate(&mut self, mask: &MaskProfile) -> Result<DpiVerdict, RepairError> {
            let (embed, type_ok, magic_ok) = Self::inspect(mask);
            // In legacy layout the header never reaches wire offset 0, so nDPI
            // sees no STUN structure at all.
            if embed && type_ok && magic_ok {
                Ok(DpiVerdict {
                    proto: "STUN".into(),
                    tunnel_risk: false,
                    structure_score: 1.0,
                })
            } else {
                let s = if embed {
                    0.5 * (type_ok as u8 as f64) + 0.5 * (magic_ok as u8 as f64)
                } else {
                    0.0
                };
                Ok(DpiVerdict {
                    proto: "Unknown".into(),
                    tunnel_risk: false,
                    structure_score: s,
                })
            }
        }
    }

    #[test]
    fn score_accepts_target_and_rejects_tunnel() {
        let ok = DpiVerdict {
            proto: "STUN".into(),
            tunnel_risk: false,
            structure_score: 0.0,
        };
        assert_eq!(score(&ok, TargetProto::Stun), (1.0, true));

        // Tunnel risk vetoes even a target classification.
        let risky = DpiVerdict {
            proto: "STUN".into(),
            tunnel_risk: true,
            structure_score: 1.0,
        };
        let (s, acc) = score(&risky, TargetProto::Stun);
        assert!(!acc);
        assert!(s <= 0.6, "partial must never reach the accept score");

        // Partial is always dominated by a real accept.
        let partial = DpiVerdict {
            proto: "Unknown".into(),
            tunnel_risk: false,
            structure_score: 1.0,
        };
        let (s, acc) = score(&partial, TargetProto::Stun);
        assert!(!acc);
        assert!(s < 1.0);
    }

    #[test]
    fn realize_preserves_learned_fields_and_zeroes_signature() {
        let mut base = broken_stun_base();
        base.signature = [7u8; 64];
        base.signature_vector = vec![0.9, 0.8];
        let g = Genome {
            embed: true,
            proto_type: true,
            magic: true,
            id_split: true,
            sizes: true,
        };
        let m = realize(&base, TargetProto::Stun, &g);
        // Observable shape rewritten.
        assert_eq!(m.tag_offset, 8);
        assert!(matches!(m.header_spec, Some(HeaderSpec::Structured { .. })));
        // Learned fields preserved.
        assert_eq!(m.signature_vector, vec![0.9, 0.8]);
        assert_eq!(m.spoof_protocol, SpoofProtocol::WebRTC_STUN);
        // Signature invalidated for re-signing.
        assert_eq!(m.signature, [0u8; 64]);
    }

    #[test]
    fn loop_converges_broken_stun_mask() {
        let base = broken_stun_base();
        let mut disc = MockStunNdpi;
        let outcome = repair(
            &base,
            TargetProto::Stun,
            RepairConfig {
                max_iters: 60,
                seed: 1,
            },
            &mut disc,
        )
        .expect("discriminator ok");

        assert!(outcome.converged, "loop must converge the broken mask");
        assert!(outcome.converged_iter.is_some());
        // Converged mask actually passes the discriminator.
        let final_verdict = MockStunNdpi.evaluate(&outcome.mask).unwrap();
        assert_eq!(final_verdict.proto, "STUN");
        assert_eq!(outcome.mask.tag_offset, 8);

        // Score curve is monotonically non-decreasing (hill-climb invariant).
        for w in outcome.curve.windows(2) {
            assert!(
                w[1].best_score >= w[0].best_score - 1e-9,
                "best_score must never decrease: {} -> {}",
                w[0].best_score,
                w[1].best_score
            );
        }
        // Final row is the accept.
        assert!(outcome.curve.last().unwrap().accepted);
    }

    #[test]
    fn loop_is_deterministic_per_seed() {
        let base = broken_stun_base();
        let run = |seed| {
            let mut disc = MockStunNdpi;
            repair(
                &base,
                TargetProto::Stun,
                RepairConfig {
                    max_iters: 60,
                    seed,
                },
                &mut disc,
            )
            .unwrap()
            .converged_iter
        };
        assert_eq!(run(1), run(1), "same seed => same convergence iteration");
    }
}
