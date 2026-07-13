//! `aivpn-mask-repair` — offline adversarial mask-repair operator tool (R2 Phase C).
//!
//! Input a gate-FAILING generated mask JSON, output a gated (nDPI-passing) mask
//! JSON. Drives the bounded, deterministic hill-climbing loop in
//! [`aivpn_server::mask_repair`], using the real nDPI eval-gate as the
//! discriminator: for each candidate it synthesises the mask's uplink flow with
//! `maskpcap` (the exact `MimicryEngine::build_packet` client path) and classifies
//! it with `ndpiReader -d`.
//!
//! Fully offline: no network, no runtime/client impact. It sits in the signing
//! pipeline *after* `mask_gen` and *before* `MaskProfile::sign` — a repaired mask
//! is emitted with its embedded signature zeroed and must be re-signed downstream.
//!
//! Exit codes:
//!   0  converged — output mask passes the nDPI gate (written to <output>)
//!   1  did not converge within the iteration budget (no output written)
//!   2  usage / tooling error (bad args, missing maskpcap/ndpiReader, parse fail)
//!
//! Usage:
//!   aivpn-mask-repair --input broken.json --output repaired.json \
//!       [--target STUN|QUIC] [--max-iters N] [--seed S] [--packets N] \
//!       [--maskpcap PATH] [--ndpi PATH]
//!
//! `--maskpcap` / `--ndpi` default to the `AIVPN_MASKPCAP` / `AIVPN_NDPIREADER`
//! environment variables. The target defaults to the mask's own `spoof_protocol`.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use aivpn_common::mask::MaskProfile;
use aivpn_server::mask_repair::{
    repair, Discriminator, DpiVerdict, RepairConfig, RepairError, TargetProto,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "aivpn-mask-repair",
    about = "Offline adversarial repair of a DPI-gate-failing mask (R2 Phase C)"
)]
struct Args {
    /// Gate-FAILING input mask JSON.
    #[arg(long)]
    input: PathBuf,

    /// Output path for the gated (nDPI-passing) mask JSON.
    #[arg(long)]
    output: PathBuf,

    /// Target protocol (STUN or QUIC). Defaults to the mask's spoof_protocol.
    #[arg(long)]
    target: Option<String>,

    /// Bounded iteration budget.
    #[arg(long, default_value_t = 40)]
    max_iters: usize,

    /// Deterministic RNG seed (same seed => same score curve).
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// Packets synthesised per candidate flow.
    #[arg(long, default_value_t = 120)]
    packets: usize,

    /// Path to the `maskpcap` binary (env: AIVPN_MASKPCAP).
    #[arg(long, env = "AIVPN_MASKPCAP")]
    maskpcap: Option<PathBuf>,

    /// Path to the `ndpiReader` binary (env: AIVPN_NDPIREADER).
    #[arg(long, env = "AIVPN_NDPIREADER")]
    ndpi: Option<PathBuf>,
}

/// Real nDPI discriminator: `maskpcap` (client build path) → `ndpiReader -d`.
struct NdpiDiscriminator {
    maskpcap: PathBuf,
    ndpi: PathBuf,
    target: TargetProto,
    packets: usize,
}

impl NdpiDiscriminator {
    /// Parse `[proto: N/NAME]` and tunnel-risk keywords from ndpiReader output.
    fn parse_ndpi(out: &str) -> (String, bool) {
        let proto = out
            .split("[proto: ")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .and_then(|inner| inner.split('/').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let up = out.to_ascii_uppercase();
        let tunnel_risk = [
            "OPENVPN",
            "WIREGUARD",
            "OBFUSCATED",
            "TOR",
            "ANONYMOUS SUBSCRIBER",
        ]
        .iter()
        .any(|k| up.contains(k));
        (proto, tunnel_risk)
    }

    /// Extract UDP payloads from a LINKTYPE_ETHERNET pcap (14 eth + 20 ip + 8 udp).
    fn pcap_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
        const GLOBAL: usize = 24;
        const REC: usize = 16;
        const L2L3L4: usize = 14 + 20 + 8;
        let mut out = Vec::new();
        if bytes.len() < GLOBAL {
            return out;
        }
        let mut off = GLOBAL;
        while off + REC <= bytes.len() {
            let incl = u32::from_le_bytes([
                bytes[off + 8],
                bytes[off + 9],
                bytes[off + 10],
                bytes[off + 11],
            ]) as usize;
            off += REC;
            if off + incl > bytes.len() {
                break;
            }
            let frame = &bytes[off..off + incl];
            if frame.len() > L2L3L4 {
                out.push(frame[L2L3L4..].to_vec());
            }
            off += incl;
        }
        out
    }

    /// Smooth wire-structure signal toward the target, in `[0,1]`.
    fn structure_score(&self, payloads: &[Vec<u8>]) -> f64 {
        if payloads.is_empty() {
            return 0.0;
        }
        let n = payloads.len() as f64;
        match self.target {
            TargetProto::Stun => {
                let type_ok = payloads
                    .iter()
                    .filter(|p| p.len() >= 2 && p[0] == 0x00 && p[1] == 0x01)
                    .count() as f64
                    / n;
                let magic_ok = payloads
                    .iter()
                    .filter(|p| p.len() >= 8 && p[4..8] == [0x21, 0x12, 0xA4, 0x42])
                    .count() as f64
                    / n;
                let len_ok = payloads
                    .iter()
                    .filter(|p| {
                        p.len() >= 4 && ((p[2] as usize) << 8 | p[3] as usize) + 20 == p.len()
                    })
                    .count() as f64
                    / n;
                0.34 * type_ok + 0.33 * magic_ok + 0.33 * len_ok
            }
            TargetProto::Quic => {
                let longform = payloads
                    .iter()
                    .filter(|p| !p.is_empty() && (p[0] & 0xC0) == 0xC0)
                    .count() as f64
                    / n;
                let version_ok = payloads
                    .iter()
                    .filter(|p| p.len() >= 5 && p[1..5] == [0x00, 0x00, 0x00, 0x01])
                    .count() as f64
                    / n;
                0.5 * longform + 0.5 * version_ok
            }
        }
    }
}

impl Discriminator for NdpiDiscriminator {
    fn evaluate(&mut self, mask: &MaskProfile) -> Result<DpiVerdict, RepairError> {
        let json = serde_json::to_string(mask)
            .map_err(|e| RepairError::Discriminator(format!("serialize mask: {e}")))?;
        let dir = std::env::temp_dir();
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let mask_path = dir.join(format!("aivpn-repair-{stamp}.json"));
        let pcap_path = dir.join(format!("aivpn-repair-{stamp}.pcap"));

        let result = (|| {
            std::fs::write(&mask_path, &json)
                .map_err(|e| RepairError::Discriminator(format!("write temp mask: {e}")))?;

            let synth = Command::new(&self.maskpcap)
                .arg(&mask_path)
                .arg(&pcap_path)
                .arg(self.packets.to_string())
                .output()
                .map_err(|e| {
                    RepairError::Discriminator(format!(
                        "run maskpcap ({}): {e}",
                        self.maskpcap.display()
                    ))
                })?;
            if !synth.status.success() {
                return Err(RepairError::Discriminator(format!(
                    "maskpcap failed: {}",
                    String::from_utf8_lossy(&synth.stderr)
                )));
            }

            let ndpi = Command::new(&self.ndpi)
                .args(["-i"])
                .arg(&pcap_path)
                .args(["-d", "-v", "2"])
                .output()
                .map_err(|e| {
                    RepairError::Discriminator(format!(
                        "run ndpiReader ({}): {e}",
                        self.ndpi.display()
                    ))
                })?;
            let out = format!(
                "{}{}",
                String::from_utf8_lossy(&ndpi.stdout),
                String::from_utf8_lossy(&ndpi.stderr)
            );
            let (proto, tunnel_risk) = Self::parse_ndpi(&out);

            let pcap_bytes = std::fs::read(&pcap_path)
                .map_err(|e| RepairError::Discriminator(format!("read pcap: {e}")))?;
            let payloads = Self::pcap_payloads(&pcap_bytes);
            let structure_score = self.structure_score(&payloads);

            Ok(DpiVerdict {
                proto,
                tunnel_risk,
                structure_score,
            })
        })();

        let _ = std::fs::remove_file(&mask_path);
        let _ = std::fs::remove_file(&pcap_path);
        result
    }
}

fn run() -> Result<(), (u8, String)> {
    let args = Args::parse();

    let maskpcap = args
        .maskpcap
        .ok_or((2, "missing --maskpcap (or AIVPN_MASKPCAP)".to_string()))?;
    let ndpi = args
        .ndpi
        .ok_or((2, "missing --ndpi (or AIVPN_NDPIREADER)".to_string()))?;
    if !maskpcap.exists() {
        return Err((2, format!("maskpcap not found: {}", maskpcap.display())));
    }
    if !ndpi.exists() {
        return Err((2, format!("ndpiReader not found: {}", ndpi.display())));
    }

    let json = std::fs::read_to_string(&args.input)
        .map_err(|e| (2, format!("read input {}: {e}", args.input.display())))?;
    let base: MaskProfile =
        serde_json::from_str(&json).map_err(|e| (2, format!("parse input mask: {e}")))?;

    let target = match &args.target {
        Some(s) => TargetProto::parse(s).ok_or((2, format!("unknown --target '{s}'")))?,
        None => TargetProto::from_spoof(&base.spoof_protocol).ok_or((
            2,
            format!(
                "mask spoof_protocol {:?} has no structural gate target; pass --target",
                base.spoof_protocol
            ),
        ))?,
    };

    eprintln!(
        "aivpn-mask-repair: input={} target={} max_iters={} seed={} packets={}",
        args.input.display(),
        target.ndpi_name(),
        args.max_iters,
        args.seed,
        args.packets
    );

    let mut disc = NdpiDiscriminator {
        maskpcap,
        ndpi,
        target,
        packets: args.packets,
    };
    let cfg = RepairConfig {
        max_iters: args.max_iters,
        seed: args.seed,
    };

    let outcome = repair(&base, target, cfg, &mut disc).map_err(|e| (2, e.to_string()))?;

    eprintln!("\niter  best_score  nDPI        accepted  genome");
    for c in &outcome.curve {
        eprintln!(
            "{:>3}   {:.3}       {:<10}  {:<8}  [{}]",
            c.iter,
            c.best_score,
            c.proto,
            c.accepted,
            c.genome.tag()
        );
    }

    if !outcome.converged {
        return Err((
            1,
            format!(
                "did NOT converge in {} iters (best_score {:.3}); no mask written",
                args.max_iters,
                outcome.curve.last().map(|c| c.best_score).unwrap_or(0.0)
            ),
        ));
    }

    let out_json = serde_json::to_string_pretty(&outcome.mask)
        .map_err(|e| (2, format!("serialize repaired mask: {e}")))?;
    std::fs::write(&args.output, out_json)
        .map_err(|e| (2, format!("write output {}: {e}", args.output.display())))?;

    eprintln!(
        "\nCONVERGED at iter {} -> nDPI {} — wrote {} (UNSIGNED; re-sign in the pipeline)",
        outcome.converged_iter.unwrap_or(0),
        target.ndpi_name(),
        args.output.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err((code, msg)) => {
            eprintln!("aivpn-mask-repair: {msg}");
            ExitCode::from(code)
        }
    }
}
