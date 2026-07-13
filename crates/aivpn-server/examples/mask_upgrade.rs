//! mask_upgrade — add R3 (size_iat_joint) + R4 (fsm_states) to an EXISTING mask.
//!
//! Part 3: the shipped bundled masks (assets/masks/*.json) carry no
//! `size_iat_joint` and only minimal hand-authored `fsm_states`, so clients get
//! no R3/R4 benefit. This tool fits R3 (joint 2-D size↔IAT GMM) and R4
//! (temporal-Markov FSM) from a real same-family corpus and writes them into the
//! mask, leaving `header_template`/`header_spec`/`spoof_protocol`/`tag_offset`
//! and the base `size_distribution` UNCHANGED — so nDPI still classifies the
//! mask and its data plane (which the base size distribution already drives) is
//! untouched. The R4 FSM is self-contained (each transition carries its own
//! `size_override`), so it bolts on regardless of the base distribution type.
//!
//! Usage:
//!   cargo run --release -p aivpn-server --example mask_upgrade -- \
//!     <mask.json> <corpus.pcap> <out.json>
//!
//! Prints R3/R4 result and a data-plane fitness line (the smallest packet size
//! the FSM overrides would target — a mask that shapes to tiny packets cannot
//! carry full-MTU tunnel data). Exit 0 on success, 2 on bad input.

use std::path::Path;

use aivpn_common::mask::MaskProfile;
use aivpn_server::mask_gen::{build_size_iat_joint, build_temporal_fsm};

/// Minimal libpcap reader → (orig_len, timestamp_ns) per record. RAW-IP / SLL /
/// Ethernet aware only for framing offset; we only need size + timestamp here.
fn read_pcap_sizes_iats(path: &Path) -> Result<(Vec<u16>, Vec<f64>), String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if data.len() < 24 {
        return Err("pcap shorter than global header".into());
    }
    let (be, nanos) = match &data[0..4] {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        m => return Err(format!("unknown pcap magic {m:02x?}")),
    };
    let rd32 = |b: &[u8]| -> u32 {
        if be {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let mut sizes = Vec::new();
    let mut iats = Vec::new();
    let mut prev_ns: Option<u64> = None;
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let ts_sec = rd32(&data[off..off + 4]) as u64;
        let ts_frac = rd32(&data[off + 4..off + 8]) as u64;
        let incl = rd32(&data[off + 8..off + 12]) as usize;
        let orig = rd32(&data[off + 12..off + 16]);
        off += 16;
        if off + incl > data.len() {
            break;
        }
        let ts_ns = ts_sec * 1_000_000_000 + if nanos { ts_frac } else { ts_frac * 1_000 };
        let iat_ms = match prev_ns {
            Some(p) if ts_ns >= p => (ts_ns - p) as f64 / 1_000_000.0,
            _ => 0.0,
        };
        prev_ns = Some(ts_ns);
        sizes.push(orig.min(u16::MAX as u32) as u16);
        iats.push(iat_ms);
        off += incl;
    }
    Ok((sizes, iats))
}

/// Smallest fixed/mean size any FSM-transition size_override would target — a
/// crude data-plane fitness probe (a mask that only ever targets tiny packets
/// cannot carry a full inner-MTU datagram efficiently).
fn min_override_size(mask: &MaskProfile) -> Option<u32> {
    let mut min: Option<u32> = None;
    for st in &mask.fsm_states {
        for tr in &st.transitions {
            if let Some(sd) = &tr.size_override {
                // Represent the override by its serialized min/mean where present.
                let v = serde_json::to_value(sd).unwrap_or(serde_json::Value::Null);
                for key in ["min", "mean", "max"] {
                    if let Some(n) = v.get(key).and_then(|x| x.as_f64()) {
                        let n = n as u32;
                        min = Some(min.map_or(n, |m| m.min(n)));
                    }
                }
            }
        }
    }
    min
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: mask_upgrade <mask.json> <corpus.pcap> <out.json>");
        std::process::exit(2);
    }
    let mask_path = Path::new(&args[1]);
    let corpus = Path::new(&args[2]);
    let out = &args[3];

    let raw = match std::fs::read_to_string(mask_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mask_upgrade: read {}: {e}", mask_path.display());
            std::process::exit(2);
        }
    };
    let mut mask: MaskProfile = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mask_upgrade: parse {}: {e}", mask_path.display());
            std::process::exit(2);
        }
    };

    let (sizes, iats) = match read_pcap_sizes_iats(corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mask_upgrade: {e}");
            std::process::exit(2);
        }
    };
    println!(
        "mask_upgrade: {} <- {} ({} corpus packets)",
        mask.mask_id,
        corpus.display(),
        sizes.len()
    );

    let r4_before = mask.fsm_states.len();
    let (fsm_states, fsm_initial) = build_temporal_fsm(&sizes, &iats);
    let r3 = build_size_iat_joint(&sizes, &iats);

    // Inject R3/R4 only — leave header/spoof/base size+iat distribution intact.
    mask.fsm_states = fsm_states;
    mask.fsm_initial_state = fsm_initial;
    let r3_present = r3.is_some();
    mask.size_iat_joint = r3;

    println!("R4_fsm_states: {} -> {}", r4_before, mask.fsm_states.len());
    println!("R3_size_iat_joint: {}", r3_present);
    match min_override_size(&mask) {
        Some(m) => println!(
            "data_plane_fitness: min FSM-override target size = {m} B{}",
            if m < 300 {
                "  ⚠ TINY — may not carry full-MTU data"
            } else {
                ""
            }
        ),
        None => {
            println!("data_plane_fitness: no size_override (base size_distribution drives sizing)")
        }
    }

    let serialized = match serde_json::to_string_pretty(&mask) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mask_upgrade: serialize: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = std::fs::write(out, serialized) {
        eprintln!("mask_upgrade: write {out}: {e}");
        std::process::exit(2);
    }
    println!("SAVED={out}");
}
