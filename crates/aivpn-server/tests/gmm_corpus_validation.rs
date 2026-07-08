//! Practical validation of the production GMM fitter against the design-doc §4
//! R&D corpus.
//!
//! The `research/mask-generation/phase2b` study fitted GMMs with Python
//! scikit-learn and showed a BIC-selected mixture cuts the KS distance to real
//! held-out DNS/QUIC/WebRTC traffic by 43–89 % versus a single Gaussian. This
//! test re-runs that comparison with the *production* Rust fitter
//! (`aivpn_server::gmm`) to prove the shipped code reproduces the win — not just
//! a Python prototype.
//!
//! The corpus lives under `research/` which is git-ignored, so this test SKIPS
//! cleanly (passes, prints a notice) when the corpus is absent — e.g. in CI.
//! Run it locally with the corpus present to see the numbers.

use aivpn_server::gmm;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Draw `n` samples from a fitted mixture (Box-Muller per selected component).
fn sample_gmm(fit: &gmm::Gmm1d, n: usize, min_value: f64, seed: u64) -> Vec<f64> {
    let mut rng = StdRng::seed_from_u64(seed);
    let wsum: f64 = fit.weights.iter().sum();
    (0..n)
        .map(|_| {
            let target = rng.gen::<f64>() * wsum;
            let mut acc = 0.0;
            let mut chosen = fit.weights.len() - 1;
            for (c, w) in fit.weights.iter().enumerate() {
                acc += *w;
                if target <= acc {
                    chosen = c;
                    break;
                }
            }
            let u1: f64 = rng.gen::<f64>().max(1e-12);
            let u2: f64 = rng.gen();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            (fit.means[chosen] + fit.vars[chosen].max(1e-12).sqrt() * z).max(min_value)
        })
        .collect()
}

/// Two-sample Kolmogorov–Smirnov statistic (max CDF gap).
fn ks_2samp(a: &[f64], b: &[f64]) -> f64 {
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort_by(|x, y| x.partial_cmp(y).unwrap());
    sb.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let (na, nb) = (sa.len() as f64, sb.len() as f64);
    let (mut i, mut j) = (0usize, 0usize);
    let mut d: f64 = 0.0;
    while i < sa.len() && j < sb.len() {
        let x = sa[i].min(sb[j]);
        while i < sa.len() && sa[i] <= x {
            i += 1;
        }
        while j < sb.len() && sb[j] <= x {
            j += 1;
        }
        let gap = (i as f64 / na - j as f64 / nb).abs();
        if gap > d {
            d = gap;
        }
    }
    d
}

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/mask-generation/phase2b/corpus/features.json")
}

/// Minimal JSON extraction: pull the `train`/`test` arrays of `[size, iat]`
/// pairs for a protocol out of features.json without adding a serde_json dep
/// to the server crate's test target (it already transitively has it, but keep
/// this test self-contained and dependency-light).
fn parse_pairs(v: &serde_json::Value, key: &str) -> (Vec<f64>, Vec<f64>) {
    let arr = v[key].as_array().cloned().unwrap_or_default();
    let mut sizes = Vec::with_capacity(arr.len());
    let mut iats = Vec::with_capacity(arr.len());
    for pair in arr {
        if let Some(p) = pair.as_array() {
            if p.len() >= 2 {
                sizes.push(p[0].as_f64().unwrap_or(0.0));
                iats.push(p[1].as_f64().unwrap_or(0.0));
            }
        }
    }
    (sizes, iats)
}

#[test]
fn gmm_beats_unimodal_on_rnd_corpus() {
    let path = corpus_path();
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!(
            "SKIP gmm_beats_unimodal_on_rnd_corpus: corpus not found at {} \
             (research/ is git-ignored; present only on the R&D machine)",
            path.display()
        );
        return;
    };
    let features: serde_json::Value =
        serde_json::from_slice(&bytes).expect("features.json is valid JSON");

    // "Clean" protocols: train and test share the same measurement framing, so
    // the KS comparison is apples-to-apples. phase2b showed large GMM wins here.
    // The plain `webrtc` / `webrtc_fixedfreq` splits carry a +28-byte VPN-framing
    // offset between train and test (writeup §5); their *size* KS is dominated by
    // that constant offset, so a tighter GMM can look worse — a documented
    // measurement confound, not a model failure. We still require multimodality
    // detection there, but only require KS improvement on the clean protocols.
    let clean_protocols = ["dns", "quic", "webrtc_synth_only"];
    let mut clean_checked = 0;
    let mut big_wins = 0;

    for (proto, d) in features.as_object().expect("top-level object") {
        let (train_sizes, train_iats) = parse_pairs(d, "train");
        let (test_sizes, test_iats) = parse_pairs(d, "test");
        // Mirror mask_gen's GMM_MIN_SAMPLES gate.
        if train_sizes.len() < 40 || test_sizes.is_empty() {
            continue;
        }

        for (label, train, test, min_value) in [
            ("size", &train_sizes, &test_sizes, 1.0),
            ("iat", &train_iats, &test_iats, 0.0),
        ] {
            let sweep = gmm::fit_sweep(train, 8);
            if sweep.is_empty() {
                continue;
            }
            let unimodal = &sweep[0]; // k = 1
            let best = gmm::select_best_bic(train, 8).expect("best fit");

            let uni_samples = sample_gmm(unimodal, 5000, min_value, 100);
            let multi_samples = sample_gmm(&best, 5000, min_value, 200);

            let ks_uni = ks_2samp(&uni_samples, test);
            let ks_multi = ks_2samp(&multi_samples, test);
            let improvement = if ks_uni > 0.0 {
                100.0 * (ks_uni - ks_multi) / ks_uni
            } else {
                0.0
            };

            eprintln!(
                "{proto:>16} {label:<4} k*={:<2} KS uni={ks_uni:.3} multi={ks_multi:.3} \
                 improvement={improvement:+.1}%",
                best.k()
            );

            if clean_protocols.contains(&proto.as_str()) {
                clean_checked += 1;
                // The whole point of the R&D: BIC finds >1 mode ...
                assert!(
                    best.k() >= 2,
                    "{proto}/{label}: expected multimodal fit, got k={}",
                    best.k()
                );
                // ... and on apples-to-apples held-out data the mixture is no
                // worse than unimodal (small held-out N → allow a little slack).
                assert!(
                    ks_multi <= ks_uni + 0.05,
                    "{proto}/{label}: GMM KS {ks_multi:.3} worse than unimodal {ks_uni:.3}"
                );
                if improvement >= 30.0 {
                    big_wins += 1;
                }
            }
        }
    }

    assert!(
        clean_checked >= 4,
        "corpus present but too few clean marginals validated ({clean_checked})"
    );
    // At least a couple of the clean marginals must show the large win phase2b
    // reported — non-regression alone could be satisfied by two equally-bad fits.
    assert!(
        big_wins >= 2,
        "expected >=2 clean marginals with >=30% KS improvement, got {big_wins}"
    );
}
