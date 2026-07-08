//! Integration test for the client-side half of the §2 "crowdsourced
//! blocking feedback" loop: `aivpn_client::mask_feedback_log`
//! (`MaskFeedbackLog`, `RegionalHintsStore`) plus
//! `aivpn_client::client::base_mask_family`, which collapses per-session
//! mask ids to a stable family id before anything is logged.
//!
//! The VPN client is recreated on every reconnect (see `main.rs`), so this
//! test specifically exercises the "log/store survives being dropped and
//! reloaded from disk" property, using real temp-directory persistence
//! rather than mocking the filesystem — but never touches real UDP/TUN.
//!
//! `AivpnClient`'s internals (the `feedback_log` / `regional_mask_hints`
//! fields and `handle_server_control`) are private to `aivpn-client`, so this
//! test drives the same public sequence those internals call into
//! (`RegionalHintsStore::load` + `::set_region`, mirroring the
//! `ControlPayload::RegionalMaskHints` arm in `client.rs`) instead of
//! reaching into the client struct itself. Only public APIs are used; no
//! source files were modified to support this test.

use aivpn_client::client::base_mask_family;
use aivpn_client::mask_feedback_log::{
    MaskFeedbackLog, RegionalHintsStore, DEFAULT_FAILURE_THRESHOLD, DEFAULT_REPORT_INTERVAL_SECS,
    MAX_ENTRIES,
};
use aivpn_common::mask::preset_masks;
use aivpn_common::protocol::ControlPayload;

/// Unique per-test temp file path, mirroring the pattern already used by
/// `mask_feedback_log`'s own unit tests (`std::env::temp_dir()` +
/// process id + tag) — this test binary runs in its own process, so there is
/// no collision with the unit-test binary's files.
fn temp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "aivpn_mask_feedback_loop_it_{}_{}.json",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// `base_mask_family` must collapse both dynamic id shapes clients actually
/// send on the wire (`bootstrap:{desc}:{base}:{slot}:{seed}` and
/// `polymorphic:{base}:{hex}`) down to the same stable family id, and must
/// pass a plain preset id through unchanged. This is the seam between raw
/// per-session mask ids and what `MaskFeedbackLog` is allowed to persist.
#[test]
fn base_mask_family_collapses_dynamic_ids_before_anything_is_logged() {
    assert_eq!(
        base_mask_family("bootstrap:desc123:webrtc_zoom_v3:2:abcdef01"),
        "webrtc_zoom_v3"
    );
    assert_eq!(
        base_mask_family("polymorphic:quic_https_v2:a1b2c3d4"),
        "quic_https_v2"
    );
    assert_eq!(base_mask_family("webrtc_zoom_v3"), "webrtc_zoom_v3");

    // Two different per-session variants of the SAME base family must
    // collapse to one identical key, or the server-side k-anonymity buckets
    // would fragment into unusable singletons.
    let a = base_mask_family("bootstrap:descAAA:webrtc_zoom_v3:0:seed1");
    let b = base_mask_family("bootstrap:descBBB:webrtc_zoom_v3:5:seed2");
    assert_eq!(a, b);
    assert_eq!(a, "webrtc_zoom_v3");
}

/// Full record→persist→reload→aggregate cycle, simulating a realistic
/// sequence of reconnect attempts: a mask family that gets blocked twice
/// then eventually succeeds (via a polymorphic variant), and a different
/// family that fails once. The client process is recreated between attempts
/// in reality (a fresh `MaskFeedbackLog::load_default()` per reconnect
/// iteration), so this test reloads from disk between every `append` to
/// prove the log is not relying on in-memory state surviving a "restart".
#[test]
fn realistic_reconnect_sequence_records_and_persists_success_and_failure_per_family() {
    let path = temp_path("reconnect_sequence");

    // Attempt 1: webrtc_zoom_v3 (via a bootstrap descriptor variant) is
    // blocked.
    {
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append(
            base_mask_family("bootstrap:desc1:webrtc_zoom_v3:0:seedA"),
            false,
        );
    }
    // Attempt 2 (fresh instance, as after a real reconnect): still blocked,
    // this time via a different bootstrap slot/seed for the same family.
    {
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append(
            base_mask_family("bootstrap:desc1:webrtc_zoom_v3:3:seedB"),
            false,
        );
    }
    // Attempt 3: client falls back to quic_https_v2, which also fails once.
    {
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append(base_mask_family("quic_https_v2"), false);
    }
    // Attempt 4: a polymorphic variant of webrtc_zoom_v3 finally succeeds.
    {
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append(
            base_mask_family("polymorphic:webrtc_zoom_v3:deadbeef"),
            true,
        );
    }

    // One more fresh instance, as the eventual §2 reporting call would use.
    let log = MaskFeedbackLog::load(path.clone());
    assert_eq!(
        log.len(),
        4,
        "all 4 attempts across 4 separate instances must have persisted"
    );
    assert!(log.has_unreported());

    let mut outcomes = log.aggregate_unreported();
    outcomes.sort_by(|a, b| a.mask_id.cmp(&b.mask_id));
    assert_eq!(
        outcomes.len(),
        2,
        "two distinct families should be aggregated"
    );

    let zoom = outcomes
        .iter()
        .find(|o| o.mask_id == "webrtc_zoom_v3")
        .expect("webrtc_zoom_v3 family must be present");
    assert_eq!(zoom.success, 1, "one eventual success");
    assert_eq!(zoom.fail, 2, "two prior blocked attempts");

    let quic = outcomes
        .iter()
        .find(|o| o.mask_id == "quic_https_v2")
        .expect("quic_https_v2 family must be present");
    assert_eq!(quic.success, 0);
    assert_eq!(quic.fail, 1);

    let _ = std::fs::remove_file(&path);
}

/// `mark_reported` must drain the buffered entries and persist that drained
/// state — a subsequent reload (simulating the next reconnect after a
/// successful §2 report) must not re-report already-sent outcomes.
#[test]
fn mark_reported_drains_entries_and_the_drain_persists_across_reload() {
    let path = temp_path("mark_reported_drain");

    let mut log = MaskFeedbackLog::load(path.clone());
    log.append("webrtc_zoom_v3".to_string(), true);
    log.append("quic_https_v2".to_string(), false);
    assert_eq!(log.len(), 2);

    // Injected timestamp — no real clock/sleep involved anywhere in this
    // test, keeping it deterministic.
    let send_time_unix = 1_700_000_000u64;
    log.mark_reported(send_time_unix);
    assert!(log.is_empty());
    assert!(!log.has_unreported());

    // Reload as a fresh instance: the drain must have persisted, not just
    // lived in the dropped instance's memory.
    let reloaded = MaskFeedbackLog::load(path.clone());
    assert!(
        reloaded.is_empty(),
        "drained state must survive a reload, or the same outcomes would be re-reported"
    );
    assert!(reloaded.aggregate_unreported().is_empty());

    let _ = std::fs::remove_file(&path);
}

/// `interval_elapsed` gates how often the reconnect loop is allowed to send
/// a §2 report. Entirely timestamp-injected (no sleeping) so the test is
/// deterministic: verifies the default interval, a server-pushed override
/// via `set_tuning`, and that the gate re-opens only once enough injected
/// time has passed since the last `mark_reported`.
#[test]
fn interval_elapsed_is_gated_by_injected_timestamps_not_by_sleeping() {
    let path = temp_path("interval_gating");
    let mut log = MaskFeedbackLog::load(path.clone());

    // Never reported yet (last_report_unix defaults to 0): far in the
    // future relative to unix epoch, so the default interval is already
    // satisfied immediately.
    assert_eq!(log.report_interval_secs(), DEFAULT_REPORT_INTERVAL_SECS);
    assert!(log.interval_elapsed(DEFAULT_REPORT_INTERVAL_SECS as u64));
    assert!(!log.interval_elapsed(DEFAULT_REPORT_INTERVAL_SECS as u64 - 1));

    let t0 = 2_000_000_000u64;
    log.mark_reported(t0);
    assert!(
        !log.interval_elapsed(t0 + 10),
        "only 10s elapsed, must not be allowed to report again yet"
    );
    assert!(
        log.interval_elapsed(t0 + DEFAULT_REPORT_INTERVAL_SECS as u64),
        "a full interval has elapsed, reporting must be allowed again"
    );

    // Server pushes a tighter interval (e.g. FeedbackConfig{report_interval_secs: 60}).
    log.set_tuning(DEFAULT_FAILURE_THRESHOLD, 60);
    assert_eq!(log.report_interval_secs(), 60);
    log.mark_reported(t0);
    assert!(!log.interval_elapsed(t0 + 59));
    assert!(log.interval_elapsed(t0 + 60));

    // A misconfigured server pushing interval=0 must not disable spacing
    // entirely — coerced back to the default.
    log.set_tuning(DEFAULT_FAILURE_THRESHOLD, 0);
    assert_eq!(log.report_interval_secs(), DEFAULT_REPORT_INTERVAL_SECS);

    let _ = std::fs::remove_file(&path);
}

/// The retained-entry cap (`MAX_ENTRIES`) must hold even across many
/// separate reload cycles (not just many `append`s within one instance),
/// since in reality each append happens on a freshly reloaded log.
#[test]
fn entry_cap_holds_across_many_reload_cycles() {
    let path = temp_path("cap_across_reloads");
    for i in 0..(MAX_ENTRIES + 20) {
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append(format!("mask-family-{i}"), true);
    }
    let log = MaskFeedbackLog::load(path.clone());
    assert_eq!(log.len(), MAX_ENTRIES);
    let outcomes = log.aggregate_unreported();
    assert!(
        outcomes.iter().all(|o| o.mask_id != "mask-family-0"),
        "oldest entries must have been evicted"
    );
    assert!(outcomes
        .iter()
        .any(|o| o.mask_id == format!("mask-family-{}", MAX_ENTRIES + 19)));
    let _ = std::fs::remove_file(&path);
}

/// §3-style seam, client side: build a `ControlPayload::RegionalMaskHints`
/// as the server would send it, round-trip it through the real wire codec,
/// then feed the *decoded* masks into `RegionalHintsStore::set_region` —
/// exactly the call `client.rs`'s `ControlPayload::RegionalMaskHints` arm
/// makes (`RegionalHintsStore::load_default(); store.set_region(country_code,
/// masks.clone())`), just using an explicit temp path instead of the real
/// per-user default path so the test stays hermetic. Confirms `for_region`
/// returns the hints sorted highest-score-first, which is what `main.rs`'s
/// reconnect loop relies on for its regional-hint mask bias.
#[test]
fn wire_decoded_regional_hints_persist_and_are_consumed_sorted_highest_first() {
    let path = temp_path("regional_hints_wire");
    let country = *b"DE";

    // As received from the server, deliberately in a non-sorted order.
    let payload = ControlPayload::RegionalMaskHints {
        country_code: country,
        masks: vec![
            ("quic_https_v2".to_string(), 0.55),
            ("webrtc_zoom_v3".to_string(), 0.92),
            ("webrtc_sberjazz_v1".to_string(), 0.30),
        ],
    };
    let bytes = payload.encode().expect("encode RegionalMaskHints");
    let (decoded_country, decoded_masks) =
        match ControlPayload::decode(&bytes).expect("decode RegionalMaskHints") {
            ControlPayload::RegionalMaskHints {
                country_code,
                masks,
            } => (country_code, masks),
            other => panic!("decoded into wrong ControlPayload variant: {other:?}"),
        };
    assert_eq!(decoded_country, country);

    // Mirrors the `ControlPayload::RegionalMaskHints` arm in client.rs.
    {
        let mut store = RegionalHintsStore::load(path.clone());
        store.set_region(decoded_country, decoded_masks);
    }

    // Fresh instance, as `main.rs`'s reconnect loop loads it one iteration
    // later on a brand-new client.
    let store = RegionalHintsStore::load(path.clone());
    let hints = store.for_region(country);
    assert_eq!(hints.len(), 3);
    assert_eq!(hints[0].0, "webrtc_zoom_v3");
    assert!((hints[0].1 - 0.92).abs() < f32::EPSILON);
    assert_eq!(hints[1].0, "quic_https_v2");
    assert_eq!(hints[2].0, "webrtc_sberjazz_v1");
    assert!(
        hints.windows(2).all(|w| w[0].1 >= w[1].1),
        "for_region must always return highest success rate first"
    );

    // Unknown region → no hints, never a panic.
    assert!(store.for_region(*b"ZZ").is_empty());

    let _ = std::fs::remove_file(&path);
}

/// `main.rs`'s regional-hint mask-selection bias
/// (`args.receive_mask_hints && ...`) lives in the binary, not the library,
/// so it is not reachable from this integration test. What IS reachable and
/// pure is exactly what that bias loop consumes: `RegionalHintsStore::
/// for_region`'s sorted output, plus `aivpn_common::mask::preset_masks::
/// by_id` to check "is this a known built-in preset". This test replicates
/// main.rs's documented selection rule (skip unknown/non-preset mask ids;
/// skip anything below the bias threshold; pick the first — i.e.
/// highest-scoring — remaining hit) using only those two public pieces, to
/// prove the *data* `for_region` hands back is exactly what that rule needs:
/// sorted so a simple first-match `find` is correct.
#[test]
fn regional_hints_sorted_output_is_correct_input_for_a_first_match_bias_rule() {
    let path = temp_path("regional_hints_bias_selection");
    let country = *b"BR";

    // Matches main.rs's private `HINT_BIAS_MIN_SCORE` constant (0.5) as of
    // this writing; duplicated here only because that constant is private to
    // the binary and not reachable from an integration test.
    const HINT_BIAS_MIN_SCORE: f32 = 0.5;

    {
        let mut store = RegionalHintsStore::load(path.clone());
        store.set_region(
            country,
            vec![
                // Highest score, but not a recognized built-in preset — must
                // be skipped by the bias rule.
                ("mystery_experimental_mask_v9".to_string(), 0.99),
                // Known preset, but below the bias threshold — must be
                // skipped too.
                ("quic_https_v2".to_string(), 0.40),
                // Known preset, at/above threshold — this is the one the
                // bias rule must land on.
                ("webrtc_zoom_v3".to_string(), 0.51),
            ],
        );
    }

    let store = RegionalHintsStore::load(path.clone());
    let hints = store.for_region(country);
    // Sorted highest-first, as guaranteed by `for_region`.
    assert_eq!(hints[0].0, "mystery_experimental_mask_v9");
    assert_eq!(hints[1].0, "webrtc_zoom_v3");
    assert_eq!(hints[2].0, "quic_https_v2");

    // Same `find_map` shape as main.rs's regional-hint bias branch.
    let biased = hints.into_iter().find_map(|(mask_id, score)| {
        if score < HINT_BIAS_MIN_SCORE {
            return None;
        }
        preset_masks::by_id(&mask_id).map(|m| (mask_id, score, m))
    });

    let (chosen_id, chosen_score, _mask) = biased.expect("bias rule must find a match");
    assert_eq!(
        chosen_id, "webrtc_zoom_v3",
        "must skip the unknown top-scoring id and the sub-threshold known preset"
    );
    assert!((chosen_score - 0.51).abs() < f32::EPSILON);

    let _ = std::fs::remove_file(&path);
}
