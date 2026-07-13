//! Integration test for the §2 "crowdsourced blocking feedback" loop.
//!
//! Exercises the aggregation seam (`aivpn_server::mask_feedback::MaskFeedbackStore`)
//! with realistic multi-reporter batches, and the wire seam
//! (`aivpn_common::protocol::ControlPayload::{MaskFeedback, RegionalMaskHints}`)
//! through the real `encode`/`decode` codec — proving the client→server→
//! aggregator→hints path is consistent end to end without needing a real UDP
//! socket or TUN device.
//!
//! Only public APIs are used; no source files were modified to support this
//! test.

use aivpn_common::protocol::{ControlPayload, MaskOutcome};
use aivpn_server::mask_feedback::{MaskFeedbackStore, MAX_VOTES_PER_REPORTER};

fn outcome(mask_id: &str, success: u16, fail: u16) -> MaskOutcome {
    MaskOutcome {
        mask_id: mask_id.to_string(),
        success,
        fail,
    }
}

/// Round-trip a `MaskFeedback` control payload through the real wire codec
/// (`ControlPayload::encode` / `::decode`) and return the decoded
/// `(entries, country_code)`. Panics (test failure) if the decoded value is
/// not a `MaskFeedback` variant.
fn wire_roundtrip_mask_feedback(
    entries: Vec<MaskOutcome>,
    country_code: [u8; 2],
) -> (Vec<MaskOutcome>, [u8; 2]) {
    let payload = ControlPayload::MaskFeedback {
        entries,
        country_code,
    };
    let bytes = payload.encode().expect("encode MaskFeedback");
    match ControlPayload::decode(&bytes).expect("decode MaskFeedback") {
        ControlPayload::MaskFeedback {
            entries,
            country_code,
        } => (entries, country_code),
        other => panic!("decoded into wrong ControlPayload variant: {other:?}"),
    }
}

/// Round-trip a `RegionalMaskHints` control payload through the real wire
/// codec and return the decoded `(country_code, masks)`.
fn wire_roundtrip_regional_hints(
    country_code: [u8; 2],
    masks: Vec<(String, f32)>,
) -> ([u8; 2], Vec<(String, f32)>) {
    let payload = ControlPayload::RegionalMaskHints {
        country_code,
        masks,
    };
    let bytes = payload.encode().expect("encode RegionalMaskHints");
    match ControlPayload::decode(&bytes).expect("decode RegionalMaskHints") {
        ControlPayload::RegionalMaskHints {
            country_code,
            masks,
        } => (country_code, masks),
        other => panic!("decoded into wrong ControlPayload variant: {other:?}"),
    }
}

/// Scenario: a bucket reported by fewer than `k_anon` (default 20) distinct
/// reporters must never be surfaced by `top_masks_for_region` — the single
/// privacy gate of this feature. "JP" is in the table's Asia continent, but
/// no other Asian country reports the same mask here, so there is also no
/// roll-up path that could accidentally satisfy the gate.
#[test]
fn sub_threshold_bucket_is_never_surfaced() {
    let store = MaskFeedbackStore::new();
    for i in 0..15u32 {
        let token = format!("jp-reporter-{i}");
        store.record_feedback(*b"JP", token.as_bytes(), &[outcome("dns_mimicry", 1, 0)]);
    }
    let top = store.top_masks_for_region(*b"JP");
    assert!(
        top.is_empty(),
        "15 distinct reporters is below k_anon=20 and JP has no same-continent \
         neighbor reporting this mask, so nothing should surface: {top:?}"
    );
}

/// Scenario: a realistic sequence of batched reports (each simulating one
/// client's aggregated §2 outcome report — see
/// `aivpn-client`'s `MaskFeedbackLog::aggregate_unreported`, which can bundle
/// several mask families a single client tried across reconnects into one
/// batch) from 30 distinct reporters for one country, covering two
/// competing mask families plus a handful of explicit failures for each.
/// Once k-anonymity (20) is cleared for both, `top_masks_for_region` must
/// rank them by (capped) success rate, best first.
#[test]
fn realistic_multi_mask_batches_are_ranked_by_capped_success_rate() {
    let store = MaskFeedbackStore::new();

    // 30 distinct clients, each reporting outcomes for both masks it tried
    // in a single batch (one MaskFeedback call per reporter, as the real
    // client would send on reconnect):
    //  - quic_https_v2: 26 succeed / 4 fail  -> ratio ~0.867
    //  - webrtc_zoom_v3: 20 succeed / 10 fail -> ratio ~0.667
    for i in 0..30u32 {
        let token = format!("de-reporter-{i}");
        let quic_ok = i < 26;
        let zoom_ok = i < 20;
        let entries = vec![
            outcome("quic_https_v2", quic_ok as u16, (!quic_ok) as u16),
            outcome("webrtc_zoom_v3", zoom_ok as u16, (!zoom_ok) as u16),
        ];
        store.record_feedback(*b"DE", token.as_bytes(), &entries);
    }

    let top = store.top_masks_for_region(*b"DE");
    assert_eq!(
        top.len(),
        2,
        "both masks cleared k_anon=20 with 30 distinct reporters each: {top:?}"
    );
    assert_eq!(
        top[0].0, "quic_https_v2",
        "higher success rate must rank first"
    );
    assert_eq!(top[1].0, "webrtc_zoom_v3");
    assert!(
        (top[0].1 - (26.0 / 30.0)).abs() < 0.02,
        "quic_https_v2 rate {} should be ~0.867",
        top[0].1
    );
    assert!(
        (top[1].1 - (20.0 / 30.0)).abs() < 0.02,
        "webrtc_zoom_v3 rate {} should be ~0.667",
        top[1].1
    );
    assert!(
        top[0].1 > top[1].1,
        "sort order must actually be descending by score"
    );
}

/// Scenario: a country with **zero** local reports for a mask must still be
/// able to receive it via the continent roll-up, once same-continent
/// neighbors collectively clear k-anonymity — this is the sparse-region
/// benefit described in the module doc comment. "IT" never reports
/// "obfs4_like" at all; "ES" and "NL" (both EU, per the continent table)
/// each get 15 distinct reporters, so combined they clear k_anon=20.
#[test]
fn continent_rollup_surfaces_mask_for_country_with_zero_local_reports() {
    let store = MaskFeedbackStore::new();

    // Confirm the premise first: with no data seeded anywhere yet, IT has
    // nothing to surface.
    assert!(
        store.top_masks_for_region(*b"IT").is_empty(),
        "sanity: no data exists yet, so IT must have nothing to surface"
    );

    for i in 0..15u32 {
        let token = format!("es-reporter-{i}");
        store.record_feedback(*b"ES", token.as_bytes(), &[outcome("obfs4_like", 4, 1)]);
    }
    for i in 0..15u32 {
        let token = format!("nl-reporter-{i}");
        store.record_feedback(*b"NL", token.as_bytes(), &[outcome("obfs4_like", 4, 1)]);
    }

    let top = store.top_masks_for_region(*b"IT");
    assert!(
        top.iter().any(|(m, _)| m == "obfs4_like"),
        "IT has zero local reports for obfs4_like, but ES+NL (both EU) \
         collectively clear k_anon=20, so the continent roll-up must surface \
         it to IT: {top:?}"
    );
}

/// Scenario: the per-reporter vote-integrity cap
/// (`MAX_VOTES_PER_REPORTER` = 4 "votes" per estimated distinct reporter)
/// bounds how much a single spamming reporter token can skew a bucket's
/// surfaced success rate, even though it cannot fake the k-anonymity gate
/// itself. 25 genuine, distinct reporters cast a roughly even mix of
/// success/fail (13/12, ratio ~0.52); one additional reporter token then
/// calls `record_feedback` 2000 times, each contributing one more "success"
/// vote (the per-call dedup clamp only bounds a single call, not repeated
/// calls from the same token — see the doc comment on `record_feedback`).
/// Without the cap this would push the bucket's reported success rate to
/// ~99%; with the cap, the effective weight of the spammer is bounded.
#[test]
fn per_reporter_vote_cap_bounds_a_single_spamming_reporter() {
    let store = MaskFeedbackStore::new();

    let genuine_success = 13u32;
    let genuine_fail = 12u32;
    for i in 0..genuine_success {
        let token = format!("fr-reporter-{i}");
        store.record_feedback(*b"FR", token.as_bytes(), &[outcome("vote_cap_mask", 1, 0)]);
    }
    for i in genuine_success..(genuine_success + genuine_fail) {
        let token = format!("fr-reporter-{i}");
        store.record_feedback(*b"FR", token.as_bytes(), &[outcome("vote_cap_mask", 0, 1)]);
    }

    let spam_calls = 2000u32;
    for _ in 0..spam_calls {
        store.record_feedback(
            *b"FR",
            b"fr-spamming-reporter",
            &[outcome("vote_cap_mask", 1, 0)],
        );
    }

    let top = store.top_masks_for_region(*b"FR");
    assert_eq!(top.len(), 1);
    let score = top[0].1;

    let total_success = genuine_success as f64 + spam_calls as f64;
    let total_fail = genuine_fail as f64;
    let uncapped_ratio = (total_success / (total_success + total_fail)) as f32;
    let genuine_only_ratio = genuine_success as f32 / (genuine_success + genuine_fail) as f32;

    assert!(
        score < uncapped_ratio - 0.05,
        "score {score} must be meaningfully below the uncapped (spam-inflated) \
         ratio {uncapped_ratio} — the vote cap must bound the spammer's effective weight"
    );
    assert!(
        score > genuine_only_ratio,
        "score {score} should still be pulled somewhat above the genuine-only \
         ratio {genuine_only_ratio} — the cap bounds the spammer's influence, \
         it does not zero it out entirely (MAX_VOTES_PER_REPORTER={MAX_VOTES_PER_REPORTER})"
    );
}

/// §3 seam: build a `ControlPayload::MaskFeedback` per reporter (as
/// `aivpn-client` would send it), round-trip it through the real wire codec
/// (`encode` → `decode`), feed the *decoded* entries into the store (never
/// the pre-encode originals — this is the point of the seam test), then
/// build a `ControlPayload::RegionalMaskHints` from `top_masks_for_region`'s
/// output and round-trip that too. Asserts the masks survive both hops
/// intact, proving the client→server→aggregator→hints wire path is
/// consistent end to end.
#[test]
fn wire_roundtrip_client_report_to_server_aggregate_to_regional_hints() {
    let store = MaskFeedbackStore::new();
    let country = *b"BR";

    let reporter_count = 24u32;
    let success_count = 20u32; // first 20 reporters report success, last 4 report failure

    for i in 0..reporter_count {
        let token = format!("br-reporter-{i}");
        let ok = i < success_count;
        let original_entries = vec![outcome("quic_https_v2", ok as u16, (!ok) as u16)];

        let (decoded_entries, decoded_country) =
            wire_roundtrip_mask_feedback(original_entries.clone(), country);

        assert_eq!(
            decoded_entries, original_entries,
            "MaskFeedback entries must survive the encode/decode round trip byte-for-byte"
        );
        assert_eq!(decoded_country, country);

        // Only ever feed the *decoded* value into the store — this is what
        // proves the wire codec, not just the aggregator, is correct.
        store.record_feedback(decoded_country, token.as_bytes(), &decoded_entries);
    }

    let top = store.top_masks_for_region(country);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].0, "quic_https_v2");
    let expected_ratio = success_count as f32 / reporter_count as f32;
    assert!(
        (top[0].1 - expected_ratio).abs() < 0.02,
        "aggregated ratio {} should be ~{}",
        top[0].1,
        expected_ratio
    );

    // Now push the aggregator's output back out over the wire as
    // RegionalMaskHints, and round-trip *that* too.
    let (decoded_hint_country, decoded_hint_masks) =
        wire_roundtrip_regional_hints(country, top.clone());

    assert_eq!(decoded_hint_country, country);
    assert_eq!(
        decoded_hint_masks, top,
        "RegionalMaskHints masks (mask_id + f32 success rate) must survive \
         the encode/decode round trip exactly — f32 is carried as raw \
         little-endian bytes on the wire, so this must be bit-exact"
    );
}
