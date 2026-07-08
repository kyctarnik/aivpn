# R2 Phase C — `aivpn-mask-repair`: offline adversarial mask-repair operator tool

Status: shipped. Productionizes the `research/mask-generation/r2/adv_loop.py`
prototype (see `research/mask-generation/r2/RESULTS.md`) as a server-side operator
binary. Fully offline — runs in the signing pipeline, **no runtime or client
impact**. Implements Part 2 "adversarial loop" and Part 4 "Phase C" of
`docs/R2_DESIGN.md`.

Deliverables:
- `crates/aivpn-server/src/mask_repair.rs` — the discriminator-agnostic loop core
  (genome, realisation, score, hill-climb), unit-tested with a mocked
  discriminator.
- `crates/aivpn-server/src/bin/aivpn-mask-repair.rs` — the operator CLI wiring the
  **real nDPI eval-gate** (`maskpcap` + `ndpiReader`) in as the discriminator.

---

## 1. The problem it solves

A mask that `mask_gen` fits from a real-traffic recording is statistically
faithful (R3 joint size↔IAT GMM, R4 temporal FSM) but can still **fail the R1 DPI
eval-gate**: nDPI reads its synthesised uplink as high-entropy `Unknown` — or, in
the worst case, flags it as an obfuscated tunnel — instead of the protocol it
means to mimic. The R1 root cause was structural and narrow: the legacy
tag-prefix wire layout shoves the real protocol header 8 bytes into the packet
where nDPI never looks, and/or the header lacks the exact discriminator bytes nDPI
keys off (STUN type `00 01`, magic cookie `21 12 A4 42`, the
`msg_len + 20 == payload_len` length consistency).

Before Phase C the only remedy was manual: discard the mask, or hand-re-author its
`header_spec` and `tag_offset` (this is exactly what commit
`fe2013f "re-author 3 STUN masks to embedded-tag layout"` did by hand). Phase C
**automates that repair**: point the tool at a gate-failing mask and it searches
the observable-shape space until the mask earns its target-protocol
classification, preserving all of the mask's learned statistical structure.

---

## 2. Loop shape (tied to the prototype's real numbers)

```
   ┌────────────┐   flip 1 gene   ┌──────────────┐  synth   ┌────────────┐
   │ genome      │ ───────────────▶│ MaskProfile   │ ───────▶ │ maskpcap    │
   │ (5 booleans)│                 │ (clone+patch) │          │ client path │
   └────────────┘                 └──────────────┘          └─────┬──────┘
        ▲                                                          │ pcap
        │ keep candidate iff score does not decrease                ▼
   ┌────┴─────────────────────────────────────────────┐   ┌──────────────┐
   │ score = 1.0  iff nDPI==target AND no tunnel risk   │◀──│ ndpiReader -d │
   │         else 0.6 × wire-structure partial [0,0.6)  │   └──────────────┘
   └────────────────────────────────────────────────────┘
```

### Mutation space (5 genes — `Genome`)

Each gene is a bounded, **structurally-real** edit to the mask's observable wire
shape — never a change to crypto or session semantics:

| gene | effect | grounding |
|---|---|---|
| `embed` | tag layout embedded (`tag_offset` = carrier slot, header at wire offset 0) vs legacy (`u16::MAX`, tag-prefix) | The single most impactful gene. R1 proved the legacy layout forces `Unknown`. STUN carrier offset = 8 (inside the 12-byte transaction id); QUIC = 6 (inside the connection id). |
| `proto_type` | correct type at offset 0 (STUN `00 01` / QUIC `0xC0` long-header) vs a deliberately-wrong placeholder | nDPI's first discriminator byte. |
| `magic` | protocol magic present (STUN cookie `21 12 A4 42` / QUIC version `00 00 00 01`) | nDPI's `is_stun()` magic check / QUIC version check. |
| `id_split` | split the id field so a clean tag-carrier slot exists (STUN `Id(8)+Id(4)`, QUIC `Id(4)+Id(4)`) | Lets the embedded tag land without overwriting a discriminator byte. |
| `sizes` | replace the size histogram with a protocol-plausible envelope | Nudges the size marginal toward the target's real envelope. |

The `realize()` function applies the genome onto a **clone** of the input mask:
only `tag_offset`, `header_spec`, `header_template`, and (if `sizes`)
`size_distribution` are overwritten. Everything the recording learned —
`size_iat_joint` (R3), `fsm_states` (R4), `signature_vector` (neural),
`iat_distribution` — is preserved byte-for-byte. The embedded `signature` is
**zeroed**, because the profile changed and any prior signature is now invalid.

### Score function

`score(verdict, target)`:
- **`1.0` (accept)** iff nDPI classifies the synthesised flow as the target
  protocol **and** raises no tunnel/obfuscation risk — the exact R1 gate.
- otherwise a **smooth partial in `[0, 0.6)`** = `0.6 ×` a wire-structure signal
  computed directly from the synthesised pcap payloads (STUN: `0.34·type@0 +
  0.33·magic@4 + 0.33·(msg_len+20==len)`; QUIC: `0.5·longform + 0.5·version`).
  The cap `< 0.6` guarantees a real accept (`1.0`) always dominates any partial.

The partial exists purely to give the hill-climb a **gradient**: without it the
score is a flat zero until the last gene flips (all discriminators satisfied at
once), and the search degenerates to blind flipping. With it, `embed` alone lifts
the score off zero (the header reaches wire offset 0), guiding the climb.

### Accept criterion & stop conditions

- **Accept move**: keep a mutated candidate iff its score does **not decrease**
  (`s >= cur_score`) — classic hill-climb, accepting equal moves so the search can
  traverse plateaus (e.g. `id_split`/`sizes` toggles that don't change the nDPI
  verdict).
- **Stop** on the first accept (score `1.0`), or after `max_iters` (bounded
  compute; default 40). No convergence within budget ⇒ the tool writes **no**
  output and exits non-zero.

### Real numbers

Prototype (`adv_loop.py`, Python): **12/12 seeds converge** to nDPI-STUN,
iterations min 3 / median 8 / max 18. The productionized Rust tool reproduces this
against the same `maskpcap` + `ndpiReader` discriminator — an 8-seed sweep on a
deliberately-broken STUN mask (legacy layout, wrong type `59 41`, wrong magic
`DE AD BE EF`) converged **8/8**, iterations `13 3 3 7 13 9 12 8` (median ~8.5).
Representative seed-1 curve:

```
iter  best_score  nDPI      genome
  0     0.000     Unknown    [-]         start: all-off, legacy layout
  7     0.198     Unknown    [e]         embed on → header reaches wire offset 0
  8     0.396     Unknown    [em]        + magic cookie @4
 13     1.000     STUN       [etmi]      + type@0 + id-split → ACCEPT
```

Independent eval-gate check on the emitted mask: input `REJECT` (Unknown) →
output `ACCEPT` (STUN, no VPN flags), `tag_offset` 8, header type `00 01`, magic
`21 12 A4 42`, embedded `signature` all-zero.

---

## 3. Why the anti-overfit measures matter

The central risk of an adversarial loop against a single DPI engine is
**overfitting to that engine's quirks** — finding a byte pattern that trips
nDPI's parser without being structurally the target protocol. R1 documented how
narrow those predicates are (the STUN `msg_len + 20 == payload_len` length check;
the QUIC long-header/AEAD form). A naive optimiser could satisfy such a check with
bytes no real client emits, producing a mask that passes nDPI but is trivially
distinguishable by any other DPI engine (Suricata, Zeek, Wireshark dissectors) or
a fingerprinting classifier.

Two guards keep the loop honest, both inherited from the prototype:

1. **Structurally-real mutation space.** The genome can *only* assemble bytes a
   genuine STUN/QUIC client actually emits — the real STUN Binding type and magic
   cookie, the real QUIC long-header form and version. It cannot invent "a magic
   string that happens to make nDPI say STUN". A converged mask is therefore STUN
   *because it is structured like STUN*, not because it exploits a parser bug.
2. **Two-discriminator agreement (design guard).** The prototype cross-checked
   every converged mask against an independently-trained ML classifier
   (`research/mask-generation/r2/train.py`) — all windows classified STUN, so the
   mask satisfies nDPI *and* a second, differently-implemented discriminator.
   Overfitting one is unlikely to fool the other. The operator pipeline SHOULD
   keep this second-discriminator check (or a held-out DPI engine) as a gate on
   the tool's output before signing.

This is why the tool restricts itself to a small, hand-curated gene set rather
than free-form byte mutation: the constraint *is* the anti-overfit mechanism.

---

## 4. Running it in the signing pipeline

### Invocation

```bash
export AIVPN_MASKPCAP=/path/to/eval-gate/target/release/maskpcap
export AIVPN_NDPIREADER=/path/to/nDPI-src/example/ndpiReader

aivpn-mask-repair \
    --input  failing_generated_mask.json \
    --output repaired_mask.json \
    [--target STUN|QUIC]   # default: derived from the mask's spoof_protocol
    [--max-iters 40]       # bounded compute budget
    [--seed 1]             # deterministic: same seed => same score curve
    [--packets 120]        # packets synthesised per candidate flow
    [--maskpcap PATH]      # overrides AIVPN_MASKPCAP
    [--ndpi PATH]          # overrides AIVPN_NDPIREADER
```

- **Input**: a gate-FAILING generated mask JSON.
- **Output**: a gated (nDPI-passing) mask JSON — but **UNSIGNED** (embedded
  `signature` zeroed). Signing is the next pipeline stage (Phase B).
- The full score curve is logged to stderr for auditability.

### Exit codes

| code | meaning |
|---|---|
| `0` | converged — output mask passes the nDPI gate, written to `--output` |
| `1` | did **not** converge within `--max-iters` — **no output written** (never emits an ungated mask) |
| `2` | usage / tooling error (bad args, missing `maskpcap`/`ndpiReader`, unparsable mask) |

### Determinism

The loop is fully deterministic per `--seed`: the RNG is `StdRng::seed_from_u64`
and the score is a pure function of the synthesised pcap. The same seed reproduces
the same score curve and the same output mask exactly — a CI job can pin a seed
and treat the repaired mask as a reproducible artifact.

### Where it sits end-to-end

```
recording (recording.rs)
   ▶ mask_gen fit + GMM + KS self-test        [exists: mask_gen.rs]
   ▶ nDPI offline gate  (eval_gate.sh)        [exists: R1]
   ▶ aivpn-mask-repair  if gate FAILS         ◀── THIS TOOL (Phase C)
   ▶ MaskProfile::sign(operator_key)          [Phase B, next stage]
   ▶ distribute via MaskUpdate / catalog
```

The tool is the **repair stage between `mask_gen`/the gate and signing**. A
freshly-generated mask is gated; if it passes, it goes straight to signing; if it
fails, `aivpn-mask-repair` recovers it (or exits `1` if it cannot, so the mask is
dropped rather than shipped ungated). Because the output is unsigned, it must flow
through `MaskProfile::sign` before distribution — the repair tool deliberately
does **not** hold the operator signing key, keeping the repair step (which runs
the untrusted generated mask through nDPI) isolated from key material.

---

## 5. Testability

`mask_repair.rs` separates the loop from the discriminator via the
`Discriminator` trait, so the mutation/scoring core is unit-tested **without
nDPI** (CI-safe): a `MockStunNdpi` reproduces nDPI's STUN predicate structurally
and the tests assert the loop converges the broken mask, the score curve is
monotonically non-decreasing, the run is deterministic per seed, `realize`
preserves learned fields while zeroing the signature, and `score` accepts the
target while vetoing tunnel-risk verdicts. The real nDPI discriminator lives only
in the binary and is exercised in the operator demo above.
