# R2 Phase E — Continuous DPI-gate retrain pipeline

Status: shipped (offline ops tooling). Implements Part 4 "Phase E — Continuous
retrain" of `docs/R2_DESIGN.md`. **No product Rust source changes** — everything
here lives under `research/` (gitignored prototype tree) and `docs/`. The only
artifact this phase can put into product code is a *candidate* const-weight
`model.rs`, which an operator reviews and copies by hand (§5). The pipeline never
writes under `crates/`.

Phase E is what makes the R2 loop **closed and self-maintaining**: the earlier
phases generate a mask (mask_gen), gate it (Phase A / R1), repair it (Phase C),
sign it (Phase B), and gate it *inline* at runtime (Phase D). Phase E periodically
re-proves all of that against a fresh corpus and a freshly-labelled dataset, and
regenerates the inline model so it never drifts away from what nDPI actually says.

```
 generate ─▶ gate ─▶ repair ─▶ sign ─▶ inline-gate ─▶ ┌─────────────┐
 (mask_gen) (Phase A)(Phase C)(Phase B)(Phase D)      │  RETRAIN     │
      ▲                                                │  (Phase E)   │
      └────────────────────────────────────────────────┴──────┬──────┘
                     re-gate + re-label + retrain + re-export + re-sign
```

---

## 1. Deliverables

All under `research/mask-generation/r2/`:

| file | role |
|---|---|
| `retrain.sh` | the driver — runs the 5-step loop end-to-end, safe on a schedule |
| `export_model.py` | regenerates the Phase D const-weight `model.rs` (candidate) |
| `check_regression.py` | fails the loop if a gate metric drops below `baseline.json` |
| `baseline.json` | the accepted current-good grouped-CV numbers (the floor) |

Reused from earlier phases (unchanged): `build_dataset.py`, `features.py`,
`ndpi.py`, `pcaputil.py`, `train.py`, and the Phase A gate
`scripts/ci-mask-gate.sh`.

Run it:

```bash
research/mask-generation/r2/retrain.sh
```

The pipeline needs Python with the **pinned** `scikit-learn`+`numpy` toolchain —
install `research/mask-generation/r2/requirements.txt` (exact versions are load-
bearing for byte-identical export; see the reproducibility note in §4). If no
sklearn python is found it **skips** the ML steps with a clear message (like the
Phase A gate skips a missing nDPI toolchain) rather than failing. Point it at an
env explicitly with `AIVPN_PY=/path/to/venv/bin/python`, or drop a venv at
`research/mask-generation/r2/.venv`.

---

## 2. Retrain cadence and triggers

Retraining is **event-driven first, calendar-driven as a backstop**. Run
`retrain.sh` when any of these happens:

- **New or changed mask.** Any add/edit under `assets/masks/` (a new app profile,
  a Phase C repair, a re-authored `header_spec`). A new mask changes both the
  gate's corpus and the training distribution — the inline model must learn it.
- **Corpus drift / new real captures.** New `research/mask-generation/realcap*/`
  inner-traffic captures (real STUN/WebRTC/QUIC/DNS) shift the "reads-as-target"
  side of the decision boundary. Refresh whenever the capture set grows.
- **A second DPI engine.** When a new offline authority is added (Suricata/Zeek
  dissectors, a newer nDPI), re-label and retrain so the inline model tracks the
  *union* verdict, not one engine's quirks (the anti-overfit guard from
  `docs/R2_DESIGN.md` Part 2).
- **nDPI version bump.** `research/dpi-harness/nDPI-src` rebuilt to a new release
  can change labels; re-gate + retrain to catch silent classification changes.
- **Calendar backstop.** Monthly, even with no change, to detect toolchain rot
  (a dependency update that quietly alters `maskpcap` output or nDPI labels).

Scheduling is external (cron / CI schedule) — Phase E is *not* a per-PR merge gate
(that is Phase A's `ci-mask-gate.sh`). A typical cron entry:

```cron
# 03:17 on the 1st of each month — re-gate + retrain, mail the log
17 3 1 * *  cd /srv/aivpn && MASK_GATE_REQUIRE=1 research/mask-generation/r2/retrain.sh 2>&1 | mail -s "aivpn R2 retrain" ops@…
```

Because every step is idempotent and deterministic on fixed inputs, a scheduled
run with no corpus change is a no-op that just re-proves the numbers.

---

## 3. The pipeline, step by step

Each step logs `retrain: [n/5] …`; the whole run exits non-zero on the first hard
failure.

### Step 1 — RE-GATE the live corpus (`scripts/ci-mask-gate.sh`)
- **Input:** `assets/masks/*.json` (override/add with `MASK_DIR=…`).
- **Does:** synthesises each mask's real on-wire packets with `maskpcap` and
  classifies them with nDPI (`ndpiReader -d`), exactly like Phase A / the R1 gate.
- **Output:** a PASS/REJECT table.
- **Pass/fail:** any **REJECT** is a hard failure — a mask that no longer reads as
  its target protocol is a *provenance regression*. The loop stops here; the mask
  must be repaired (Phase C, `aivpn-mask-repair`) or removed before retraining.
  Retraining on a corpus that already fails the offline authority would just teach
  the inline model to accept a broken mask.
- **Skip:** if the nDPI/`maskpcap` toolchain is absent the gate skips (exit 0)
  unless `MASK_GATE_REQUIRE=1`, which turns the skip into a hard failure — set
  that in scheduled/CI runs so an unbuilt toolchain can't hide a regression.
- Set `SKIP_GATE=1` to run dataset+retrain only (e.g. iterating on the model with
  a corpus you already gated this run).

### Step 2 — DATASET refresh (`build_dataset.py`)
- **Input:** current `assets/masks/` + the deliberately-broken masks in
  `broken/` + real captures under `research/mask-generation/realcap2/`.
- **Does:** for every mask, several RNG draws → per-flow pcap → nDPI label; for
  each real capture, per-5-tuple sub-pcap → nDPI label. Slices each flow into
  24-packet windows and computes the 25 `features.py` features per window.
- **Output:** `dataset.json` (`{features, rows:[{x,y,src,kind,ndpi_proto}]}`).
  The previous file is copied to `dataset.prev.json` and the loop logs the
  row-count and per-label deltas so a corpus change is visible in the log.
- **Pass/fail:** a `build_dataset.py` error (missing `maskpcap`/`ndpiReader`) is a
  hard failure. Note the dataset is re-derived from RNG draws, so `dataset.json`
  can differ run-to-run even with an unchanged corpus — the regression guard in
  step 3, not byte-equality, is what protects quality.

### Step 3 — RETRAIN + regression guard (`train.py` → `check_regression.py`)
- **Input:** `dataset.json`.
- **Does:** `train.py` drops the two IAT features (cosmetic on synthetic pcaps —
  see `docs/R2_DESIGN.md` Part 1), then reports:
  - random 5-fold (leakage sanity check only),
  - **grouped 5-fold by source mask** (honest — a whole mask is held out),
  - the **masked-domain binary "reads-as-tunnel" detector** — the gate's real
    accept/reject decision — as precision/recall.
  It writes `results.json`. Then `check_regression.py` compares the new
  `results.json` to `baseline.json`.
- **Output:** grouped-CV numbers on stdout; a regression table.
- **Pass/fail (the important gate):** the loop **FAILS** if any tracked metric
  drops more than its tolerance below baseline:

  | metric (`results.json` key) | meaning | tolerance |
  |---|---|---|
  | `masked_tunnel_detector.precision` | never wrongly reject a genuine masked flow | 0.02 |
  | `masked_tunnel_detector.recall` | always catch a broken (Unknown) mask | 0.02 |
  | `masked_domain_GBDT.acc` | softer multiclass accuracy | 0.05 |

  Improvements are always allowed. A regression stops the loop **before** export —
  a model that gates worse than today's is never even offered for promotion.
  Current baseline: **precision 1.000 / recall 1.000**, masked-domain acc 0.933.

### Step 4 — EXPORT candidate const-weight model (`export_model.py`)
- **Input:** `dataset.json` (masked-domain rows).
- **Does:** trains the *ship* GBDT — `GradientBoostingClassifier(n_estimators=120,
  max_depth=3, learning_rate=0.15)`, identical to `train.py::gbdt()` — on the full
  masked-domain binary problem (Unknown vs OK), and serialises it to the exact
  Rust table format `crates/aivpn-server/src/dpi_gate/model.rs` expects (§5).
- **Output:** `research/mask-generation/r2/model.candidate.rs` — **never** the
  product file. The loop then runs `export_model.py --check` and logs whether the
  candidate's weight tables match the checked-in product model.
- **Pass/fail:** export itself does not fail the loop (the regression guard in
  step 3 already vouched for the model). "MATCH" ⇒ nothing to promote. "DIFFER" ⇒
  the model moved; an operator reviews and copies (§5).

### Step 5 — RE-SIGN hook (Phase B operator key) — documented stub
- **Input:** `assets/masks/*.json`.
- **Does:** checks each mask's embedded `signature` field; flags any that is
  missing or all-zero (unsigned). It is a **stub by design**: it holds no private
  key and does not reimplement the Rust signing crypto — it only tells the
  operator which masks need signing and the exact command. See §6.

---

## 4. Model-weight regeneration + review + copy (tied to `dpi_gate/model.rs`)

Phase D bakes the GBDT into the server binary as a const table walked by
`crates/aivpn-server/src/dpi_gate.rs::tunnel_probability`:

```
raw = INIT + LEARNING_RATE * Σ over trees of (the leaf reached);
descend left iff x[feature] <= threshold; leaf iff feature < 0;
P(reads-as-tunnel) = 1 / (1 + e^-raw)
```

`export_model.py` regenerates the file that feeds that walk. The **exact format**
it must (and does) reproduce — verified against the checked-in product file:

- Header: `// @generated by research/mask-generation/r2/export_model.py …`.
- `use super::GbdtNode;`
- `pub const N_FEATURES: usize = 23;` (the 25 `features.py` features minus the 2
  IAT features).
- `pub const INIT: f32 = …f32;` — sklearn's raw-score prior, the log-odds of the
  positive-class (Unknown) fraction. With 270/1260 masked-domain rows Unknown,
  `INIT = ln(270/990) = -1.2992830…`.
- `pub const LEARNING_RATE: f32 = 0.15…f32;`
- `pub const N_TREES: usize = 120;`
- `pub const TREE_OFFSETS: [u32; N_TREES+1] = [ … ];` — start index of each tree in
  `NODES`; `TREE_OFFSETS[t]..TREE_OFFSETS[t+1]` is tree `t`.
- `pub const NODES: [GbdtNode; …] = [ GbdtNode { feature, threshold, left, right,
  value }, … ];` — depth-first pre-order per tree, `left`/`right` **local** to the
  tree, leaves as `feature: -1, left: 0, right: 0, value: <leaf>`.

Format fidelity details `export_model.py` gets right so the candidate is
diff-clean against a `cargo fmt`ed product file:

- **float literals** are rendered `repr(float(np.float32(x))) + "f32"`. sklearn
  stores thresholds/leaf values as float32 internally; round-tripping through
  `np.float32` reproduces literals like `3.933912992477417f32` exactly.
- **leaf `value` is pre-shrinkage** — the raw tree newton step; `LEARNING_RATE` is
  applied at inference, matching `dpi_gate.rs`.
- **class ordering** is alphabetical, so `Unknown` is the positive class (index 1)
  and `decision_function` == the raw log-odds of P(tunnel) that the Rust squashes.
- **split direction** is `<=` → left, matching sklearn and `dpi_gate.rs`.

### The operator promote workflow (the ONLY step that touches product code)

1. Run `retrain.sh`. If step 4 logs **MATCH**, stop — the shipped model is current.
2. If it logs **DIFFER**, review the diff:
   `diff crates/aivpn-server/src/dpi_gate/model.rs research/mask-generation/r2/model.candidate.rs`
   Sanity-check `INIT`, `N_TREES`, node count, and that `results.json` shows no
   regression (step 3 already enforced this).
3. Promote — **one line, done by a human, never by the script**:

   ```bash
   cp research/mask-generation/r2/model.candidate.rs \
      crates/aivpn-server/src/dpi_gate/model.rs && cargo fmt --all
   ```

4. Rebuild the server with the `neural` feature and run its `dpi_gate` tests:
   `cargo test -p aivpn-server --features neural dpi_gate`. Commit the regenerated
   `model.rs` as a normal product change with the retrain provenance in the message.

> **Reproducibility note (byte-identical export).** The export is now
> **guaranteed byte-identical** across re-runs given the same `dataset.json` and
> the pinned toolchain. Three sources of nondeterminism were closed:
>
> 1. **Unseeded RNG.** Even with `subsample=1.0`/`max_features=None`, sklearn's
>    tree splitter draws from the RNG to break ties, so an unseeded fit is *not*
>    deterministic — two consecutive unseeded exports produced different tree
>    *shapes* (7294 vs 7308 nodes). Fixed: `random_state=0` on the
>    `GradientBoostingClassifier` (in both `export_model.py` and `train.py::gbdt()`)
>    plus a `np.random.seed(0)` belt-and-braces. `SEED` is a named constant.
> 2. **sklearn version drift.** A different scikit-learn version tie-breaks splits
>    differently. Pinned in `research/mask-generation/r2/requirements.txt`
>    (**scikit-learn==1.9.0, numpy==2.5.1**, plus scipy/joblib/threadpoolctl).
>    Never bump these pins without regenerating + reviewing + promoting `model.rs`
>    in the same change.
> 3. **Dataset row ordering.** `export_model.py` now sorts the masked-domain rows
>    by a stable content key before fitting, so the output is invariant to the
>    on-disk order of `dataset.json` rows.
>
> Float literals are already emitted via a fixed `np.float32` round-trip and all
> iteration is index-ordered (no dict/set-order dependence), so the emitted text
> is stable. `export_model.py --check` normalises both its output and the product
> file through `rustfmt` before comparing, so `TREE_OFFSETS` line-wrapping does
> not read as a weight diff.
>
> **Enforcement.** `retrain.sh` step 4 exports the candidate **twice** and
> hard-fails (`export: NOT REPRODUCIBLE`) if the two files are not byte-identical
> (`diff -q`). The shipped `crates/aivpn-server/src/dpi_gate/model.rs` was itself
> regenerated with this seeded pipeline, so `export_model.py --check` reports
> **MATCH** against it — a fresh export equals the checked-in file bit-for-bit
> until the corpus/dataset actually changes.
>
> Note: `build_dataset.py` (step 2) still re-draws `dataset.json` from RNG, so the
> *dataset* can change run-to-run — that is protected by the step-3 regression
> guard, not byte-equality. The reproducibility guarantee above is over a **fixed**
> `dataset.json`: keep the shipped `dataset.json` stable and the export is
> deterministic. Promotion remains a reviewed manual copy so a genuine corpus
> change is never auto-shipped.

---

## 5. Re-sign hook (where Phase B slots in after a corpus change)

A mask's embedded ed25519 `signature` (see `crates/aivpn-common/src/mask.rs`
`signing_message`/`sign`/`verify_signature`) covers the **whole profile**, so
**any** corpus change invalidates it:

- a Phase C repair (`aivpn-mask-repair` emits its output **UNSIGNED** by design —
  see `docs/R2_PHASE_C.md`),
- a newly generated or hand-authored mask,
- any edit to a mask's `header_spec`, `size_distribution`, etc.

So re-signing belongs **after** the corpus is final and has passed the gate, and
**before** distribution — the same position as in the end-to-end flow
(`…gate → sign → distribute…`, `docs/R2_DESIGN.md` Part 3/4). The retrain loop's
step 5 detects unsigned masks and prints the operator command; it deliberately
does not sign, because signing needs the offline operator private key and the Rust
`signing_message` construction (BLAKE3 over the profile, ed25519), which must not
be re-implemented in a shell/Python stub.

Re-sign with the Phase B operator key (`crates/aivpn-server/src/main.rs`
`--mask-signing-key`, key generated by `--gen-mask-signing-key`):

```bash
# generate the operator key once (root-owned, 0600), keep it OFFLINE:
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key

# masks are (re-)signed by the server when it loads/generates them with the key:
aivpn-server --mask-signing-key /etc/aivpn/mask-signing.key \
             --mask-dir /var/lib/aivpn/masks  …
```

Load-side verification (`mask_store.rs`, config-gated warn → enforce-new →
enforce-all) then rejects any mask that fails, so an unsigned mask that skips this
step is caught downstream rather than silently shipped. Keep the operator key
separate from the server transport key so a compromised edge server cannot forge
masks (`docs/R2_DESIGN.md` Part 3).

---

## 6. How a regression is detected and what to do

| symptom | where | meaning | action |
|---|---|---|---|
| a mask shows **REJECT** | step 1 | nDPI no longer reads it as its target protocol | repair with `aivpn-mask-repair` (Phase C) or drop the mask; re-run |
| `check_regression.py` **FAIL** | step 3 | inline gate precision/recall/acc dropped below baseline | do **not** promote; inspect the `dataset.prev.json`→`dataset.json` label deltas and the just-added mask/capture that shifted the boundary |
| candidate **DIFFER** | step 4 | model moved (normal after any corpus change) | review the diff, then the §5 promote copy |
| unsigned mask warnings | step 5 | corpus changed since last signing | re-sign per §5 before distributing |
| ML steps **SKIPPED** | — | no sklearn python found | provide `AIVPN_PY` or a venv (message shows the exact commands) |

A regression is **never** auto-shipped: step 3 stops the loop before export, and
even a passing candidate is only ever written under `research/` for manual review.

### Updating the baseline

`baseline.json` is the *accepted* floor, not a moving average. Only raise it after
an operator has reviewed a new `results.json` and decided the new numbers are the
new normal (e.g. a genuinely better model, or an intentionally harder corpus).
Copy the reviewed `masked_tunnel_detector` precision/recall and
`masked_domain_GBDT.acc` into `baseline.json` and commit that decision. Never
lower the baseline to make a regression pass.

---

## 7. Operator runbook (quick reference)

```bash
# 0. one-time: python env with the PINNED toolchain (byte-identical export).
#    Skipped gracefully if absent; use the exact versions in requirements.txt.
python3 -m venv research/mask-generation/r2/.venv
research/mask-generation/r2/.venv/bin/pip install -r research/mask-generation/r2/requirements.txt

# 1. run the full loop (re-gate → dataset → retrain → export candidate → re-sign check)
MASK_GATE_REQUIRE=1 research/mask-generation/r2/retrain.sh

# 2. if step 1 REJECTs a mask: repair it, then re-run
research/mask-generation/eval-gate/eval_gate.sh assets/masks/<name>.json   # diagnose
#   (repair via aivpn-mask-repair — see docs/R2_PHASE_C.md)

# 3. if step 4 says DIFFER and step 3 passed: review + promote (manual, product change)
diff crates/aivpn-server/src/dpi_gate/model.rs research/mask-generation/r2/model.candidate.rs
cp research/mask-generation/r2/model.candidate.rs \
   crates/aivpn-server/src/dpi_gate/model.rs && cargo fmt --all
cargo test -p aivpn-server --features neural dpi_gate

# 4. if step 5 flags unsigned masks: re-sign with the operator key, then distribute
aivpn-server --mask-signing-key /etc/aivpn/mask-signing.key --mask-dir <dir> …
```

Environment knobs: `AIVPN_PY` (python with sklearn), `MASK_DIR` (extra/override
mask dir), `MASK_GATE_REQUIRE=1` (skip → hard failure), `SKIP_GATE=1` (dataset +
retrain only).

---

## 8. How this closes the R2 loop

- **generate** (`mask_gen`) → **gate** (Phase A, `ci-mask-gate.sh`) → **repair**
  (Phase C, `aivpn-mask-repair`) → **sign** (Phase B, operator key) → **inline
  gate** (Phase D, `dpi_gate.rs`) → **retrain** (Phase E) → back to gate.
- Phase E re-runs the offline authority (nDPI) over the live corpus, re-labels a
  fresh synth+real dataset against it, retrains the inline model that Phase D
  ships, and refuses to move the model backwards (the baseline guard). The result
  is regenerated as a reviewed candidate, and the re-sign hook keeps provenance
  intact across the change.
- Net effect: the cheap always-on inline gate (`dpi_gate.rs`) is kept honest
  against the expensive offline authority (nDPI) forever, without a human having
  to hand-retrain — and without a single automated write to product code.
