# R2 Phase A — Offline nDPI Mask Gate

Status: implemented. Ships `scripts/ci-mask-gate.sh`, a `make mask-gate` target,
and a CI step in `.github/workflows/ci.yml`. This is the first, lowest-risk phase
of the R2 productionization plan (`docs/R2_DESIGN.md`, Part 4). It has **no wire
protocol, client, or runtime impact** — it is a build-time quality gate over the
mask assets, scripts + Makefile + CI only.

---

## 1. What the gate does and why

A **mask** (`assets/masks/*.json`, schema `crates/aivpn-common/src/mask.rs`
`MaskProfile`) is the recipe aivpn uses to disguise a client's real uplink
traffic as an innocuous application protocol — Zoom/WebRTC-STUN, QUIC/HTTPS, and
so on. The whole security value of a mask is a single claim: *"traffic shaped by
this mask reads to a DPI box as protocol X, not as an obfuscated tunnel."* If
that claim is false, the mask is worse than useless — it advertises a VPN while
pretending not to.

Nothing in the build proved that claim before this gate. A mask could be authored
or machine-generated (`crates/aivpn-server/src/mask_gen.rs`), pass its statistical
self-test, be committed, and ship — while a real DPI engine classifies its actual
packets as `Unknown` high-entropy (i.e. "tunnel"). The R1 eval-gate
(`research/mask-generation/eval-gate/`) turned that claim into an automated
accept/reject; **Phase A wires that gate into the build** so **every mask asset
carries a DPI provenance check before it can be merged or published**.

Concretely, for each `assets/masks/*.json` the gate:

1. **Synthesises the mask's real on-wire uplink packets.** `maskpcap` (a small
   Rust bin in `research/mask-generation/eval-gate/`) loads the mask JSON and
   runs the **exact client build path** — `MimicryEngine::build_packet`, the same
   code `aivpn-client` executes per data packet — then wraps the output in
   Ethernet/IPv4/UDP into a libpcap file. No sudo, no network, deterministic. This
   matters: the gate scores the bytes a real client would actually emit, not a
   hand-drawn approximation.
2. **Classifies those packets with nDPI.** `ndpiReader -d -v 2`
   (`research/dpi-harness/nDPI-src/example/ndpiReader`). `-d` is **DPI-only mode
   with UDP port-guessing OFF**, so nDPI's verdict reflects *payload structure*,
   not the port number — exactly the adversary model we care about (a censor does
   not trust ports).
3. **Renders an accept/reject verdict** and fails the build if any mask is
   rejected.

nDPI is the right authority here because it is a real, widely-deployed DPI stack
(13 MB, full per-protocol state machines) — the same class of tool a censor runs.
It is too heavy to run inline in the server per-flow (that is what R2 Part 1's
learned inline classifier is for), but in an **offline** build/CI gate latency is
free, so we use the real thing as the source of truth.

## 2. How nDPI classification maps to accept / reject

The decision logic lives in `research/mask-generation/eval-gate/eval_gate.sh`
(exit 0 = accept, 1 = reject, 2 = tooling error). For each mask:

- **Target protocol** is auto-derived from the mask's own `spoof_protocol` field
  (`WebRTC_STUN` → `STUN`, `QUIC` → `QUIC`, `DNS` → `DNS`, `TLS`/`HTTPS` → `TLS`),
  so the gate is self-describing — a mask declares what it claims to be, and the
  gate holds it to that claim. It can be overridden with an explicit second arg.
- **REJECT (tunnel outed)** if nDPI raises any VPN/obfuscation risk flag —
  `OpenVPN`, `WireGuard`, `Obfuscated`, `Tor`, `Anonymous Subscriber`,
  `Malformed`. This is the worst outcome: the mask is being fingerprinted *as* a
  tunnel.
- **ACCEPT** if the detected protocol matches the target (case-insensitive
  substring, so `STUN` / `WhatsAppCall.STUN` / `Zoom` all satisfy a `STUN`/`Zoom`
  target) **and** no VPN flag is present. The mask earned its protocol identity.
- **REJECT (not earned)** otherwise — typically high-entropy `Unknown`, or a
  *different* protocol than declared. `Unknown`-with-no-VPN-flag is *necessary but
  not sufficient*: not being outed is not the same as convincingly being STUN. A
  mask must earn its target classification to pass.

`scripts/ci-mask-gate.sh` batches this over the whole `assets/masks/` directory,
prints a per-mask PASS/REJECT table, and exits non-zero if **any** mask is a
REJECT — so one bad mask fails the build.

## 3. Current result over `assets/masks/`

As of 2026-07-05 (nDPI 5.1.0, `-d`, targets auto-derived), **11 / 11 masks
PASS**:

```
mask                         | target | verdict    | nDPI
-----------------------------+--------+------------+---------
avito_api_v1                 | QUIC   | PASS       | QUIC
quic_https_v2                | QUIC   | PASS       | QUIC
sber_salute_v1               | STUN   | PASS       | STUN
telegram_mtproto_v1          | QUIC   | PASS       | QUIC
vk_video_v1                  | QUIC   | PASS       | QUIC
webrtc_sberjazz_v1           | STUN   | PASS       | STUN
webrtc_vk_teams_v1           | STUN   | PASS       | STUN
webrtc_yandex_telemost_v1    | STUN   | PASS       | STUN
webrtc_zoom_v3               | STUN   | PASS       | STUN
whatsapp_voip_v1             | STUN   | PASS       | STUN
yandex_alice_v1              | STUN   | PASS       | STUN
-----------------------------+--------+------------+---------
mask-gate: 11 PASS / 0 REJECT of 11
```

(The three STUN masks `sber_salute_v1` / `whatsapp_voip_v1` / `yandex_alice_v1`
that R1's README recorded as `Unknown` rejects were re-authored to the
embedded-tag STUN layout in commits leading up to master — see the failure
workflow in §7 for why they failed and what fixed them. The gate now confirms all
three read as STUN.)

## 4. Running it locally

From the repo root:

```bash
make mask-gate
# or directly, optionally over a different mask dir:
scripts/ci-mask-gate.sh [mask_dir]
```

Prerequisites (the research DPI toolchain — see §6 for why it may be absent):

- **`ndpiReader`** built at `research/dpi-harness/nDPI-src/example/ndpiReader`.
- **`maskpcap`** — the gate builds it automatically via `cargo` if a Rust
  toolchain is present; otherwise place/build it at
  `research/mask-generation/eval-gate/target/release/maskpcap`.
- **`eval_gate.sh`** at `research/mask-generation/eval-gate/eval_gate.sh` (present
  whenever the research tree is checked out).

Exit codes: `0` all PASS (or toolchain absent and skip allowed); `1` at least one
mask REJECTed; `2` toolchain absent while enforcement was demanded
(`MASK_GATE_REQUIRE=1`).

## 5. How it plugs into CI

`.github/workflows/ci.yml` runs a **Mask DPI gate (R2 Phase A)** step in the
`build` job after clippy:

```yaml
- name: Mask DPI gate (R2 Phase A)
  run: make mask-gate
```

Because the DPI toolchain lives under the gitignored `research/` tree (§6), a
**plain CI checkout does not contain it**, so on stock CI this step **skips
gracefully (exit 0) and never blocks the build**. That is deliberate: Phase A
lands the wiring and the local-dev gate with zero risk of red-building `master`
on infrastructure that has not yet provisioned nDPI.

To make CI **enforce** the gate (the intended end state), a runner must:

1. Build `ndpiReader` from the nDPI source into
   `research/dpi-harness/nDPI-src/example/` (a `./autogen.sh && ./configure &&
   make` of upstream nDPI; cache the binary between runs — it is large and slow to
   compile).
2. Ensure `research/mask-generation/eval-gate/` (the `maskpcap` crate +
   `eval_gate.sh`) is present. Since `research/` is gitignored, provision it via a
   checkout of the research tree, a submodule, or a cached artifact.
3. Run the step with `MASK_GATE_REQUIRE=1 make mask-gate` so a *skip* is promoted
   to a hard failure — meaning "the gate could not run" is treated as "not
   proven," never silently green.

Until a runner does that, the committed step is a documented, non-blocking
placeholder that becomes enforcing the moment the toolchain is available — no
workflow edit required, just the env var.

## 6. The graceful-skip behavior and its rationale

`scripts/ci-mask-gate.sh` checks for its inputs and, if any are missing, prints a
clear `mask-gate: SKIP — <reason>` line and exits 0 (unless `MASK_GATE_REQUIRE=1`,
which turns a skip into exit 2). It skips when:

- the mask dir is missing or empty,
- `eval_gate.sh` is absent (research tree not checked out),
- `ndpiReader` is not built,
- `maskpcap` is not built **and** `cargo` is unavailable to build it.

**Why skip rather than fail?** The DPI toolchain is heavyweight (a 13 MB nDPI
build) and lives under the **gitignored `research/` tree** — it is intentionally
*not* part of a normal clone. A backend developer building the server, or a first
`git clone`, has neither nDPI nor `maskpcap`. Failing the gate for them would
block unrelated work on a research dependency they never asked for. So the default
is: *if you have the toolchain, you are gated; if you do not, you are told clearly
and not blocked.* Enforcement is opt-in via `MASK_GATE_REQUIRE=1`, used exactly in
the one place that owns provisioning the toolchain — the CI/signing pipeline.

A **cargo build error with cargo present** is *not* a skip — that is a real
failure and exits 1. Only a genuinely absent toolchain skips. This keeps the skip
path from masking a broken `maskpcap`.

## 7. Adding a new mask and getting it gated

1. Author or generate the mask JSON into `assets/masks/<name>.json`. Set its
   `spoof_protocol` to the protocol it mimics (`WebRTC_STUN`, `QUIC`, …) — the
   gate derives the target from this field, so it must be truthful.
2. Run `make mask-gate` (with the toolchain present). Your mask appears as a new
   row in the table.
3. If it PASSES, commit it. If it REJECTs, the build now fails until you fix it —
   follow §8. You cannot merge a mask that a real DPI engine outs as a tunnel.

That is the entire contract: **a mask asset is only mergeable once nDPI confirms
it reads as its declared protocol.**

## 8. Failure-diagnosis workflow (mask REJECTed)

When the gate rejects a mask, run the single-mask gate to see the verdict line:

```bash
research/mask-generation/eval-gate/eval_gate.sh assets/masks/<name>.json
# eval-gate: mask=<name>.json target=STUN nDPI_proto=Unknown risks=[]
# REJECT: not classified as target protocol (got 'Unknown', want ~'STUN')
```

Two failure shapes, mapped to the R1 eval-gate root-cause findings:

### 8a. STUN masks landing as `Unknown` — the length-field / embedded-tag issue

R1 isolated the exact cause by diffing `header_spec` between passing and failing
STUN masks. nDPI's `is_stun()` predicate requires three things to be true *at wire
offset 0*: type `00 01`, magic cookie `21 12 A4 42` at offset 4, and the
structural check **`msg_len + 20 == payload_len`** (the STUN length field must
equal the actual body length). Failures came from two mechanisms:

- **Legacy tag layout (`tag_offset = None`).** The 8-byte resonance tag is
  *prepended*, shoving the STUN header 8 bytes into the wire where nDPI never
  looks → `Unknown`. Additionally `patch_stun_length` is skipped in legacy layout,
  so even the length field is wrong. **Fix:** use the embedded-tag layout
  (`tag_offset = 8`) so the STUN header sits at wire offset 0 and the length patch
  runs. This is the single most impactful gene.
- **Header/length field missing or malformed.** No `Length` field, or a single
  wide `Id(12)` where the passing masks split `Id(8) + Id(4)` around a real
  `Length(2)` field, so `msg_len + 20 == payload_len` never holds. **Fix:**
  re-author the `header_spec` to
  `Fixed[00 01] · Length(2) · Fixed[21 12 A4 42] · Id(8) · Id(4)`, matching
  `webrtc_vk_teams_v1` / `webrtc_zoom_v3`.

Inspect the failing mask's `tag_offset` and `header_spec` fields and compare to a
passing STUN mask (`assets/masks/webrtc_vk_teams_v1.json`). A misconfigured mask
whose `spoof_protocol` says `WebRTC_STUN` but whose header carries no magic cookie
(the `yandex_alice` case) is a *declaration bug*: either fix the header to real
STUN or correct `spoof_protocol` so the target matches what the bytes actually
are.

### 8b. QUIC masks — the AEAD / long-header form

For QUIC targets, the strongest signal nDPI keys on is the **long-header first
byte** (`byte0 & 0xC0 == 0xC0`) plus a plausible version and connection-ID shape;
the initial packet's protected payload must look like QUIC AEAD ciphertext, not
raw tunnel entropy. A QUIC mask landing as `Unknown` almost always has a
`header_spec` that does not set the long-header form byte at offset 0, or a
`size_distribution` that never produces a plausible Initial packet. Compare
against `assets/masks/quic_https_v2.json` and check the first `Fixed` header byte
and the size envelope.

### 8c. Escalate to the R2 adversarial loop

If a hand-fix is not obvious, the failing mask is exactly the input the R2
adversarial repair loop (`research/mask-generation/r2/adv_loop.py`, Phase C when
productionized) is built for: point it at the failing mask, let it search the
`header_spec` / `tag_offset` / distribution space, and it recovers the correct
layout automatically (12/12 seeds drove a deliberately-broken `Unknown` mask to
nDPI-`STUN`, median 8 iterations, in the R2 prototype). The gate here is the exact
pass/fail signal that loop optimizes against.

---

## Files in this phase

- `scripts/ci-mask-gate.sh` — the committed, CI-invokable, hermetic gate
  (repo-root-relative paths, per-mask PASS/REJECT table, graceful skip, non-zero
  exit on any reject). shellcheck-clean.
- `Makefile` — `mask-gate` target + help line.
- `.github/workflows/ci.yml` — `Mask DPI gate (R2 Phase A)` step in the `build`
  job (non-blocking until the toolchain is provisioned; `MASK_GATE_REQUIRE=1`
  enforces).
- `docs/R2_PHASE_A.md` — this document.

Reused, unchanged: `research/mask-generation/eval-gate/{eval_gate.sh,
scoreboard.sh, maskpcap}` and `research/dpi-harness/nDPI-src/.../ndpiReader`. No
Rust source under `crates/` was touched.
