# R2 Phase B — Operator-signed masks with config-gated verification

Status: shipped. Implements Part 3 "sign the artifact, verify on every load" and
Part 4 "Phase B" of `docs/R2_DESIGN.md`. This is the **all-client** phase of R2:
the sign/verify primitive lives in `aivpn-common`, so the server, the desktop
CLI client, and both mobile cores (iOS/Android) all inherit identical
verification semantics from one function. No wire-format change — the ed25519
signature rides in the `MaskProfile.signature` field that already existed in the
schema (previously always all-zero at runtime).

Deliverables:
- `crates/aivpn-common/src/mask.rs` — `MaskVerifyMode` / `MaskVerifyDetail` /
  `MaskVerifyResult` and the single shared entry point `verify_mask_artifact()`
  (lines 297–408), plus the `is_unsigned()` / `is_derived_variant()` helpers.
- `crates/aivpn-server` — operator key CLI (`--gen-mask-signing-key`,
  `--sign-mask-dir`), config plumbing (`mask_signing_key` /
  `mask_operator_pubkey` / `mask_verify_mode`), load-time verification in
  `mask_store.rs`, sign-after-self-test in `mask_gen.rs`.
- `crates/aivpn-client` + `crates/aivpn-ios-core` + `crates/aivpn-android-core` —
  artifact verification at every `ControlPayload::MaskUpdate` ingestion point.
- `deploy/config/server.json.example` + README (EN/RU/CN) operator docs
  (`README.md` §"Mask Signing & Verification (provenance)", line 732).

---

## 1. Threat model — why mask provenance matters

A **mask** is executable policy: the client shapes every uplink packet exactly
as the `MaskProfile` says (`MimicryEngine::build_packet`). Before Phase B there
were two signature mechanisms in the tree and **neither** protected a runtime
mask artifact (`docs/R2_DESIGN.md` Part 3):

1. The **transport MaskUpdate signature** — the server signs the msgpack bytes
   of the pushed profile with its transport-derived ed25519 key
   (`gateway.rs:718` `derive_server_signing_key`). This proves *"pushed by my
   server"* — and nothing more. A **compromised edge server** signs anything it
   likes with a valid transport key.
2. The **embedded `MaskProfile.signature`** — existed in the schema, was checked
   nowhere: `mask_store.rs` did a bare `serde_json::from_str` on disk load, and
   the client `MaskUpdate` arm deserialized and applied. Every runtime mask was
   effectively unsigned.

What a tampered or attacker-authored mask buys the adversary:

- **De-anonymization / beaconing.** `tag_offset` (where the 8-byte resonance
  tag is embedded) and `header_spec` are attacker-controllable shape. A
  malicious mask can plant the tag or a fixed header pattern at a chosen offset,
  turning every packet the victim emits into a **watermark** a DPI middlebox can
  key on — the mask *is* the fingerprint. The field doc at `mask.rs:594-596`
  states this explicitly: the tag position is security-critical, so a signed
  mask must commit to it.
- **Deliberate outing.** Replace a gated mask's distributions/FSM with shapes
  that read to nDPI as `Obfuscated`/`Unknown` — the client happily emits
  traffic that advertises "VPN here" while believing it is masked. This
  silently undoes everything Phase A/C guarantee.
- **Gate bypass.** Phase A gates masks *at build time in CI*. Nothing bound the
  artifact a client actually applies at runtime to the artifact that passed the
  gate. Provenance is the missing link: a signature that is only granted
  **after** the gates pass makes "gated" a verifiable property of the artifact
  itself, on every device, on every load.

Attack surfaces closed: (a) a writable `--mask-dir` on an edge node (disk
tampering between restarts), (b) a compromised edge server pushing arbitrary
masks over an otherwise-valid transport channel, (c) any future distribution
channel that moves profile bytes (catalog, pool sync) — the artifact signature
is channel-independent.

What Phase B does **not** claim: it does not authenticate the transport (that
is `server_signing_key` / the AEAD session, kept as defense-in-depth), and it
cannot help a client that has no operator public key configured — which is
exactly why the rollout is config-gated (§7).

---

## 2. The signature: whole-struct, zero-then-sign

`crates/aivpn-common/src/mask.rs`:

- **`signing_message()`** (`mask.rs:1401-1405`) — the canonical byte string:
  clone the profile, zero the 64-byte `signature` field, `serde_json::to_vec`
  the whole struct. `MaskProfile` contains no hash maps, so serde field order —
  and therefore the encoding — is deterministic.
- **`sign(&SigningKey)`** (`mask.rs:1409-1414`) — zeroes `signature` in place,
  signs `signing_message()`, stores the 64-byte ed25519 signature back into the
  struct. The signature travels *inside* the JSON/msgpack artifact — no
  side-channel, no detached `.sig` files.
- **`verify_signature(&[u8;32])`** (`mask.rs:1416-1428`) — verifies against the
  operator verifying key; malformed key is an error, a bad signature is
  `Ok(false)`.

The load-bearing property: **the signature covers EVERY field**. Because the
message is the whole struct with only `signature` zeroed, an attacker cannot
keep a valid signature while repointing `tag_offset`, swapping the
`header_spec`, editing `spoof_protocol`, the distributions, the FSM, the
`perturbation_bounds`, or `eph_pub_offset` — any single-field edit invalidates
the signature (`mask.rs:1389-1396`). This is intentionally NOT the pre-0.10
message (which covered only `mask_id`/`version`/`header_template`/`eph_pub_*`);
old signatures do not verify — an accepted breaking change for 0.10
(`mask.rs:1398-1400`).

Two structural consequences handled explicitly:

- **Reverse profiles are signed first.** A mask's nested `reverse_profile`
  (downlink shape) is itself a `MaskProfile`. Both `mask_gen.rs:195-210` and
  `--sign-mask-dir` (`main.rs:899-902`) sign the reverse profile *before* the
  outer profile, so the outer signature covers the already-signed reverse
  profile and the reverse profile stays independently verifiable if extracted.
- **Derived variants are not verifiable — by design.** Per-session polymorphic
  variants (`polymorphic:*`, `bootstrap:*` mask_ids,
  `is_derived_variant()` at `mask.rs:1444-1446`) are perturbed from a signed
  base, which shifts signature-covered fields (e.g. `eph_pub_offset`) while
  keeping the base's now-stale signature
  (`apply_polymorphic_perturbation`, `mask.rs:415-421`). They must never be
  passed to `verify_signature` expecting `true`; §4 explains where they are
  exempted and where they deliberately are **not**.

**Unsigned ≠ forged.** `is_unsigned()` (`mask.rs:1434-1436`) is `true` for the
legacy all-zero signature — a mask produced before Phase B or by a generator
with no `--mask-signing-key`. The verify *mode* decides whether such masks are
accepted; the verdict machinery distinguishes `Unsigned` from `Invalid` so an
operator can tell "not yet signed" from "actively tampered" in the logs.

---

## 3. `verify_mask_artifact` — one shared, config-gated entry point

All platforms call the same function
(`mask.rs:384-408`):

```rust
pub fn verify_mask_artifact(
    profile: &MaskProfile,
    operator_pubkey: Option<&[u8; 32]>,
    mode: MaskVerifyMode,
) -> MaskVerifyResult
```

**`MaskVerifyMode`** (`mask.rs:310-317`, serde lowercase, `FromStr` accepts
`off|warn|enforce`, `#[default]` = **`Warn`**):

| mode | verification | on failure |
|---|---|---|
| `off` | skipped entirely (`ModeOff`) | accept |
| `warn` *(default)* | runs when an operator pubkey is configured | **log-and-accept** |
| `enforce` | required | **reject** anything that is not `Valid` |

**`MaskVerifyDetail`** (`mask.rs:337-348`) carries *why*: `ModeOff`, `Valid`,
`NoOperatorKey` (no pubkey configured — verification impossible), `Unsigned`
(legacy all-zero), `Invalid` (present but did not verify, or malformed key).
The verdict (`MaskVerifyResult`, `mask.rs:352-371`) is
`accept = mode != Enforce || detail == Valid`, plus `is_failure()` which is
`true` for `Unsigned | Invalid | NoOperatorKey` so callers know a warning line
is deserved even when `accept` is `true`.

Semantics worth calling out:

- **`warn` with no key is a silent no-op.** `detail = NoOperatorKey`,
  `accept = true`, and every call-site guards its warn-log with
  `verdict.is_failure() && operator_pubkey.is_some()` — so the shipped default
  changes *nothing* for existing deployments that have never heard of mask
  signing. This is what makes `warn` a safe default (§7).
- **`enforce` with no key fails closed.** Every mask is rejected
  (`NoOperatorKey` is not `Valid`): the operator explicitly opted into
  enforcement, so "cannot verify" must mean "reject", never "wave through"
  (`mask.rs:306-309`).
- **The derived-variant exemption is the caller's decision, path-dependent**
  (`mask.rs:380-383`): runtime `MaskUpdate` arms exempt
  `is_derived_variant()` masks because they arrive only over the
  AEAD-authenticated session channel — that channel is what authenticates
  them. The server **disk-load path does NOT exempt them**
  (`mask_store.rs:312-316`): disk is not a channel-authenticated path, and an
  attacker who can write to the mask dir must not bypass `enforce` by naming a
  file `polymorphic:evil`.

---

## 4. Every call-site (the all-client inheritance)

Because `verify_mask_artifact` lives in `aivpn-common` — the crate shared by
the server, the desktop client, and both mobile cores — one implementation
gives every platform identical semantics. The four ingestion points:

| # | platform | site | pubkey / mode source | derived-variant exempt? |
|---|---|---|---|---|
| 1 | server, disk load | `crates/aivpn-server/src/mask_store.rs:312-336` (`load_from_disk`) | `GatewayConfig.mask_operator_pubkey` / `.mask_verify_mode` | **No** (disk path) |
| 2 | server, generation | `crates/aivpn-server/src/mask_gen.rs:195-210` — *sign*, not verify | `MaskStore.operator_signing_key()` (`mask_store.rs:100-102`) | n/a |
| 3 | desktop client, `MaskUpdate` | `crates/aivpn-client/src/client.rs:1692-1720` | `ClientConfig.mask_operator_pubkey` / `.mask_verify_mode` (`client.rs:173-186`) | Yes (`client.rs:1700`) |
| 4a | iOS core, `MaskUpdate` | `crates/aivpn-ios-core/src/ios_tunnel.rs:1109-1143` | `(None, Warn)` hardcoded pending FFI plumbing | Yes |
| 4b | Android core, `MaskUpdate` | `crates/aivpn-android-core/src/android_tunnel.rs:1445-1477` | `(None, Warn)` hardcoded pending JNI plumbing | Yes |

**Site 1 — server load-time verify.** After `serde_json::from_str` of each
`*.json` in the mask dir, `verify_mask_artifact` runs; `enforce` rejection
`error!`s and skips the file ("Mask '{}' REJECTED (mask_verify_mode=enforce)"),
a `warn`-mode failure logs the actionable line *"Re-sign it or set
mask_verify_mode=enforce once the corpus is signed"* and loads anyway
(`mask_store.rs:319-336`). This is the exact site `docs/R2_DESIGN.md` Part 3
named (`mask_store.rs:275-281` pre-change).

**Site 2 — sign only after the gate.** `generate_and_store_mask` signs a
freshly generated mask **only after the KS self-test passed**
(`mask_gen.rs:195-196`: "so a signature attests 'this mask went through the
gates'"). No key configured ⇒ the mask is stored with `signature=[0u8;64]`,
exactly as pre-Phase B. The `production-secure` `compile_error!`
(`mask_gen.rs:16-21`) **stays** until the remaining hardening lands: make the
signing key mandatory and default `mask_verify_mode` to `enforce` in
production-secure builds — the error text says precisely this, so the feature
cannot be enabled while unsigned generation is still possible.

**Site 3 — desktop client, two independent checks.** The `MaskUpdate` arm
(`client.rs:1668-1730`) first verifies the **transport** signature over the raw
`mask_data` bytes against `server_signing_key` (`client.rs:1674-1689`,
unchanged behavior), then — after deserializing — runs the **artifact** check
(`client.rs:1700-1719`). The comment at `client.rs:1692-1699` states the
layering: *transport auth proves "pushed by my server"; artifact auth proves
"gated + signed by the operator"* — two different keys, two different threat
models, deliberately kept as independent defense-in-depth layers
(`client.rs:176-178`). Derived per-session variants are exempt here (channel-
authenticated, not independently verifiable). Under `enforce`, a rejected mask
is logged and dropped; the session keeps its current mask.

**Sites 4a/4b — mobile cores.** Both tunnel loops run the identical hook with
`(None, MaskVerifyMode::Warn)` — a documented silent no-op today, because the
operator pubkey is not yet plumbed through the C-FFI/JNI config surface
(`ios_tunnel.rs:1111-1116`, `android_tunnel.rs:1448-1452`). The point of
landing the hook now is that when the FFI grows the two parameters, **only
those two arguments change** and mobile inherits desktop semantics with zero
new verification code. (The mobile cores already verify *bootstrap descriptors*
via FFI — `aivpn_verify_bootstrap_descriptor`, `ios-core/src/lib.rs:645` —
the same pattern the mask pubkey will follow.)

---

## 5. Operator key lifecycle

### Generate — `--gen-mask-signing-key <PATH>`

`crates/aivpn-server/src/main.rs:830-857` (`handle_gen_mask_signing_key`,
dispatched before any config load at `main.rs:234-238`):

```bash
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key
# ✅ Operator mask-signing key written to /etc/aivpn/mask-signing.key
#    Public key (base64) — distribute to servers (--mask-operator-pubkey)
#    and clients (--mask-operator-pubkey / config mask_operator_pubkey):
#    <base64 32-byte ed25519 verifying key>
```

- 32-byte seed from `OsRng`, written **base64** with mode **0600**; refuses to
  overwrite an existing file (`main.rs:836-839` — a rerun cannot silently
  rotate the key out from under a signed corpus).
- Prints the base64 **public** key once — that string is the only thing that
  ever leaves the signing host.
- The loader (`load_mask_signing_seed`, `main.rs:729-760`) accepts raw-32-bytes
  or base64, and **exits with a clear error** on a configured-but-unreadable
  key: silently skipping it would silently ship unsigned masks.

### Custody

The operator key is deliberately **separate from `--key-file`** (the server
transport key). `server.rs:184-187` and `gateway.rs:150-155` both spell out
why: the transport key lives on every edge node; the mask-signing key should
live on the **signing/operator host only** (CI or the box that runs
`mask_gen` + the Phase A/C gates). A compromised edge server then cannot forge
mask provenance — it can push masks (transport-signed), but they will not
carry a valid operator signature and `enforce`-mode clients reject them. Edge
nodes that only *verify* need nothing but the base64 pubkey
(`mask_operator_pubkey`).

### Bulk-sign an existing corpus — `--sign-mask-dir <DIR>`

`main.rs:863-915` (`handle_sign_mask_dir`): signs every `*.json` in the
directory **in place** (reverse profile first, then outer — §2), prints a
per-file `signed`/`skip`/`FAILED` line, then exits. Requires
`--mask-signing-key` (or config `mask_signing_key`); refuses to run without it.
Non-mask JSON files (e.g. `.stats` companions are not `.json`, but any stray
JSON that fails to parse as a `MaskProfile`) are skipped with a reason, never
clobbered.

```bash
aivpn-server --sign-mask-dir /var/lib/aivpn/masks \
             --mask-signing-key /etc/aivpn/mask-signing.key
# run once over the corpus BEFORE turning on mask_verify_mode=enforce
```

This is the "Run once over your mask corpus before turning on
mask_verify_mode=enforce" step (`server.rs:210-211`) and the command Phase E's
step 5 re-sign hook points operators at after any corpus change
(`docs/R2_PHASE_E.md` §5 — a Phase C repair, a regenerated mask, any
`header_spec` edit all zero/stale the signature by construction).

### Rotation

Per `docs/R2_DESIGN.md` Part 3, rotation follows the **bootstrap two-key
trust-set pattern**: ship *current + next* operator pubkeys for an overlap
window, re-sign the active corpus with the new key during the window
(`--sign-mask-dir` — a pure re-signature, no wire change, because
`signing_message()` covers the whole profile), then drop the old key. The
shipped code carries a **single** `mask_operator_pubkey` today; the trust-set
widening is the designed extension point and costs only a `Vec` at the config
surface plus an any-key-verifies loop in `verify_mask_artifact` — the artifact
format needs nothing. Until then, rotation is: generate new key → re-sign
corpus → distribute the new pubkey (new connection keys carry it automatically,
§6) → retire the old seed file.

---

## 6. Config wiring, end to end

### Server

Resolution precedence is **CLI/env → `server.json` → derived/default**
(`main.rs:762-826`):

| what | CLI flag (env var) | `server.json` key | fallback |
|---|---|---|---|
| signing key path | `--mask-signing-key` (`AIVPN_MASK_SIGNING_KEY`), `server.rs:188-189` | `"mask_signing_key"` (`main.rs:180-183`) | `None` ⇒ generate unsigned |
| verifying pubkey (base64) | `--mask-operator-pubkey` (`AIVPN_MASK_OPERATOR_PUBKEY`), `server.rs:194-195` | `"mask_operator_pubkey"` (`main.rs:185-187`) | **derived from the signing key** (`main.rs:802-807`) so a single-host generate+verify setup needs one flag |
| verify mode | `--mask-verify-mode` (`AIVPN_MASK_VERIFY_MODE`), `server.rs:200-201` | `"mask_verify_mode"` (`main.rs:189-191`) | `MaskVerifyMode::default()` = `warn` |

The resolved values land in `GatewayConfig` (`gateway.rs:156` `mask_signing_key:
Option<[u8;32]>` — the 32-byte **seed**, loaded from the file path;
`gateway.rs:161` `mask_operator_pubkey: Option<[u8;32]>`; `gateway.rs:166`
`mask_verify_mode`) via `main.rs:538-541`, and the gateway hands them to the
`MaskStore` constructor at `gateway.rs:945-962` (the same derive-pubkey-from-
signing-key fallback is applied there for the store). `MaskStore::new`
(`mask_store.rs:73-91`) keeps `signing_key` (signs generated masks, §4 site 2),
`operator_pubkey` and `verify_mode` (disk-load verification, §4 site 1).

`deploy/config/server.json.example` ships the three keys explicitly:

```json
  "mask_verify_mode": "warn",
  "mask_signing_key": null,
  "mask_operator_pubkey": null,
```

### Client (desktop CLI)

- Flags: `--mask-operator-pubkey` (base64) and `--mask-verify-mode`
  (`crates/aivpn-client/src/main.rs:44-52`); config-file fields of the same
  names (`main.rs:238-239`).
- **Out-of-box distribution: the `mop` connection-key field.** When the server
  builds a connection key (`--add-client` / `--show-client`), it embeds the
  operator pubkey as `"mop"` in the `aivpn://` JSON (`main.rs:940-951` server
  side) — right next to `"sk"`, the server *transport* signing pubkey
  (`main.rs:934-939`; note these are two different keys for two different
  checks). The client resolves the pubkey as CLI → config file → `mop` field
  (`crates/aivpn-client/src/main.rs:785-803`) and the mode as CLI → config →
  default `warn` (`main.rs:804-811`), then passes both into `ClientConfig`
  (`main.rs:1205-1206` → `client.rs:180,186`).

So a client provisioned with a connection key minted by a signing-enabled
server verifies pushed masks **with zero manual configuration** — in `warn`
mode, logging only. Mobile cores: not yet (§4, FFI plumbing pending); they run
the shared hook as `(None, warn)`.

---

## 7. The `warn` → `enforce` rollout — why the default MUST stay `warn`

`MaskVerifyMode::default()` is `Warn` (`mask.rs:314-315`) and
`server.json.example` ships `"warn"`. This is not caution for its own sake —
`enforce`-by-default would break correct deployments out of the box:

1. **Fielded corpora are unsigned.** Every mask generated before Phase B, and
   every mask generated today on a server without `--mask-signing-key`,
   carries `signature=[0u8;64]`. Under `enforce` the server's own mask dir
   would empty itself on the next restart.
2. **Fielded clients have no operator pubkey.** Only connection keys minted
   *after* the operator configures signing carry `mop`; every existing client
   resolves `operator_pubkey = None`. Under `enforce`, `NoOperatorKey` fails
   closed (§3) — those clients would reject **every** MaskUpdate, including
   legitimate rotations triggered by neural resonance, degrading them onto a
   possibly-compromised mask forever.
3. **The mobile cores cannot receive the pubkey yet** (§4). `enforce` there is
   not even expressible until the FFI grows the parameters.

Hence the shipped ladder, each rung config-gated, no flag day:

| stage | operator action | effect |
|---|---|---|
| 0. `warn`, no key *(shipped default)* | none | silent no-op everywhere (`NoOperatorKey`, log guarded by `pubkey.is_some()`) |
| 1. `warn` + key | `--gen-mask-signing-key`; set `mask_signing_key`; `--sign-mask-dir` the corpus | new masks signed; unsigned/invalid masks **logged** on server load and client apply — field telemetry on what is still unsigned |
| 2. re-key clients | re-issue connection keys (now carrying `mop`); embed the operator pubkey in shipped client builds/configs — **this is the Part 4b release task** | clients verify in `warn`, logging failures |
| 3. `enforce` | set `mask_verify_mode=enforce` on servers, then on clients | unsigned/tampered masks rejected everywhere; a mask that skipped the sign step is caught downstream (`docs/R2_PHASE_E.md` §5) |
| 4. `production-secure` *(future)* | drop the `mask_gen.rs:16-21` `compile_error!` by making the signing key mandatory and defaulting `enforce` | hardened builds strict by default |

**Legacy/unsigned handling per mode** (behavior at every call-site, from the
§3 truth table): `off` — accepted, no check, no log. `warn` + key — accepted
with a warning naming the detail (`Unsigned` vs `Invalid`) and, on the server,
the remediation ("Re-sign it or set mask_verify_mode=enforce once the corpus
is signed", `mask_store.rs:330-332`). `enforce` — rejected: on disk load the
file is skipped (`error!`, `mask_store.rs:320-326`); on `MaskUpdate` the push
is dropped and the current mask kept (`client.rs:1706-1712`).

The design's intermediate *enforce-new* stage (reject unsigned masks with
`created_at` after a signed cutoff, grandfather older — `docs/R2_DESIGN.md`
Part 3) is **not** implemented; the shipped enum is the simpler
`off|warn|enforce`. The stage-1 `warn` telemetry plus `--sign-mask-dir` (which
signs the *whole* corpus in one command, removing the need to grandfather)
made the extra mode unnecessary in practice.

---

## 8. Tests

- `crates/aivpn-common/src/mask.rs:2353-2500` — the Phase B suite:
  `phase_b_sign_verify_round_trip_generated_style` (sign → verify → any field
  edit breaks it), `phase_b_warn_mode_accepts_bad_signature`,
  `phase_b_enforce_mode_rejects_bad_signature`,
  `phase_b_off_mode_skips_verification`,
  `phase_b_warn_without_key_is_silent_noop`,
  `phase_b_verify_mode_parsing_and_default` (`FromStr` + `Warn` default),
  `phase_b_derived_variants_are_flagged`.
- `crates/aivpn-server/src/mask_gen.rs:2482,2525` —
  `phase_b_generated_mask_is_signed_when_key_configured` (generated mask +
  reverse profile verify against the operator pubkey) and
  `phase_b_generated_mask_unsigned_without_key` (no key ⇒ all-zero signature,
  pre-Phase-B behavior preserved).
- `crates/aivpn-server/src/mask_store.rs:410-482` —
  `phase_b_load_verification_modes`: disk-load behavior under `Enforce` /
  `Warn` / `Off` against a signed and an unsigned mask file (enforce rejects
  the unsigned legacy mask; warn and off load both).

All CI-safe: pure ed25519, no nDPI toolchain required.

---

## Files in this phase

- `crates/aivpn-common/src/mask.rs` — `MaskVerifyMode`, `MaskVerifyDetail`,
  `MaskVerifyResult`, `verify_mask_artifact` (297–408); full-struct
  `signing_message`/`sign`/`verify_signature` (1401–1428); `is_unsigned`
  (1434), `is_derived_variant` (1444); Phase B tests (2353–2500).
- `crates/aivpn-server/src/server.rs` — the five Phase B `ServerArgs` flags
  (183–213) with env-var aliases.
- `crates/aivpn-server/src/main.rs` — subcommand dispatch (234–242), key
  load/resolve helpers (723–826), `handle_gen_mask_signing_key` (830),
  `handle_sign_mask_dir` (863), `mop` embedding into connection keys (940–951),
  `ServerFileConfig` fields (180–192), `GatewayConfig` wiring (538–541).
- `crates/aivpn-server/src/gateway.rs` — `GatewayConfig.mask_signing_key` /
  `mask_operator_pubkey` / `mask_verify_mode` (150–166), MaskStore wiring with
  pubkey derivation (945–962).
- `crates/aivpn-server/src/mask_store.rs` — signing key + verify config on the
  store (58–102), load-time verification (312–336).
- `crates/aivpn-server/src/mask_gen.rs` — sign-after-self-test (195–210),
  updated `production-secure` `compile_error!` rationale (8–21).
- `crates/aivpn-client/src/main.rs` — client flags, config fields, `mop`
  connection-key sourcing (44–52, 785–811).
- `crates/aivpn-client/src/client.rs` — `ClientConfig.mask_operator_pubkey` /
  `mask_verify_mode` (173–186), artifact check in the `MaskUpdate` arm
  (1692–1720).
- `crates/aivpn-ios-core/src/ios_tunnel.rs` (1109–1143) and
  `crates/aivpn-android-core/src/android_tunnel.rs` (1445–1477) — shared verify
  hook at the mobile `MaskUpdate` arms (`(None, warn)` until FFI plumbing).
- `deploy/config/server.json.example`, `README.md` §"Mask Signing &
  Verification (provenance)" (+ RU/CN) — operator-facing docs (commit
  `a5cbf3a`).
- `docs/R2_PHASE_B.md` — this document.
