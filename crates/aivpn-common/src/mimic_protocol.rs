//! Per-protocol DPI-mimicry finalization.
//!
//! A [`MimicProtocol`] names the wire protocol a mask mimics and owns the
//! POST-ASSEMBLY fixups that make a fully-built `[mdh][ciphertext]` packet pass
//! that protocol's *real* DPI validation (e.g. nDPI's `is_stun`).
//!
//! This is the extension point for mimicked protocols: adding one (QUIC, DNS,
//! …) means adding a variant here and implementing its [`MimicProtocol::finalize`]
//! — nothing in the packet-build path changes. The per-protocol knowledge stays
//! in one place instead of being scattered as `spoof_protocol`-gated branches in
//! the mimicry engine.

use crate::crypto::TAG_SIZE;
use crate::mask::{MaskProfile, SpoofProtocol};
use crate::quic_initial::{build_quic_initial, QUIC_MIN_DATAGRAM};

/// The wire protocol a mask mimics, together with its post-assembly DPI fixups.
///
/// A small copy enum rather than a `dyn` trait: the set of mimicked protocols is
/// closed and known at compile time, the per-protocol state lives in the
/// [`MaskProfile`] (not the handler), and dispatch is a cheap `match`. Adding a
/// protocol is still a one-variant, one-`finalize`-arm change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProtocol {
    /// No protocol-specific fixup (raw / opaque UDP).
    Raw,
    /// WebRTC STUN (RFC 5389). Patches the STUN message-length field so
    /// `msg_len + 20 == udp_payload_len`, which nDPI's `is_stun` requires.
    Stun,
    /// QUIC (RFC 9000 / 9001). No fixup yet — see [`MimicProtocol::finalize`].
    Quic,
    /// DNS over UDP.
    Dns,
    /// TLS / HTTPS.
    Tls,
}

impl MimicProtocol {
    /// Map a mask's [`SpoofProtocol`] to the mimic-protocol handler that owns its
    /// post-assembly DPI fixups.
    pub fn for_spoof(spoof: SpoofProtocol) -> Self {
        match spoof {
            SpoofProtocol::WebRTC_STUN => MimicProtocol::Stun,
            SpoofProtocol::QUIC => MimicProtocol::Quic,
            SpoofProtocol::DNS_over_UDP => MimicProtocol::Dns,
            SpoofProtocol::HTTPS_H2 => MimicProtocol::Tls,
            SpoofProtocol::None => MimicProtocol::Raw,
        }
    }

    /// Whether this protocol *constructs* the entire datagram at build time
    /// (a variable-size, crypto-built header coalesced with aivpn's ciphertext)
    /// instead of the default in-place layout of
    /// `[mdh-with-embedded-tag][ciphertext]` + [`finalize`].
    ///
    /// QUIC is the only such protocol today: a real RFC 9001 Initial cannot be
    /// patched into a fixed buffer after the fact (its length, AEAD tag and
    /// header protection all depend on the payload), so it is emitted directly
    /// by [`emit`](Self::emit).
    pub fn is_constructed(&self) -> bool {
        matches!(self, MimicProtocol::Quic)
    }

    /// Construct the full outgoing datagram for a *constructed* protocol
    /// ([`is_constructed`](Self::is_constructed)). `tag` is the 8-byte resonance
    /// tag and `ciphertext` is aivpn's real encrypted payload; the returned
    /// datagram is a decoy protocol header (carrying `tag`) coalesced with
    /// `ciphertext`. Returns `None` for the default in-place protocols, which
    /// use the `[mdh][ciphertext]` + [`finalize`](Self::finalize) path instead.
    pub fn emit(&self, tag: &[u8; TAG_SIZE], ciphertext: &[u8]) -> Option<Vec<u8>> {
        match self {
            // QUIC: coalesce a genuine, decryptable RFC 9001 v1 Initial (DCID =
            // resonance tag) with aivpn's ciphertext, padded to nDPI's 1200-byte
            // Initial floor. See `quic_initial::build_quic_initial`.
            MimicProtocol::Quic => Some(build_quic_initial(tag, ciphertext, QUIC_MIN_DATAGRAM)),
            _ => None,
        }
    }

    /// Apply protocol-specific POST-ASSEMBLY fixups to a fully-built packet so it
    /// passes the mimicked protocol's real-DPI validation.
    ///
    /// Called once the entire `[mdh][ciphertext]` packet (the Variant A
    /// embedded-tag layout, protocol header at offset 0) is assembled — the same
    /// point at which the resonance tag is embedded. A no-op for protocols with
    /// no length/consistency field to reconcile.
    pub fn finalize(&self, packet: &mut [u8], mask: &MaskProfile) {
        match self {
            // STUN: reconcile the message-length field with the final packet
            // size. The exact computation lives on `MaskProfile` as this
            // handler's implementation detail.
            MimicProtocol::Stun => mask.patch_stun_length(packet),
            MimicProtocol::Quic => {
                // QUIC is a *constructed* protocol: its RFC 9001 Initial is built
                // whole by `emit()` at build time, not patched in place here.
                // See `is_constructed`/`emit`. Nothing to fix up post-assembly.
            }
            // Raw/DNS/TLS carry no post-assembly consistency field today.
            MimicProtocol::Raw | MimicProtocol::Dns | MimicProtocol::Tls => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::preset_masks;

    #[test]
    fn for_spoof_maps_every_variant() {
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::WebRTC_STUN),
            MimicProtocol::Stun
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::QUIC),
            MimicProtocol::Quic
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::DNS_over_UDP),
            MimicProtocol::Dns
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::HTTPS_H2),
            MimicProtocol::Tls
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::None),
            MimicProtocol::Raw
        );
    }

    #[test]
    fn stun_finalize_is_byte_identical_to_patch_stun_length() {
        // The refactor must not change STUN's post-assembly behavior: routing
        // through MimicProtocol::finalize produces exactly what a direct
        // patch_stun_length call would.
        let mask = preset_masks::webrtc_zoom_v3();
        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Stun);
        for total in [20usize, 21, 40, 170, 1380] {
            let mut via_finalize = vec![0u8; total];
            let mut via_direct = vec![0u8; total];
            proto.finalize(&mut via_finalize, &mask);
            mask.patch_stun_length(&mut via_direct);
            assert_eq!(via_finalize, via_direct);
            // And the nDPI is_stun invariant holds.
            let msg_len = u16::from_be_bytes([via_finalize[2], via_finalize[3]]) as usize;
            assert_eq!(msg_len + 20, total);
        }
    }

    #[test]
    fn non_stun_finalize_is_noop() {
        // QUIC (and other non-STUN) masks must leave the packet untouched.
        let mask = preset_masks::quic_https_v2();
        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Quic);
        let mut packet = vec![0xABu8; 200];
        proto.finalize(&mut packet, &mask);
        assert_eq!(packet, vec![0xABu8; 200]);
    }
}
