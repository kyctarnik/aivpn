//! AIVPN Wire Protocol
//!
//! Implements packet format, inner payload encoding, and control messages

use bytes::{BufMut, BytesMut};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{POLY1305_TAG_SIZE, TAG_SIZE};
use crate::error::{Error, Result};
use crate::network_config::ClientNetworkConfig;

/// Maximum UDP packet size (optimized for VPN MTU 1420 + overhead)
pub const MAX_PACKET_SIZE: usize = 1500;

/// Minimum header overhead (tag + pad_len + inner_header + poly1305)
pub const MIN_HEADER_OVERHEAD: usize = TAG_SIZE + 2 + 4 + POLY1305_TAG_SIZE;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - MIN_HEADER_OVERHEAD;

/// Inner payload types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum InnerType {
    Data = 0x0001,
    Control = 0x0002,
    Fragment = 0x0003,
    Ack = 0x0004,
    /// FEC repair packet — XOR of N preceding data packets
    FecRepair = 0x0005,
}

impl InnerType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Data),
            0x0002 => Some(Self::Control),
            0x0003 => Some(Self::Fragment),
            0x0004 => Some(Self::Ack),
            0x0005 => Some(Self::FecRepair),
            _ => None,
        }
    }
}

/// Control message subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlSubtype {
    KeyRotate = 0x01,
    MaskUpdate = 0x02,
    Keepalive = 0x03,
    TelemetryRequest = 0x04,
    TelemetryResponse = 0x05,
    TimeSync = 0x06,
    Shutdown = 0x07,
    ControlAck = 0x08,
    ServerHello = 0x09,
    RecordingStart = 0x0A,
    RecordingAck = 0x0B,
    RecordingStop = 0x0C,
    RecordingComplete = 0x0D,
    RecordingFailed = 0x0E,
    RecordingStatusRequest = 0x0F,
    RecordingStatus = 0x10,
    BootstrapDescriptorUpdate = 0x11,
    PoolSync = 0x12,
    /// Site-to-site subnet advertisement (0x13)
    RouteSync = 0x13,
    /// Multi-hop forwarded data packet (0x14)
    ChainForward = 0x14,
    /// Client mTLS certificate presentation (0x15)
    ClientCert = 0x15,
    /// Server notification that a ClientCert was rejected (0x16)
    CertRejected = 0x16,
    /// Device enrollment — client proves static X25519 key ownership via DH (0x17)
    DeviceEnrollment = 0x17,
    /// Server echoes keepalive timestamp for RTT measurement (0x18)
    KeepaliveAck = 0x18,
    /// Quality metrics report (0x19)
    QualityReport = 0x19,
    /// Server hints client to change adaptive mode level (0x1A)
    AdaptiveHint = 0x1A,
}

impl ControlSubtype {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::KeyRotate),
            0x02 => Some(Self::MaskUpdate),
            0x03 => Some(Self::Keepalive),
            0x04 => Some(Self::TelemetryRequest),
            0x05 => Some(Self::TelemetryResponse),
            0x06 => Some(Self::TimeSync),
            0x07 => Some(Self::Shutdown),
            0x08 => Some(Self::ControlAck),
            0x09 => Some(Self::ServerHello),
            0x0A => Some(Self::RecordingStart),
            0x0B => Some(Self::RecordingAck),
            0x0C => Some(Self::RecordingStop),
            0x0D => Some(Self::RecordingComplete),
            0x0E => Some(Self::RecordingFailed),
            0x0F => Some(Self::RecordingStatusRequest),
            0x10 => Some(Self::RecordingStatus),
            0x11 => Some(Self::BootstrapDescriptorUpdate),
            0x12 => Some(Self::PoolSync),
            0x13 => Some(Self::RouteSync),
            0x14 => Some(Self::ChainForward),
            0x15 => Some(Self::ClientCert),
            0x16 => Some(Self::CertRejected),
            0x17 => Some(Self::DeviceEnrollment),
            0x18 => Some(Self::KeepaliveAck),
            0x19 => Some(Self::QualityReport),
            0x1A => Some(Self::AdaptiveHint),
            _ => None,
        }
    }
}

/// Inner payload header (after decryption)
#[derive(Debug, Clone)]
pub struct InnerHeader {
    pub inner_type: InnerType,
    pub seq_num: u16,
}

impl InnerHeader {
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&(self.inner_type as u16).to_le_bytes());
        buf[2..4].copy_from_slice(&self.seq_num.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidPacket("Inner header too short"));
        }
        let inner_type = InnerType::from_u16(u16::from_le_bytes([data[0], data[1]]))
            .ok_or(Error::InvalidPacket("Unknown inner type"))?;
        let seq_num = u16::from_le_bytes([data[2], data[3]]);
        Ok(Self {
            inner_type,
            seq_num,
        })
    }
}

/// AIVPN Packet structure
#[derive(Debug, Clone)]
pub struct AivpnPacket {
    pub resonance_tag: [u8; TAG_SIZE],
    pub mask_dependent_header: Vec<u8>,
    pub pad_len: u16,
    pub encrypted_payload: Vec<u8>,
    pub random_padding: Vec<u8>,
}

impl AivpnPacket {
    pub fn new(
        resonance_tag: [u8; TAG_SIZE],
        mask_dependent_header: Vec<u8>,
        encrypted_payload: Vec<u8>,
        padding_len: u16,
    ) -> Self {
        Self {
            resonance_tag,
            mask_dependent_header,
            pad_len: padding_len,
            encrypted_payload,
            random_padding: {
                let mut pad = vec![0u8; padding_len as usize];
                rand::thread_rng().fill_bytes(&mut pad);
                pad
            },
        }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let total_len = TAG_SIZE
            + self.mask_dependent_header.len()
            + 2 // pad_len
            + self.encrypted_payload.len()
            + self.random_padding.len();

        let mut buf = BytesMut::with_capacity(total_len);
        buf.put_slice(&self.resonance_tag);
        buf.put_slice(&self.mask_dependent_header);
        buf.put_u16_le(self.pad_len);
        buf.put_slice(&self.encrypted_payload);
        buf.put_slice(&self.random_padding);
        buf
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Packet too short"));
        }

        let mut cursor = 0;

        // Resonance tag
        let mut resonance_tag = [0u8; TAG_SIZE];
        resonance_tag.copy_from_slice(&data[cursor..cursor + TAG_SIZE]);
        cursor += TAG_SIZE;

        // We need to know the mask-dependent header length to parse correctly
        // This is determined by the active Mask profile
        // For now, we'll parse it in the server/client with mask context
        // Return raw data for upper layers to parse
        let _remaining = &data[cursor..];

        Ok(Self {
            resonance_tag,
            mask_dependent_header: Vec::new(),
            pad_len: 0,
            encrypted_payload: Vec::new(),
            random_padding: Vec::new(),
        })
    }

    /// Parse with mask context (knowing MDH length)
    pub fn from_bytes_with_mdh_len(data: &[u8], mdh_len: usize) -> Result<Self> {
        if data.len() < TAG_SIZE + mdh_len + 2 {
            return Err(Error::InvalidPacket("Packet too short"));
        }

        let mut cursor = 0;

        // Resonance tag
        let mut resonance_tag = [0u8; TAG_SIZE];
        resonance_tag.copy_from_slice(&data[cursor..cursor + TAG_SIZE]);
        cursor += TAG_SIZE;

        // Mask-dependent header
        let mask_dependent_header = data[cursor..cursor + mdh_len].to_vec();
        cursor += mdh_len;

        // Pad length
        let pad_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;

        // Encrypted payload (everything except padding)
        let remaining = data.len().saturating_sub(cursor);
        if pad_len as usize > remaining {
            return Err(Error::InvalidPacket("pad_len exceeds packet bounds"));
        }
        let payload_len = remaining - pad_len as usize;
        let encrypted_payload = data[cursor..cursor + payload_len].to_vec();
        cursor += payload_len;

        // Random padding
        let random_padding = data[cursor..].to_vec();

        Ok(Self {
            resonance_tag,
            mask_dependent_header,
            pad_len,
            encrypted_payload,
            random_padding,
        })
    }
}

/// Control message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlPayload {
    KeyRotate {
        new_eph_pub: [u8; 32],
    },
    MaskUpdate {
        mask_data: Vec<u8>,
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    },
    Keepalive {
        send_ts: u64,
    },
    TelemetryRequest {
        metric_flags: u8,
    },
    TelemetryResponse {
        packet_loss: u16,
        rtt_ms: u16,
        jitter_ms: u16,
        buffer_pct: u8,
    },
    TimeSync {
        server_ts_ms: u64,
    },
    Shutdown {
        reason: u8,
    },
    ControlAck {
        ack_seq: u16,
        ack_for_subtype: u8,
    },
    ServerHello {
        server_eph_pub: [u8; 32],
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
        network_config: Option<ClientNetworkConfig>,
    },
    /// Admin requests recording start for a service
    RecordingStart {
        service: String,
    },
    /// Server acknowledges recording start
    RecordingAck {
        session_id: [u8; 16],
        status: String,
    },
    /// Admin requests recording stop
    RecordingStop {
        session_id: [u8; 16],
    },
    /// Server reports mask generation complete
    RecordingComplete {
        service: String,
        mask_id: String,
        confidence: f32,
    },
    /// Server reports recording/generation failure
    RecordingFailed {
        reason: String,
    },
    /// Client asks whether the current authenticated session may record masks.
    RecordingStatusRequest,
    /// Server reports recording capability and current active recording state.
    RecordingStatus {
        can_record: bool,
        active_service: Option<String>,
    },
    BootstrapDescriptorUpdate {
        descriptor_data: Vec<u8>,
    },
    /// Carries a full clients.json snapshot for pool-node synchronization.
    PoolSync {
        clients_json: Vec<u8>,
    },
    /// Site-to-site subnet advertisement — JSON array of CIDR strings.
    RouteSync {
        subnets_json: Vec<u8>,
    },
    /// Multi-hop chain-forward — raw inner IP payload to NAT-forward at exit node.
    ChainForward {
        payload: Vec<u8>,
    },
    /// Client mTLS certificate — 104-byte SimpleCert sent after session setup.
    ClientCert {
        cert_bytes: Vec<u8>,
    },
    /// Server rejection of a ClientCert — client should re-provision its certificate.
    CertRejected {},
    /// Device enrollment — client proves ownership of its static X25519 keypair.
    /// Sent by client after ServerHello using ratcheted session keys.
    /// `dh_proof` = X25519(static_priv, server_static_pub) — proves private key possession.
    DeviceEnrollment {
        static_pub: [u8; 32],
        dh_proof: [u8; 32],
    },
    /// Server echoes client's keepalive timestamp for RTT measurement.
    KeepaliveAck {
        /// Echo of the timestamp sent by client in the keepalive
        echo_ts: u64,
    },
    /// Quality metrics report sent by client or server.
    QualityReport {
        /// 0–100 composite quality score
        quality: u8,
        /// Round-trip time (EWMA) in milliseconds
        rtt_ms: u16,
        /// Packet loss in parts-per-million
        loss_ppm: u32,
        /// Jitter (EWMA) in milliseconds
        jitter_ms: u16,
    },
    /// Server instructs client to switch adaptive mode level.
    AdaptiveHint {
        /// 0=Off, 1=Light, 2=Aggressive, 3=Satellite
        level: u8,
    },
}

impl ControlPayload {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        match self {
            Self::KeyRotate { new_eph_pub } => {
                buf.push(ControlSubtype::KeyRotate as u8);
                buf.push(0); // reserved
                buf.extend_from_slice(&(new_eph_pub.len() as u16).to_le_bytes());
                buf.extend_from_slice(new_eph_pub);
            }
            Self::MaskUpdate {
                mask_data,
                signature,
            } => {
                buf.push(ControlSubtype::MaskUpdate as u8);
                buf.extend_from_slice(&(mask_data.len() as u16).to_le_bytes());
                buf.extend_from_slice(mask_data);
                buf.extend_from_slice(signature);
            }
            Self::Keepalive { send_ts } => {
                buf.push(ControlSubtype::Keepalive as u8);
                buf.extend_from_slice(&send_ts.to_le_bytes());
            }
            Self::TelemetryRequest { metric_flags } => {
                buf.push(ControlSubtype::TelemetryRequest as u8);
                buf.push(*metric_flags);
            }
            Self::TelemetryResponse {
                packet_loss,
                rtt_ms,
                jitter_ms,
                buffer_pct,
            } => {
                buf.push(ControlSubtype::TelemetryResponse as u8);
                buf.push(0); // flags
                buf.extend_from_slice(&packet_loss.to_le_bytes());
                buf.extend_from_slice(&rtt_ms.to_le_bytes());
                buf.extend_from_slice(&jitter_ms.to_le_bytes());
                buf.push(*buffer_pct);
                buf.extend_from_slice(&[0u8; 3]); // reserved
            }
            Self::TimeSync { server_ts_ms } => {
                buf.push(ControlSubtype::TimeSync as u8);
                buf.extend_from_slice(&server_ts_ms.to_le_bytes());
            }
            Self::Shutdown { reason } => {
                buf.push(ControlSubtype::Shutdown as u8);
                buf.push(*reason);
            }
            Self::ControlAck {
                ack_seq,
                ack_for_subtype,
            } => {
                buf.push(ControlSubtype::ControlAck as u8);
                buf.extend_from_slice(&ack_seq.to_le_bytes());
                buf.push(*ack_for_subtype);
            }
            Self::ServerHello {
                server_eph_pub,
                signature,
                network_config,
            } => {
                buf.push(ControlSubtype::ServerHello as u8);
                buf.extend_from_slice(server_eph_pub);
                buf.extend_from_slice(signature);
                if let Some(network_config) = network_config {
                    buf.extend_from_slice(&network_config.encode_wire());
                }
            }
            Self::RecordingStart { service } => {
                buf.push(ControlSubtype::RecordingStart as u8);
                let service_bytes = service.as_bytes();
                buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(service_bytes);
            }
            Self::RecordingAck { session_id, status } => {
                buf.push(ControlSubtype::RecordingAck as u8);
                buf.extend_from_slice(session_id);
                let status_bytes = status.as_bytes();
                buf.extend_from_slice(&(status_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(status_bytes);
            }
            Self::RecordingStop { session_id } => {
                buf.push(ControlSubtype::RecordingStop as u8);
                buf.extend_from_slice(session_id);
            }
            Self::RecordingComplete {
                service,
                mask_id,
                confidence,
            } => {
                buf.push(ControlSubtype::RecordingComplete as u8);
                let service_bytes = service.as_bytes();
                buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(service_bytes);
                let mask_id_bytes = mask_id.as_bytes();
                buf.extend_from_slice(&(mask_id_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(mask_id_bytes);
                buf.extend_from_slice(&confidence.to_le_bytes());
            }
            Self::RecordingFailed { reason } => {
                buf.push(ControlSubtype::RecordingFailed as u8);
                let reason_bytes = reason.as_bytes();
                buf.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(reason_bytes);
            }
            Self::RecordingStatusRequest => {
                buf.push(ControlSubtype::RecordingStatusRequest as u8);
            }
            Self::RecordingStatus {
                can_record,
                active_service,
            } => {
                buf.push(ControlSubtype::RecordingStatus as u8);
                let mut flags = 0u8;
                if *can_record {
                    flags |= 0x01;
                }
                if active_service.is_some() {
                    flags |= 0x02;
                }
                buf.push(flags);
                if let Some(service) = active_service {
                    let service_bytes = service.as_bytes();
                    buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(service_bytes);
                }
            }
            Self::BootstrapDescriptorUpdate { descriptor_data } => {
                buf.push(ControlSubtype::BootstrapDescriptorUpdate as u8);
                buf.extend_from_slice(&(descriptor_data.len() as u16).to_le_bytes());
                buf.extend_from_slice(descriptor_data);
            }
            Self::PoolSync { clients_json } => {
                buf.push(ControlSubtype::PoolSync as u8);
                buf.extend_from_slice(&(clients_json.len() as u32).to_le_bytes());
                buf.extend_from_slice(clients_json);
            }
            Self::RouteSync { subnets_json } => {
                buf.push(ControlSubtype::RouteSync as u8);
                buf.extend_from_slice(&(subnets_json.len() as u32).to_le_bytes());
                buf.extend_from_slice(subnets_json);
            }
            Self::ChainForward { payload } => {
                buf.push(ControlSubtype::ChainForward as u8);
                buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                buf.extend_from_slice(payload);
            }
            Self::ClientCert { cert_bytes } => {
                buf.push(ControlSubtype::ClientCert as u8);
                buf.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(cert_bytes);
            }
            Self::CertRejected {} => {
                buf.push(ControlSubtype::CertRejected as u8);
            }
            Self::DeviceEnrollment {
                static_pub,
                dh_proof,
            } => {
                buf.push(ControlSubtype::DeviceEnrollment as u8);
                buf.extend_from_slice(static_pub);
                buf.extend_from_slice(dh_proof);
            }
            Self::KeepaliveAck { echo_ts } => {
                buf.push(ControlSubtype::KeepaliveAck as u8);
                buf.extend_from_slice(&echo_ts.to_le_bytes());
            }
            Self::QualityReport {
                quality,
                rtt_ms,
                loss_ppm,
                jitter_ms,
            } => {
                buf.push(ControlSubtype::QualityReport as u8);
                buf.push(*quality);
                buf.extend_from_slice(&rtt_ms.to_le_bytes());
                buf.extend_from_slice(&loss_ppm.to_le_bytes());
                buf.extend_from_slice(&jitter_ms.to_le_bytes());
            }
            Self::AdaptiveHint { level } => {
                buf.push(ControlSubtype::AdaptiveHint as u8);
                buf.push(*level);
            }
        }

        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidPacket("Empty control payload"));
        }

        let subtype = ControlSubtype::from_u8(data[0])
            .ok_or(Error::InvalidPacket("Unknown control subtype"))?;

        match subtype {
            ControlSubtype::KeyRotate => {
                if data.len() < 6 {
                    return Err(Error::InvalidPacket("KeyRotate too short"));
                }
                let new_eph_pub_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                if new_eph_pub_len != 32 {
                    return Err(Error::InvalidPacket(
                        "KeyRotate: invalid eph pub key length",
                    ));
                }
                if data.len() < 4 + new_eph_pub_len {
                    return Err(Error::InvalidPacket("KeyRotate invalid length"));
                }
                let mut new_eph_pub = [0u8; 32];
                new_eph_pub.copy_from_slice(&data[4..4 + 32]);
                Ok(Self::KeyRotate { new_eph_pub })
            }
            ControlSubtype::MaskUpdate => {
                if data.len() < 4 {
                    return Err(Error::InvalidPacket("MaskUpdate too short"));
                }
                let mask_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + mask_len + 64 {
                    return Err(Error::InvalidPacket("MaskUpdate invalid length"));
                }
                let mask_data = data[3..3 + mask_len].to_vec();
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[3 + mask_len..3 + mask_len + 64]);
                Ok(Self::MaskUpdate {
                    mask_data,
                    signature,
                })
            }
            ControlSubtype::Keepalive => {
                let send_ts = if data.len() >= 9 {
                    u64::from_le_bytes(data[1..9].try_into().unwrap())
                } else {
                    0
                };
                Ok(Self::Keepalive { send_ts })
            }
            ControlSubtype::TelemetryRequest => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("TelemetryRequest too short"));
                }
                Ok(Self::TelemetryRequest {
                    metric_flags: data[1],
                })
            }
            ControlSubtype::TelemetryResponse => {
                if data.len() < 12 {
                    return Err(Error::InvalidPacket("TelemetryResponse too short"));
                }
                Ok(Self::TelemetryResponse {
                    packet_loss: u16::from_le_bytes([data[2], data[3]]),
                    rtt_ms: u16::from_le_bytes([data[4], data[5]]),
                    jitter_ms: u16::from_le_bytes([data[6], data[7]]),
                    buffer_pct: data[8],
                })
            }
            ControlSubtype::TimeSync => {
                if data.len() < 9 {
                    return Err(Error::InvalidPacket("TimeSync too short"));
                }
                Ok(Self::TimeSync {
                    server_ts_ms: u64::from_le_bytes(data[1..9].try_into().unwrap()),
                })
            }
            ControlSubtype::Shutdown => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("Shutdown too short"));
                }
                Ok(Self::Shutdown { reason: data[1] })
            }
            ControlSubtype::ControlAck => {
                if data.len() < 4 {
                    return Err(Error::InvalidPacket("ControlAck too short"));
                }
                Ok(Self::ControlAck {
                    ack_seq: u16::from_le_bytes([data[1], data[2]]),
                    ack_for_subtype: data[3],
                })
            }
            ControlSubtype::ServerHello => {
                if data.len() < 1 + 32 + 64 {
                    return Err(Error::InvalidPacket("ServerHello too short"));
                }
                let mut server_eph_pub = [0u8; 32];
                server_eph_pub.copy_from_slice(&data[1..33]);
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[33..97]);
                let network_config = if data.len() >= 97 + 12 {
                    let end = (97 + ClientNetworkConfig::WIRE_SIZE).min(data.len());
                    Some(ClientNetworkConfig::decode_wire(&data[97..end])?)
                } else {
                    None
                };
                Ok(Self::ServerHello {
                    server_eph_pub,
                    signature,
                    network_config,
                })
            }
            ControlSubtype::RecordingStart => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingStart too short"));
                }
                let svc_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + svc_len {
                    return Err(Error::InvalidPacket("RecordingStart invalid length"));
                }
                let service = String::from_utf8_lossy(&data[3..3 + svc_len]).to_string();
                Ok(Self::RecordingStart { service })
            }
            ControlSubtype::RecordingAck => {
                if data.len() < 1 + 16 + 2 {
                    return Err(Error::InvalidPacket("RecordingAck too short"));
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&data[1..17]);
                let status_len = u16::from_le_bytes([data[17], data[18]]) as usize;
                if data.len() < 19 + status_len {
                    return Err(Error::InvalidPacket("RecordingAck invalid length"));
                }
                let status = String::from_utf8_lossy(&data[19..19 + status_len]).to_string();
                Ok(Self::RecordingAck { session_id, status })
            }
            ControlSubtype::RecordingStop => {
                if data.len() < 17 {
                    return Err(Error::InvalidPacket("RecordingStop too short"));
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&data[1..17]);
                Ok(Self::RecordingStop { session_id })
            }
            ControlSubtype::RecordingComplete => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingComplete too short"));
                }
                let mut cursor = 1;
                let svc_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
                cursor += 2;
                if data.len() < cursor + svc_len + 2 + 4 {
                    return Err(Error::InvalidPacket("RecordingComplete invalid length"));
                }
                let service = String::from_utf8_lossy(&data[cursor..cursor + svc_len]).to_string();
                cursor += svc_len;
                let mid_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
                cursor += 2;
                if data.len() < cursor + mid_len + 4 {
                    return Err(Error::InvalidPacket("RecordingComplete invalid mask_id"));
                }
                let mask_id = String::from_utf8_lossy(&data[cursor..cursor + mid_len]).to_string();
                cursor += mid_len;
                let confidence = f32::from_le_bytes([
                    data[cursor],
                    data[cursor + 1],
                    data[cursor + 2],
                    data[cursor + 3],
                ]);
                Ok(Self::RecordingComplete {
                    service,
                    mask_id,
                    confidence,
                })
            }
            ControlSubtype::RecordingFailed => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingFailed too short"));
                }
                let reason_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + reason_len {
                    return Err(Error::InvalidPacket("RecordingFailed invalid length"));
                }
                let reason = String::from_utf8_lossy(&data[3..3 + reason_len]).to_string();
                Ok(Self::RecordingFailed { reason })
            }
            ControlSubtype::RecordingStatusRequest => Ok(Self::RecordingStatusRequest),
            ControlSubtype::RecordingStatus => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("RecordingStatus too short"));
                }
                let flags = data[1];
                let can_record = (flags & 0x01) != 0;
                let has_service = (flags & 0x02) != 0;
                let active_service = if has_service {
                    if data.len() < 4 {
                        return Err(Error::InvalidPacket(
                            "RecordingStatus missing service length",
                        ));
                    }
                    let service_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                    if data.len() < 4 + service_len {
                        return Err(Error::InvalidPacket(
                            "RecordingStatus invalid service length",
                        ));
                    }
                    Some(String::from_utf8_lossy(&data[4..4 + service_len]).to_string())
                } else {
                    None
                };
                Ok(Self::RecordingStatus {
                    can_record,
                    active_service,
                })
            }
            ControlSubtype::BootstrapDescriptorUpdate => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("BootstrapDescriptorUpdate too short"));
                }
                let descriptor_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + descriptor_len {
                    return Err(Error::InvalidPacket(
                        "BootstrapDescriptorUpdate invalid length",
                    ));
                }
                Ok(Self::BootstrapDescriptorUpdate {
                    descriptor_data: data[3..3 + descriptor_len].to_vec(),
                })
            }
            ControlSubtype::PoolSync => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("PoolSync too short"));
                }
                let payload_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + payload_len {
                    return Err(Error::InvalidPacket("PoolSync invalid length"));
                }
                Ok(Self::PoolSync {
                    clients_json: data[5..5 + payload_len].to_vec(),
                })
            }
            ControlSubtype::RouteSync => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("RouteSync too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + len {
                    return Err(Error::InvalidPacket("RouteSync invalid length"));
                }
                Ok(Self::RouteSync {
                    subnets_json: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::ChainForward => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("ChainForward too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + len {
                    return Err(Error::InvalidPacket("ChainForward invalid length"));
                }
                Ok(Self::ChainForward {
                    payload: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::ClientCert => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("ClientCert too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + len {
                    return Err(Error::InvalidPacket("ClientCert invalid length"));
                }
                Ok(Self::ClientCert {
                    cert_bytes: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::CertRejected => Ok(Self::CertRejected {}),
            ControlSubtype::DeviceEnrollment => {
                if data.len() < 65 {
                    return Err(Error::InvalidPacket("DeviceEnrollment too short"));
                }
                let mut static_pub = [0u8; 32];
                let mut dh_proof = [0u8; 32];
                static_pub.copy_from_slice(&data[1..33]);
                dh_proof.copy_from_slice(&data[33..65]);
                Ok(Self::DeviceEnrollment {
                    static_pub,
                    dh_proof,
                })
            }
            ControlSubtype::KeepaliveAck => {
                if data.len() < 9 {
                    return Err(Error::InvalidPacket("KeepaliveAck too short"));
                }
                let echo_ts = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Ok(Self::KeepaliveAck { echo_ts })
            }
            ControlSubtype::QualityReport => {
                if data.len() < 10 {
                    return Err(Error::InvalidPacket("QualityReport too short"));
                }
                Ok(Self::QualityReport {
                    quality: data[1],
                    rtt_ms: u16::from_le_bytes([data[2], data[3]]),
                    loss_ppm: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
                    jitter_ms: u16::from_le_bytes([data[8], data[9]]),
                })
            }
            ControlSubtype::AdaptiveHint => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("AdaptiveHint too short"));
                }
                Ok(Self::AdaptiveHint { level: data[1] })
            }
        }
    }
}

/// ACK packet for selective acknowledgment
#[derive(Debug, Clone)]
pub struct AckPacket {
    pub ack_seq: u16,
    pub ack_base: u16,
    pub bitmap: Vec<u8>,
}

impl AckPacket {
    pub fn new(ack_seq: u16, ack_base: u16, bitmap: Vec<u8>) -> Self {
        Self {
            ack_seq,
            ack_base,
            bitmap,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.bitmap.len());
        buf.extend_from_slice(&(InnerType::Ack as u16).to_le_bytes());
        buf.extend_from_slice(&self.ack_seq.to_le_bytes());
        buf.extend_from_slice(&self.ack_base.to_le_bytes());
        buf.push(self.bitmap.len() as u8);
        buf.extend_from_slice(&self.bitmap);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 7 {
            return Err(Error::InvalidPacket("ACK too short"));
        }
        let ack_seq = u16::from_le_bytes([data[2], data[3]]);
        let ack_base = u16::from_le_bytes([data[4], data[5]]);
        let bitmap_len = data[6] as usize;
        if data.len() < 7 + bitmap_len {
            return Err(Error::InvalidPacket("ACK invalid length"));
        }
        let bitmap = data[7..7 + bitmap_len].to_vec();
        Ok(Self {
            ack_seq,
            ack_base,
            bitmap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // InnerType::from_u16
    // -----------------------------------------------------------------------

    #[test]
    fn inner_type_roundtrip_all_variants() {
        let variants = [
            (0x0001u16, InnerType::Data),
            (0x0002, InnerType::Control),
            (0x0003, InnerType::Fragment),
            (0x0004, InnerType::Ack),
            (0x0005, InnerType::FecRepair),
        ];
        for (v, expected) in variants {
            assert_eq!(InnerType::from_u16(v), Some(expected));
        }
        assert_eq!(InnerType::from_u16(0x0000), None);
        assert_eq!(InnerType::from_u16(0x0006), None);
    }

    // -----------------------------------------------------------------------
    // ControlSubtype::from_u8
    // -----------------------------------------------------------------------

    #[test]
    fn control_subtype_from_u8_all_variants() {
        let pairs: &[(u8, ControlSubtype)] = &[
            (0x01, ControlSubtype::KeyRotate),
            (0x02, ControlSubtype::MaskUpdate),
            (0x03, ControlSubtype::Keepalive),
            (0x04, ControlSubtype::TelemetryRequest),
            (0x05, ControlSubtype::TelemetryResponse),
            (0x06, ControlSubtype::TimeSync),
            (0x07, ControlSubtype::Shutdown),
            (0x08, ControlSubtype::ControlAck),
            (0x09, ControlSubtype::ServerHello),
            (0x0A, ControlSubtype::RecordingStart),
            (0x0B, ControlSubtype::RecordingAck),
            (0x0C, ControlSubtype::RecordingStop),
            (0x0D, ControlSubtype::RecordingComplete),
            (0x0E, ControlSubtype::RecordingFailed),
            (0x0F, ControlSubtype::RecordingStatusRequest),
            (0x10, ControlSubtype::RecordingStatus),
            (0x11, ControlSubtype::BootstrapDescriptorUpdate),
            (0x12, ControlSubtype::PoolSync),
            (0x13, ControlSubtype::RouteSync),
            (0x14, ControlSubtype::ChainForward),
            (0x15, ControlSubtype::ClientCert),
            (0x16, ControlSubtype::CertRejected),
            (0x17, ControlSubtype::DeviceEnrollment),
            (0x18, ControlSubtype::KeepaliveAck),
            (0x19, ControlSubtype::QualityReport),
            (0x1A, ControlSubtype::AdaptiveHint),
        ];
        for (byte, expected) in pairs {
            assert_eq!(
                ControlSubtype::from_u8(*byte),
                Some(*expected),
                "byte={:#04x}",
                byte
            );
        }
        assert_eq!(ControlSubtype::from_u8(0x00), None);
        assert_eq!(ControlSubtype::from_u8(0x1B), None);
    }

    // -----------------------------------------------------------------------
    // InnerHeader encode / decode
    // -----------------------------------------------------------------------

    #[test]
    fn inner_header_encode_decode_data() {
        let hdr = InnerHeader {
            inner_type: InnerType::Data,
            seq_num: 0x1234,
        };
        let encoded = hdr.encode();
        let decoded = InnerHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.inner_type, InnerType::Data);
        assert_eq!(decoded.seq_num, 0x1234);
    }

    #[test]
    fn inner_header_encode_decode_fragment() {
        let hdr = InnerHeader {
            inner_type: InnerType::Fragment,
            seq_num: 0xFFFF,
        };
        let encoded = hdr.encode();
        let decoded = InnerHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.inner_type, InnerType::Fragment);
        assert_eq!(decoded.seq_num, 0xFFFF);
    }

    #[test]
    fn inner_header_decode_too_short_returns_error() {
        assert!(InnerHeader::decode(&[0x01, 0x00, 0x00]).is_err());
        assert!(InnerHeader::decode(&[]).is_err());
    }

    #[test]
    fn inner_header_decode_unknown_type_returns_error() {
        // type 0x0099 is unknown
        let data = [0x99u8, 0x00, 0x01, 0x00];
        assert!(InnerHeader::decode(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // AivpnPacket encode / decode (from_bytes_with_mdh_len)
    // -----------------------------------------------------------------------

    fn make_tag() -> [u8; TAG_SIZE] {
        [0xAB; TAG_SIZE]
    }

    #[test]
    fn aivpn_packet_data_roundtrip() {
        let tag = make_tag();
        let mdh = vec![0x01, 0x02, 0x03, 0x04];
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11];
        let pkt = AivpnPacket::new(tag, mdh.clone(), payload.clone(), 0);

        let bytes = pkt.to_bytes();
        let decoded = AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).unwrap();

        assert_eq!(decoded.resonance_tag, tag);
        assert_eq!(decoded.mask_dependent_header, mdh);
        assert_eq!(decoded.pad_len, 0);
        assert_eq!(decoded.encrypted_payload, payload);
        assert!(decoded.random_padding.is_empty());
    }

    #[test]
    fn aivpn_packet_fragment_roundtrip_with_padding() {
        let tag = make_tag();
        let mdh = vec![0xAA, 0xBB];
        let payload = vec![0x01, 0x02, 0x03];
        let padding_len = 8u16;
        let pkt = AivpnPacket::new(tag, mdh.clone(), payload.clone(), padding_len);

        let bytes = pkt.to_bytes();
        let decoded = AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).unwrap();

        assert_eq!(decoded.resonance_tag, tag);
        assert_eq!(decoded.mask_dependent_header, mdh);
        assert_eq!(decoded.pad_len, padding_len);
        assert_eq!(decoded.encrypted_payload, payload);
        assert_eq!(decoded.random_padding.len(), padding_len as usize);
    }

    #[test]
    fn aivpn_packet_from_bytes_too_short_returns_error() {
        // Fewer than TAG_SIZE + 2 bytes
        let short = vec![0u8; TAG_SIZE + 1];
        assert!(AivpnPacket::from_bytes(&short).is_err());
    }

    #[test]
    fn aivpn_packet_from_bytes_with_mdh_len_too_short_returns_error() {
        // Only tag bytes, no room for mdh=4 + pad_len
        let short = vec![0u8; TAG_SIZE + 2];
        assert!(AivpnPacket::from_bytes_with_mdh_len(&short, 4).is_err());
    }

    #[test]
    fn aivpn_packet_pad_len_overflow_returns_error() {
        // Construct a packet where pad_len > remaining bytes
        let tag = make_tag();
        let mdh = vec![0x01u8; 2];
        let payload = vec![0x00u8; 4];
        let mut bytes = AivpnPacket::new(tag, mdh.clone(), payload, 0)
            .to_bytes()
            .to_vec();

        // Overwrite pad_len field (at offset TAG_SIZE + mdh.len()) with 0xFFFF
        let pad_offset = TAG_SIZE + mdh.len();
        bytes[pad_offset] = 0xFF;
        bytes[pad_offset + 1] = 0xFF;

        assert!(AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).is_err());
    }

    #[test]
    fn aivpn_packet_from_bytes_minimal_valid() {
        // Exactly TAG_SIZE + 2 bytes: tag + empty mdh + pad_len=0
        let mut data = vec![0u8; TAG_SIZE + 2];
        data[0] = 0xCC;
        let pkt = AivpnPacket::from_bytes(&data).unwrap();
        assert_eq!(pkt.resonance_tag[0], 0xCC);
    }

    // -----------------------------------------------------------------------
    // AckPacket encode / decode
    // -----------------------------------------------------------------------

    #[test]
    fn ack_packet_roundtrip_empty_bitmap() {
        let ack = AckPacket::new(100, 50, vec![]);
        let encoded = ack.encode();
        let decoded = AckPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_seq, 100);
        assert_eq!(decoded.ack_base, 50);
        assert!(decoded.bitmap.is_empty());
    }

    #[test]
    fn ack_packet_roundtrip_with_bitmap() {
        let bitmap = vec![0b10101010, 0b01010101, 0xFF];
        let ack = AckPacket::new(0xBEEF, 0x1234, bitmap.clone());
        let encoded = ack.encode();
        let decoded = AckPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_seq, 0xBEEF);
        assert_eq!(decoded.ack_base, 0x1234);
        assert_eq!(decoded.bitmap, bitmap);
    }

    #[test]
    fn ack_packet_decode_too_short_returns_error() {
        assert!(AckPacket::decode(&[0x04, 0x00, 0x01, 0x00, 0x00]).is_err());
        assert!(AckPacket::decode(&[]).is_err());
    }

    #[test]
    fn ack_packet_decode_truncated_bitmap_returns_error() {
        let ack = AckPacket::new(1, 0, vec![0xAA, 0xBB, 0xCC]);
        let mut encoded = ack.encode();
        // truncate by removing last byte
        encoded.pop();
        assert!(AckPacket::decode(&encoded).is_err());
    }

    // -----------------------------------------------------------------------
    // ControlPayload encode / decode — all variants
    // -----------------------------------------------------------------------

    fn roundtrip(payload: &ControlPayload) -> ControlPayload {
        let encoded = payload.encode().expect("encode failed");
        ControlPayload::decode(&encoded).expect("decode failed")
    }

    #[test]
    fn control_payload_key_rotate_roundtrip() {
        let new_eph_pub = [0x42u8; 32];
        let p = ControlPayload::KeyRotate { new_eph_pub };
        let decoded = roundtrip(&p);
        if let ControlPayload::KeyRotate { new_eph_pub: k } = decoded {
            assert_eq!(k, new_eph_pub);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_update_roundtrip() {
        let mask_data = vec![1u8, 2, 3, 4, 5];
        let signature = [0x7Fu8; 64];
        let p = ControlPayload::MaskUpdate {
            mask_data: mask_data.clone(),
            signature,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskUpdate {
            mask_data: md,
            signature: sig,
        } = decoded
        {
            assert_eq!(md, mask_data);
            assert_eq!(sig, signature);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_keepalive_roundtrip() {
        let p = ControlPayload::Keepalive {
            send_ts: 0xDEAD_BEEF_1234_5678,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::Keepalive { send_ts } = decoded {
            assert_eq!(send_ts, 0xDEAD_BEEF_1234_5678);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_telemetry_request_roundtrip() {
        let p = ControlPayload::TelemetryRequest {
            metric_flags: 0b0000_1111,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TelemetryRequest { metric_flags } = decoded {
            assert_eq!(metric_flags, 0b0000_1111);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_telemetry_response_roundtrip() {
        let p = ControlPayload::TelemetryResponse {
            packet_loss: 300,
            rtt_ms: 42,
            jitter_ms: 7,
            buffer_pct: 88,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TelemetryResponse {
            packet_loss,
            rtt_ms,
            jitter_ms,
            buffer_pct,
        } = decoded
        {
            assert_eq!(packet_loss, 300);
            assert_eq!(rtt_ms, 42);
            assert_eq!(jitter_ms, 7);
            assert_eq!(buffer_pct, 88);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_time_sync_roundtrip() {
        let p = ControlPayload::TimeSync {
            server_ts_ms: 1_700_000_000_000,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TimeSync { server_ts_ms } = decoded {
            assert_eq!(server_ts_ms, 1_700_000_000_000);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_shutdown_roundtrip() {
        let p = ControlPayload::Shutdown { reason: 0x05 };
        let decoded = roundtrip(&p);
        if let ControlPayload::Shutdown { reason } = decoded {
            assert_eq!(reason, 0x05);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_control_ack_roundtrip() {
        let p = ControlPayload::ControlAck {
            ack_seq: 0x1001,
            ack_for_subtype: 0x09,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ControlAck {
            ack_seq,
            ack_for_subtype,
        } = decoded
        {
            assert_eq!(ack_seq, 0x1001);
            assert_eq!(ack_for_subtype, 0x09);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_server_hello_no_network_config_roundtrip() {
        let server_eph_pub = [0x11u8; 32];
        let signature = [0x22u8; 64];
        let p = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config: None,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ServerHello {
            server_eph_pub: k,
            signature: sig,
            network_config: nc,
        } = decoded
        {
            assert_eq!(k, server_eph_pub);
            assert_eq!(sig, signature);
            assert!(nc.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_start_roundtrip() {
        let p = ControlPayload::RecordingStart {
            service: "zoom".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStart { service } = decoded {
            assert_eq!(service, "zoom");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_ack_roundtrip() {
        let session_id = [0xABu8; 16];
        let p = ControlPayload::RecordingAck {
            session_id,
            status: "ok".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingAck {
            session_id: sid,
            status,
        } = decoded
        {
            assert_eq!(sid, session_id);
            assert_eq!(status, "ok");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_stop_roundtrip() {
        let session_id = [0x01u8; 16];
        let p = ControlPayload::RecordingStop { session_id };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStop { session_id: sid } = decoded {
            assert_eq!(sid, session_id);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_complete_roundtrip() {
        let p = ControlPayload::RecordingComplete {
            service: "https".to_string(),
            mask_id: "mask-001".to_string(),
            confidence: 0.987_654,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingComplete {
            service,
            mask_id,
            confidence,
        } = decoded
        {
            assert_eq!(service, "https");
            assert_eq!(mask_id, "mask-001");
            assert!((confidence - 0.987_654f32).abs() < 1e-5);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_failed_roundtrip() {
        let p = ControlPayload::RecordingFailed {
            reason: "disk full".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingFailed { reason } = decoded {
            assert_eq!(reason, "disk full");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_status_request_roundtrip() {
        let p = ControlPayload::RecordingStatusRequest;
        let decoded = roundtrip(&p);
        assert!(matches!(decoded, ControlPayload::RecordingStatusRequest));
    }

    #[test]
    fn control_payload_recording_status_with_service_roundtrip() {
        let p = ControlPayload::RecordingStatus {
            can_record: true,
            active_service: Some("quic".to_string()),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStatus {
            can_record,
            active_service,
        } = decoded
        {
            assert!(can_record);
            assert_eq!(active_service, Some("quic".to_string()));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_status_no_service_roundtrip() {
        let p = ControlPayload::RecordingStatus {
            can_record: false,
            active_service: None,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStatus {
            can_record,
            active_service,
        } = decoded
        {
            assert!(!can_record);
            assert!(active_service.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_bootstrap_descriptor_update_roundtrip() {
        let descriptor_data = vec![0xDE, 0xAD, 0xC0, 0xDE];
        let p = ControlPayload::BootstrapDescriptorUpdate {
            descriptor_data: descriptor_data.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::BootstrapDescriptorUpdate {
            descriptor_data: dd,
        } = decoded
        {
            assert_eq!(dd, descriptor_data);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_pool_sync_roundtrip() {
        let clients_json = br#"[{"name":"alice"}]"#.to_vec();
        let p = ControlPayload::PoolSync {
            clients_json: clients_json.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::PoolSync { clients_json: cj } = decoded {
            assert_eq!(cj, clients_json);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_route_sync_roundtrip() {
        let subnets_json = br#"["10.0.0.0/8","192.168.0.0/16"]"#.to_vec();
        let p = ControlPayload::RouteSync {
            subnets_json: subnets_json.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RouteSync { subnets_json: sj } = decoded {
            assert_eq!(sj, subnets_json);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_chain_forward_roundtrip() {
        let payload = vec![0x45, 0x00, 0x00, 0x28]; // fake IP header start
        let p = ControlPayload::ChainForward {
            payload: payload.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ChainForward { payload: pl } = decoded {
            assert_eq!(pl, payload);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_client_cert_roundtrip() {
        let cert_bytes = vec![0xCCu8; 104];
        let p = ControlPayload::ClientCert {
            cert_bytes: cert_bytes.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ClientCert { cert_bytes: cb } = decoded {
            assert_eq!(cb, cert_bytes);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_cert_rejected_roundtrip() {
        let p = ControlPayload::CertRejected {};
        let decoded = roundtrip(&p);
        assert!(matches!(decoded, ControlPayload::CertRejected {}));
    }

    #[test]
    fn control_payload_device_enrollment_roundtrip() {
        let static_pub = [0x33u8; 32];
        let dh_proof = [0x44u8; 32];
        let p = ControlPayload::DeviceEnrollment {
            static_pub,
            dh_proof,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::DeviceEnrollment {
            static_pub: sp,
            dh_proof: dp,
        } = decoded
        {
            assert_eq!(sp, static_pub);
            assert_eq!(dp, dh_proof);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_keepalive_ack_roundtrip() {
        let p = ControlPayload::KeepaliveAck {
            echo_ts: 0x0102_0304_0506_0708,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::KeepaliveAck { echo_ts } = decoded {
            assert_eq!(echo_ts, 0x0102_0304_0506_0708);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_quality_report_roundtrip() {
        let p = ControlPayload::QualityReport {
            quality: 95,
            rtt_ms: 12,
            loss_ppm: 500,
            jitter_ms: 3,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::QualityReport {
            quality,
            rtt_ms,
            loss_ppm,
            jitter_ms,
        } = decoded
        {
            assert_eq!(quality, 95);
            assert_eq!(rtt_ms, 12);
            assert_eq!(loss_ppm, 500);
            assert_eq!(jitter_ms, 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_adaptive_hint_roundtrip() {
        for level in 0u8..=3 {
            let p = ControlPayload::AdaptiveHint { level };
            let decoded = roundtrip(&p);
            if let ControlPayload::AdaptiveHint { level: l } = decoded {
                assert_eq!(l, level);
            } else {
                panic!("wrong variant for level {level}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // ControlPayload::decode — malformed / too short inputs
    // -----------------------------------------------------------------------

    #[test]
    fn control_payload_decode_empty_returns_error() {
        assert!(ControlPayload::decode(&[]).is_err());
    }

    #[test]
    fn control_payload_decode_unknown_subtype_returns_error() {
        assert!(ControlPayload::decode(&[0x00]).is_err());
        assert!(ControlPayload::decode(&[0xFF]).is_err());
    }

    #[test]
    fn control_payload_key_rotate_too_short_returns_error() {
        // subtype byte only
        assert!(ControlPayload::decode(&[0x01]).is_err());
    }

    #[test]
    fn control_payload_server_hello_too_short_returns_error() {
        // only 10 bytes — needs 1+32+64=97 minimum
        let data = vec![0x09u8; 10];
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_keepalive_ack_too_short_returns_error() {
        // only 5 bytes — needs 9
        assert!(ControlPayload::decode(&[0x18, 0x01, 0x02, 0x03, 0x04]).is_err());
    }

    #[test]
    fn control_payload_adaptive_hint_too_short_returns_error() {
        assert!(ControlPayload::decode(&[0x1A]).is_err());
    }

    #[test]
    fn control_payload_pool_sync_too_short_returns_error() {
        // only 3 bytes — needs 5 for length prefix
        assert!(ControlPayload::decode(&[0x12, 0x00, 0x00]).is_err());
    }

    #[test]
    fn control_payload_pool_sync_length_exceeds_data_returns_error() {
        // subtype + length=9999 but no payload bytes
        let mut data = vec![0x12u8];
        data.extend_from_slice(&9999u32.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }
}
