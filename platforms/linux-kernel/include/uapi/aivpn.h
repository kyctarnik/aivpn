/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * aivpn.h — shared userspace/kernel UAPI header
 *
 * Included by both the kernel module (src/*.c) and userspace tools
 * (tests/user_ioctl_test.c, aivpn-server dev.rs FFI layer).
 *
 * All structs are packed to avoid ABI surprises across compilers.
 */

#ifndef _UAPI_AIVPN_H
#define _UAPI_AIVPN_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* Module API version returned by AIVPN_IOC_GET_VERSION.
 * Increment when any ioctl struct or semantic changes.
 * v3: aivpn_session_add carries tag_offset + mdh_len (Variant A wire layout).
 * v4: aivpn_session_add carries session_key_s2c (directional downlink key).
 * v5: adds AIVPN_IOC_SESSION_DOWNLINK (reserved counter block + MDH template)
 *     and AIVPN_IOC_SET_EGRESS (kernel-side downlink encrypt egress hook). */
#define AIVPN_MODULE_API_VERSION  5U

/* ioctl magic byte */
#define AIVPN_MAGIC  0xAE

/* ------------------------------------------------------------------ *
 *  Structures                                                          *
 * ------------------------------------------------------------------ */

/**
 * struct aivpn_session_add - payload for AIVPN_IOC_SESSION_ADD
 *
 * @session_id:      16-byte opaque session identifier (matches Rust [u8;16])
 * @session_key:     32-byte ChaCha20-Poly1305 key for the client->server (c2s)
 *                   uplink the kernel decrypts.
 * @session_key_s2c: 32-byte ChaCha20-Poly1305 key for the server->client (s2c)
 *                   downlink direction (used by kernel downlink encryption).
 * @tag_secret:   32-byte BLAKE3 secret used to derive resonance tags
 * @nonce_suffix:  bytes 8-11 of the 12-byte ChaCha20 nonce. The current AIVPN
 *                 protocol builds the nonce as counter_LE(8) || zeros(4), so
 *                 user-space MUST pass all zeros here; the field exists only so
 *                 a future protocol revision can introduce a real suffix without
 *                 an ABI change.
 * @tag_offset:   Variant A wire layout selector. u16::MAX (0xFFFF) = legacy
 *                (8-byte resonance tag prefixed at packet offset 0, ciphertext
 *                at TAG_SIZE + mdh_len). Otherwise the tag is embedded inside
 *                the mimic header at byte offset @tag_offset and the ciphertext
 *                starts at @mdh_len (no separate prefix).
 * @mdh_len:      mimic-header length in bytes (ciphertext-offset basis).
 * @counter_base: initial send counter value (little-endian u64)
 * @client_ip:    VPN IPv4 address assigned to this client (network byte order)
 * @client_addr:  28-byte sockaddr_storage holding UDP peer address
 * @window_ms:    tag validity window in milliseconds (default 10000)
 */
struct aivpn_session_add {
	__u8  session_id[16];
	__u8  session_key[32];     /* c2s uplink key */
	__u8  session_key_s2c[32]; /* s2c downlink key */
	__u8  tag_secret[32];
	__u8  nonce_suffix[4]; /* bytes 8-11 of the 12-byte ChaCha20 nonce */
	__u16 tag_offset;      /* Variant A: u16::MAX = legacy prefix; else embedded */
	__u16 mdh_len;         /* mimic-header length (ciphertext offset basis) */
	__u8  _reserved[24];
	__u64 counter_base;
	__u32 client_ip;
	__u8  client_addr[28];
	__u64 window_ms;
} __attribute__((packed));

/**
 * struct aivpn_session_del - payload for AIVPN_IOC_SESSION_DEL
 *
 * @session_id: 16-byte session identifier to remove
 */
struct aivpn_session_del {
	__u8 session_id[16];
} __attribute__((packed));

/**
 * struct aivpn_session_stat - payload for AIVPN_IOC_SESSION_STAT
 *
 * Fill session_id before the ioctl; the kernel fills the remaining fields.
 *
 * @session_id: 16-byte session identifier to query
 * @active:     1 if the session exists in the kernel table, 0 otherwise
 * @rx_packets: inbound packet count
 * @tx_packets: outbound packet count
 * @rx_bytes:   inbound byte count
 * @tx_bytes:   outbound byte count
 */
struct aivpn_session_stat {
	__u8  session_id[16];
	__u32 active;
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
} __attribute__((packed));

/**
 * struct aivpn_set_tun - payload for AIVPN_IOC_SET_TUN
 *
 * @ifindex: net_device ifindex of the TUN interface that decrypted
 *           packets should be injected into via netif_rx().
 */
struct aivpn_set_tun {
	__u32 ifindex;
} __attribute__((packed));

/**
 * struct aivpn_set_udp_sock - payload for AIVPN_IOC_SET_UDP_SOCK
 *
 * @fd: file descriptor of the UDP socket whose sk_data_ready the
 *      module should intercept.
 */
struct aivpn_set_udp_sock {
	__u32 fd;
} __attribute__((packed));

/* Maximum number of (tag, counter) pairs per update batch */
#define AIVPN_TAG_WINDOW_SLOTS  256

/**
 * struct aivpn_tag_window_entry - one (resonance_tag, counter) pair
 *
 * The kernel looks up incoming packets by their 8-byte resonance tag.
 * User-space pre-computes a window of valid tags from the session's
 * tag_secret and passes them here so the kernel can route and decrypt.
 *
 * @tag:     8-byte resonance tag as it appears on the wire
 * @counter: sender counter value that was used to derive this tag
 */
struct aivpn_tag_window_entry {
	__u8  tag[8];
	__u64 counter;
} __attribute__((packed));

/**
 * struct aivpn_session_update_tags - payload for AIVPN_IOC_SESSION_UPDATE_TAGS
 *
 * @session_id: identifies the session to update
 * @count:      number of valid entries in @entries (max AIVPN_TAG_WINDOW_SLOTS)
 * @entries:    array of (tag, counter) pairs for the current validity window
 */
struct aivpn_session_update_tags {
	__u8  session_id[16];
	__u32 count;
	struct aivpn_tag_window_entry entries[AIVPN_TAG_WINDOW_SLOTS];
} __attribute__((packed));

/* Maximum MDH (mask header) bytes the kernel downlink path carries inline.
 * Real masks use short headers (DNS/QUIC/WebRTC, well under this); a session
 * whose MDH exceeds this simply is not armed for kernel downlink and its
 * server->client traffic keeps flowing through the user-space path. */
#define AIVPN_DL_MDH_MAX  64

/**
 * struct aivpn_session_downlink - payload for AIVPN_IOC_SESSION_DOWNLINK
 *
 * Arms (or refreshes) the kernel downlink (server->client) fast path for a
 * session. User-space RESERVES a contiguous block of downlink send-counters
 * exclusively for the kernel (advancing its own send_counter past the block so
 * it can never emit any counter in it), pre-computes the BLAKE3 resonance tag
 * for each reserved counter, and hands the block plus the mask-derived MDH
 * template to the kernel here. The kernel consumes the entries strictly one per
 * packet; when the block is exhausted it stops accelerating and the packet
 * falls back to user-space (which uses fresh, higher counters). Because every
 * counter value has exactly one owner, no (s2c-key, nonce) pair is ever reused.
 *
 * @session_id: identifies the session to arm.
 * @mdh_len:    valid bytes in @mdh (<= AIVPN_DL_MDH_MAX). 0 = no MDH.
 * @seq_base:   starting inner-header seq_num; the kernel increments per packet.
 * @count:      number of reserved (tag,counter) entries (<= AIVPN_TAG_WINDOW_SLOTS).
 * @mdh:        mask-derived downlink header template prepended after the tag.
 * @entries:    reserved (resonance_tag, counter) pairs, ascending by counter.
 */
struct aivpn_session_downlink {
	__u8  session_id[16];
	__u16 mdh_len;
	__u16 seq_base;
	__u32 count;
	__u8  mdh[AIVPN_DL_MDH_MAX];
	struct aivpn_tag_window_entry entries[AIVPN_TAG_WINDOW_SLOTS];
} __attribute__((packed));

/**
 * struct aivpn_set_egress - payload for AIVPN_IOC_SET_EGRESS
 *
 * Enables or disables the kernel downlink egress hook. When enabled the module
 * registers a netfilter LOCAL_OUT hook that intercepts packets routed toward a
 * kernel-known client VPN IP, encrypts them with the session's s2c key using a
 * reserved counter (see AIVPN_IOC_SESSION_DOWNLINK), and transmits them from
 * @udp_fd to the client. Packets for sessions not armed for downlink (or with
 * an exhausted counter block) pass through untouched to the user-space path.
 *
 * @udp_fd:      server UDP socket the downlink datagrams are transmitted from.
 * @tun_ifindex: TUN ifindex whose egress is intercepted (0 = match on dst IP only).
 * @enable:      1 = register the hook; 0 = unregister it.
 */
struct aivpn_set_egress {
	__u32 udp_fd;
	__u32 tun_ifindex;
	__u32 enable;
} __attribute__((packed));

/* ------------------------------------------------------------------ *
 *  ioctl commands                                                      *
 * ------------------------------------------------------------------ */

/** Install a new session into the kernel session table */
#define AIVPN_IOC_SESSION_ADD   _IOW(AIVPN_MAGIC, 1, struct aivpn_session_add)

/** Remove a session by its 16-byte session_id */
#define AIVPN_IOC_SESSION_DEL   _IOW(AIVPN_MAGIC, 2, struct aivpn_session_del)

/** Query liveness / packet counters for a session */
#define AIVPN_IOC_SESSION_STAT  _IOWR(AIVPN_MAGIC, 3, struct aivpn_session_stat)

/** Register the TUN ifindex that decrypted packets should be injected into */
#define AIVPN_IOC_SET_TUN       _IOW(AIVPN_MAGIC, 4, struct aivpn_set_tun)

/** Register the UDP socket fd whose RX the module should intercept */
#define AIVPN_IOC_SET_UDP_SOCK  _IOW(AIVPN_MAGIC, 5, struct aivpn_set_udp_sock)

/** Flush all sessions (called on clean shutdown) */
#define AIVPN_IOC_FLUSH         _IO(AIVPN_MAGIC, 6)

/** Get module API version — returns AIVPN_MODULE_API_VERSION */
#define AIVPN_IOC_GET_VERSION          _IOR(AIVPN_MAGIC, 7, __u32)

/** Push a batch of (tag, counter) pairs so the kernel can route packets */
#define AIVPN_IOC_SESSION_UPDATE_TAGS  _IOW(AIVPN_MAGIC, 8, struct aivpn_session_update_tags)

/** Arm/refresh the kernel downlink fast path (reserved counter block + MDH) */
#define AIVPN_IOC_SESSION_DOWNLINK     _IOW(AIVPN_MAGIC, 9, struct aivpn_session_downlink)

/** Enable/disable the kernel downlink egress hook */
#define AIVPN_IOC_SET_EGRESS           _IOW(AIVPN_MAGIC, 10, struct aivpn_set_egress)

#endif /* _UAPI_AIVPN_H */
