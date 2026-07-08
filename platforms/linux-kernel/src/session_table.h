/* SPDX-License-Identifier: GPL-2.0 */
/*
 * session_table.h — kernel-side session table for aivpn.ko
 *
 * Two hash tables:
 *   aivpn_tag_htable    — keyed by 8-byte resonance tag (RCU, read from softirq)
 *   aivpn_session_htable — keyed by 16-byte session_id (spinlock, management only)
 *
 * Anti-replay uses a WireGuard-style 256-bit sliding window per session.
 */

#ifndef AIVPN_SESSION_TABLE_H
#define AIVPN_SESSION_TABLE_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <crypto/aead.h>
#include "../include/uapi/aivpn.h"

/* Hash table sizes */
#define AIVPN_TAG_HASH_BITS      17   /* 128K buckets for tag entries */
#define AIVPN_SESSION_HASH_BITS   9   /* 512 buckets for session objects */

/* WireGuard-style sliding window: 256 bits */
#define AIVPN_REPLAY_WINDOW  256UL

/**
 * struct aivpn_tag_entry - one (tag, counter) entry in the per-session tag window.
 *
 * Installed by AIVPN_IOC_SESSION_UPDATE_TAGS.  The kernel looks up incoming
 * packets by their 8-byte resonance tag; matching an entry gives both the
 * session pointer and the counter needed to build the AEAD nonce.
 *
 * Protected by RCU on the read side (softirq); spinlock_bh on writes.
 */
struct aivpn_tag_entry {
	u8                       tag[8];      /* wire resonance tag (hash key) */
	u64                      counter;     /* counter that generated this tag */
	struct aivpn_kern_session *session;   /* owning session (non-owning ptr) */
	struct hlist_node        hnode;       /* aivpn_tag_htable linkage */
	struct rcu_head          rcu;         /* for call_rcu on removal */
};

/**
 * struct aivpn_kern_session - per-VPN-session state
 *
 * Allocated by AIVPN_IOC_SESSION_ADD, freed after all RCU grace periods
 * following AIVPN_IOC_SESSION_DEL / flush.
 */
/**
 * struct aivpn_dl_entry - one reserved downlink (tag, counter) slot.
 *
 * Installed by AIVPN_IOC_SESSION_DOWNLINK. The counter is owned exclusively by
 * the kernel (user-space advanced its send_counter past it), so using it for
 * the s2c AEAD nonce can never collide with a user-space downlink packet.
 */
struct aivpn_dl_entry {
	u8   tag[8];      /* pre-computed resonance tag for this counter */
	u64  counter;     /* reserved downlink send-counter (AEAD nonce basis) */
};

struct aivpn_kern_session {
	/* management hash table linkage — keyed on session_id */
	struct hlist_node  mgmt_node;

	/* client-VPN-IP hash linkage (RCU) — keyed on client_ip, for egress */
	struct hlist_node  ip_node;

	/* identity */
	u8   session_id[16];

	/* crypto material — zeroed on removal */
	struct crypto_aead *tfm;      /* c2s uplink key (ChaCha20-Poly1305) */
	struct crypto_aead *tfm_s2c;  /* s2c downlink key (ChaCha20-Poly1305) */
	u8   nonce_suffix[4];         /* bytes 8-11 of the 12-byte nonce */

	/* Variant A wire layout (derived from tag_offset + mdh_len at insert) */
	u16  tag_pos;                 /* byte offset of the resonance tag in the packet */
	u16  ct_pos;                  /* byte offset where the ciphertext begins */

	/* VPN routing */
	u32  client_ip;               /* VPN IPv4 (network byte order) */
	u8   client_addr[28];         /* sockaddr_storage of the UDP peer (downlink dst) */

	/* Downlink (s2c) acceleration — reserved counter block + MDH template.
	 * dl_entries/dl_count/dl_mdh are replaced wholesale under s->lock by
	 * AIVPN_IOC_SESSION_DOWNLINK; dl_next is the monotonic consume cursor. When
	 * dl_next >= dl_count the block is exhausted and downlink falls back. */
	u8   dl_mdh[AIVPN_DL_MDH_MAX];
	u16  dl_mdh_len;
	u16  dl_seq_base;
	u32  dl_count;
	u32  dl_next;                 /* next unused entry (protected by s->lock) */
	struct aivpn_dl_entry dl_entries[AIVPN_TAG_WINDOW_SLOTS];

	/* WireGuard-style anti-replay */
	spinlock_t        lock;            /* protects counter + replay_window + stats */
	u64               recv_counter;   /* highest validated counter */
	unsigned long     replay_window[AIVPN_REPLAY_WINDOW / BITS_PER_LONG];

	/* stats (updated under lock) */
	u64  rx_packets;
	u64  rx_bytes;
	u64  tx_packets;
	u64  tx_bytes;

	/* tag window: pointers to tag entries installed in aivpn_tag_htable */
	struct aivpn_tag_entry   *tag_entries[AIVPN_TAG_WINDOW_SLOTS];
	int                       tag_entry_count;

	/* outbound TX counter for aivpn_encrypt(); atomic, no lock needed */
	atomic64_t                tx_counter;
};

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

int  aivpn_session_table_init(void);
void aivpn_session_table_fini(void);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

int  aivpn_session_insert(const struct aivpn_session_add *add);
int  aivpn_session_tags_update(const struct aivpn_session_update_tags *upd);
int  aivpn_session_downlink_update(const struct aivpn_session_downlink *dl);
int  aivpn_session_remove(const u8 *session_id);
void aivpn_session_flush(void);
int  aivpn_session_stat(struct aivpn_session_stat *stat);

/**
 * struct aivpn_dl_reservation - a claimed downlink slot returned to the caller.
 *
 * Snapshot of everything the crypto/transmit path needs, copied out while
 * s->lock is held so the AEAD (which must run lock-free) never touches the
 * session again.
 */
struct aivpn_dl_reservation {
	u8   tag[8];
	u64  counter;
	u16  seq_num;
	u16  mdh_len;
	u8   mdh[AIVPN_DL_MDH_MAX];
	u8   client_addr[28];
};

/**
 * aivpn_session_lookup_by_ip - find an RCU-protected session by client VPN IP.
 *
 * Called from the egress hook (softirq/process). Must be wrapped in
 * rcu_read_lock(); the returned pointer stays valid until rcu_read_unlock().
 * Returns NULL if no session owns @client_ip (network byte order).
 */
struct aivpn_kern_session *aivpn_session_lookup_by_ip(u32 client_ip);

/**
 * aivpn_session_dl_reserve - claim the next reserved downlink slot.
 *
 * Caller holds rcu_read_lock() over @s. Takes s->lock internally, atomically
 * consumes one (tag, counter) entry, and copies it plus the MDH and client
 * address into @out. Returns 0 on success, -EAGAIN when the block is exhausted
 * (caller must fall back to user-space). The AEAD is performed by the caller
 * AFTER this returns, with no lock held.
 */
int aivpn_session_dl_reserve(struct aivpn_kern_session *s,
			     struct aivpn_dl_reservation *out);

/**
 * aivpn_tag_lookup - find a session by its wire resonance tag.
 *
 * Called from softirq.  Returns a pointer with rcu_read_lock held by the
 * caller; fills *counter with the nonce counter for this tag.  Returns NULL
 * if the tag is not in the table.
 *
 * Caller must hold rcu_read_lock() across the returned pointer's use and
 * call rcu_read_unlock() when done.
 */
struct aivpn_kern_session *aivpn_tag_lookup(const u8 *tag, u64 *counter);

/**
 * aivpn_tag_probe_offsets - bitmap of packet byte offsets at which a resonance
 * tag might sit, across all installed sessions (Variant A).
 *
 * The kernel finds a session BY its tag, but the tag's position depends on that
 * session's mask — a chicken-and-egg the RX path resolves by probing every
 * offset that any live session uses. Bit N set means "some session reads its
 * tag at byte offset N". Offsets are small (legacy=0, quic=6, webrtc=8), so the
 * set is tiny; it only ever grows, so a stale extra bit just costs one wasted
 * lookup that misses. Read lock-free on the hot path.
 */
u64 aivpn_tag_probe_offsets(void);

/**
 * aivpn_counter_check - WireGuard-style sliding window anti-replay CHECK.
 *
 * Must be called with session->lock held.  Read-only: returns true if the
 * counter would be acceptable (not too old, not yet seen) WITHOUT advancing
 * the window.  The caller marks the counter with aivpn_counter_update() only
 * after the packet authenticates (WireGuard ordering) so fallback packets
 * never burn counters in the kernel window.
 */
bool aivpn_counter_check(const struct aivpn_kern_session *s, u64 counter);

/**
 * aivpn_counter_update - mark @counter as received, advancing the window.
 *
 * Must be called with session->lock held, after AEAD authentication succeeds
 * and while the same lock hold that performed aivpn_counter_check() is still
 * in place (check+update are atomic under s->lock).
 */
void aivpn_counter_update(struct aivpn_kern_session *s, u64 counter);

#endif /* AIVPN_SESSION_TABLE_H */
