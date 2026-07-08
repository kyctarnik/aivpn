/* SPDX-License-Identifier: GPL-2.0 */
/*
 * egress.h — kernel downlink (server->client) egress hook for aivpn.ko
 */

#ifndef AIVPN_EGRESS_H
#define AIVPN_EGRESS_H

#include <linux/types.h>

/**
 * aivpn_egress_set - enable or disable the downlink egress hook.
 * @udp_fd:      server UDP socket the downlink datagrams are transmitted from.
 * @tun_ifindex: TUN ifindex whose egress to intercept (0 = match on dst IP only).
 * @enable:      1 = register the netfilter POST_ROUTING hook; 0 = unregister.
 *
 * When enabled, packets routed toward a kernel-known client VPN IP are
 * encrypted with the session's s2c key (using a reserved counter) and sent to
 * the client; everything else passes through untouched. Disabled by default so
 * the module is inert until user-space explicitly opts in.
 *
 * Returns 0 on success, -errno on failure.
 */
int aivpn_egress_set(int udp_fd, u32 tun_ifindex, u32 enable);

/** Tear down the egress hook at module unload (idempotent). */
void aivpn_egress_fini(void);

#endif /* AIVPN_EGRESS_H */
