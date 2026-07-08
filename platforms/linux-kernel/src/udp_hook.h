/* SPDX-License-Identifier: GPL-2.0 */
/*
 * udp_hook.h — UDP socket sk_data_ready intercept for aivpn.ko
 */

#ifndef AIVPN_UDP_HOOK_H
#define AIVPN_UDP_HOOK_H

#include <linux/net.h>

/**
 * aivpn_udp_hook_install - replace sk_data_ready on the given socket.
 * @sock: the UDP socket whose RX the module should intercept.
 *
 * Saves the original sk_data_ready, installs aivpn_sk_data_ready, and holds a
 * reference on the sock while hooked.  Only one socket may be hooked at a
 * time: re-installing on the same socket is an idempotent no-op; installing
 * on a different socket first tears down the previous hook.  Returns 0 on
 * success, -EBUSY if the socket is claimed by another user, -errno on error.
 */
int  aivpn_udp_hook_install(struct socket *sock);

/**
 * aivpn_udp_hook_uninstall - restore the hooked socket's callbacks, if any.
 *
 * Restores sk_data_ready/sk_user_data, waits (synchronize_rcu) for in-flight
 * softirq invocations of the hook to drain, frees the hook state and drops
 * the sock reference.  Safe to call when nothing is hooked.  MUST run during
 * module teardown before module text is freed.
 */
void aivpn_udp_hook_uninstall(void);

/**
 * aivpn_udp_hook_install_by_fd - install UDP hook via a userspace file descriptor.
 * @fd: file descriptor of the UDP socket, or a negative value to uninstall
 *      the currently hooked socket (explicit clear path).
 *
 * Looks up the socket with sockfd_lookup(), installs the hook, then releases.
 * Returns 0 on success, -errno on error.
 */
int aivpn_udp_hook_install_by_fd(int fd);

#endif /* AIVPN_UDP_HOOK_H */
