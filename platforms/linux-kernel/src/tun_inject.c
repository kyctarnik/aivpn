// SPDX-License-Identifier: GPL-2.0
/*
 * tun_inject.c — inject decrypted packets into the TUN net_device via netif_rx
 *
 * MEDIUM-7 fix: the PI header (tun_pi flags+proto) is only required when
 * writing to a TUN file descriptor.  Direct netif_rx injection needs only
 * skb->protocol set correctly; no push/pull of a PI header is needed.
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include "tun_inject.h"
#include "helpers.h"

static struct net_device *aivpn_tun_dev __read_mostly = NULL;
static DEFINE_SPINLOCK(aivpn_tun_lock);

int aivpn_tun_set_device(u32 ifindex)
{
	struct net_device *dev;
	struct net *net;

	/* ifindex 0 is never a valid device: treat it as the explicit clear
	 * path so user-space can drop the module's TUN reference without
	 * unloading the module. */
	if (!ifindex) {
		aivpn_tun_clear();
		return 0;
	}

	/*
	 * K-2: resolve the ifindex in the CALLER's network namespace, not
	 * init_net. The SET_TUN ioctl runs in the client's process context,
	 * so current->nsproxy->net_ns is the netns the client and its TUN
	 * device actually live in. Using init_net broke netns'd / containerised
	 * clients — an ifindex valid inside the client's netns either missed
	 * here or matched an unrelated device in the init namespace.
	 */
	net = current->nsproxy ? current->nsproxy->net_ns : &init_net;
	dev = dev_get_by_index(net, ifindex);
	if (!dev) {
		aivpn_err("tun set_device: ifindex %u not found\n", ifindex);
		return -ENODEV;
	}

	spin_lock_bh(&aivpn_tun_lock);
	if (aivpn_tun_dev)
		dev_put(aivpn_tun_dev);
	aivpn_tun_dev = dev;
	spin_unlock_bh(&aivpn_tun_lock);

	aivpn_info("TUN device set: %s (ifindex %u)\n", dev->name, ifindex);
	return 0;
}

void aivpn_tun_clear(void)
{
	struct net_device *dev;

	spin_lock_bh(&aivpn_tun_lock);
	dev = aivpn_tun_dev;
	aivpn_tun_dev = NULL;
	spin_unlock_bh(&aivpn_tun_lock);

	if (dev)
		dev_put(dev);
}

int aivpn_tun_inject(struct sk_buff *skb)
{
	struct net_device *dev;

	spin_lock_bh(&aivpn_tun_lock);
	dev = aivpn_tun_dev;
	if (dev)
		dev_hold(dev);
	spin_unlock_bh(&aivpn_tun_lock);

	if (!dev)
		return -ENODEV;

	/*
	 * The skb is the REUSED outer UDP datagram (payload overwritten in
	 * place with the inner IP packet). It can still carry state from the
	 * outer flow — dst_entry, conntrack ref, secpath, mark — which the
	 * canonical TUN inject path (tun_get_user builds a fresh skb) never
	 * has. Scrub it so the inner packet is routed/filtered from scratch;
	 * the egress path scrubs for the symmetric reason (see egress.c).
	 * skb_scrub_packet also sets pkt_type = PACKET_HOST.
	 *
	 * Checksum state also belongs to the OUTER packet: with
	 * CHECKSUM_COMPLETE, skb->csum covers the old wire payload and would
	 * make the stack reject the rewritten inner L4 checksums on real NICs.
	 * CHECKSUM_NONE forces normal software verification of the inner
	 * packet, exactly like a TUN-delivered packet.
	 */
	skb_scrub_packet(skb, true);
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum      = 0;

	skb->dev      = dev;
	skb->protocol = (skb->len > 0 && (skb->data[0] >> 4) == 6)
			? htons(ETH_P_IPV6) : htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	aivpn_netif_rx(skb);
	dev_put(dev);
	return 0;
}
