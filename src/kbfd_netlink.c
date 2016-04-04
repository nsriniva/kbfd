/* 
 *  BFD Netlink Interface
 *
 * base from draft-ietf-bfd-base-05.txt
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Hajime TAZAKI, 2007
 */

#ifdef __KERNEL__
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/in.h>
#include <net/inet_sock.h>
#else
#include <stdio.h>
#include "proc_compat.h"
#endif

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_netlink.h"
#include "kbfd_interface.h"
#include "kbfd_log.h"
#include "kbfd.h"

static struct sock *bfd_nls = NULL;
static unsigned long bfd_nl_seq = 0;

char *session_str[] = { "Normal Session", "LAG Session", "Micro Session",
	"Tunnel Session"
};

/* FIXME */
extern struct bfd_proto v4v6_proto;

static inline void
bfd_peer_stat_fill(struct bfd_nl_peerstat *peer, struct bfd_session *bfd)
{
#ifndef __KERNEL__
	size_t dscp_size = sizeof( peer->dscp );
#endif
	peer->is1hop = 1;
	peer->state = bfd->cpkt.state;
        peer->session_type = bfd->session_type;
        peer->vrf_fd = bfd->vrf_fd;
        peer->notif_group = bfd->notif_group;
#ifdef __KERNEL__
	peer->dscp = inet_sk(bfd->tx_ctrl_sock->sk)->tos;
#else
	getsockopt(bfd->tx_ctrl_sock->sk->sk_socket, IPPROTO_IP, IP_TOS,
		   &peer->dscp, &dscp_size);
#endif
	memcpy(&peer->dst, bfd->dst, bfd->proto->namelen(bfd->dst));
	memcpy(&peer->src, bfd->src, bfd->proto->namelen(bfd->src));
	peer->ifindex = bfd_interface_index(bfd->bif);
	peer->my_disc = bfd->cpkt.my_disc;
	peer->your_disc = bfd->cpkt.your_disc;

	peer->last_up = bfd->last_up;
	peer->last_down = bfd->last_down;
	peer->last_diag = bfd->last_diag;
}

static int
bfd_peer_fill_info(struct sk_buff *skb, struct bfd_session *bfd,
		   u32 pid, u32 seq, int event, unsigned int flags)
{
	struct bfd_nl_peerinfo *peer;
	struct nlmsghdr *nlh;
#ifdef __KERNEL__
	u_char *b = skb_tail_pointer(skb);
#endif

	nlh = NLMSG_NEW(skb, pid, seq, event, sizeof(*peer), flags);
	peer = NLMSG_DATA(nlh);

	memset(peer, 0, sizeof(struct bfd_nl_peerinfo));

	bfd_peer_stat_fill((struct bfd_nl_peerstat *)peer, bfd);
	/* counter */
	peer->pkt_in = bfd->pkt_in;
	peer->pkt_out = bfd->pkt_out;
	peer->up_cnt = bfd->up_cnt;
	peer->last_discont = bfd->last_discont;

#ifdef __KERNEL__
	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	return skb->len;

 nlmsg_failure:
	if (IS_DEBUG_NETLINK) {
		blog_info("bfd_peer_fill_info()nlmsg_failure");
	}
	skb_trim(skb, b - skb->data);
	return -1;
#else
	return 0;
#endif

}

static int
bfd_peer_change_fill_info(struct sk_buff *skb, struct bfd_session *bfd,
			  u32 pid, u32 seq, int event)
{
	struct bfd_nl_peerstat *peer;
	struct nlmsghdr *nlh;
#ifdef __KERNEL__
	u_char *b = skb_tail_pointer(skb);
#endif

	nlh = NLMSG_NEW(skb, pid, seq, event, sizeof(*peer), NLM_F_MULTI);
	peer = NLMSG_DATA(nlh);

	memset(peer, 0, sizeof(*peer));

	bfd_peer_stat_fill(peer, bfd);
	bfd->dirty = 0;

#ifdef __KERNEL__
	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	return skb->len;

 nlmsg_failure:
	if (IS_DEBUG_NETLINK) {
		blog_info("bfd_peer_change_fill_info(): skb full ");
	}
	skb_trim(skb, b - skb->data);
	return -1;
#else
	return 0;
#endif

}

// Note: This function should be modified for per-link if we use BFD_GET_PEER
// in the future
static int bfd_peer_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bfd_session *bfd;
	struct bfd_nl_peerinfo *peer = NLMSG_DATA(cb->nlh);
	int i = 0;
	int s_idx = cb->args[0];

	/* Query by Peer Address */
	if (peer->dst.sa.sa_family) {
           bfd = bfd_session_lookup(&v4v6_proto, 0, peer->vrf_fd, 
                                    &peer->dst.sa, 0);
		if (!bfd) {
			return skb->len;
		}
		if (bfd_peer_fill_info(skb, bfd, NETLINK_CB(cb->skb).pid,
				       cb->nlh->nlmsg_seq, BFD_NEWPEER, 0) <= 0)
		{
			bfd_session_release(bfd, SESSION_FIND);
			return skb->len;
		}
		bfd_session_release(bfd, SESSION_FIND);
	}
	/* Then All Info dump */
	else {
		spin_lock(&tbl_lock);
		for (i = 0; i < 2 * BFD_SESSION_HASH_SIZE; i++) {
			if (i < s_idx)
				continue;
			bfd = v4v6_proto.nbr_tbl[i];
			while (bfd) {
				if (bfd_peer_fill_info
				    (skb, bfd, NETLINK_CB(cb->skb).pid,
				     cb->nlh->nlmsg_seq, BFD_NEWPEER,
				     NLM_F_MULTI) <= 0) {
					goto done;
				}

				bfd = bfd->nbr_next;
			}
		}
 done:
		spin_unlock(&tbl_lock);
	}
	cb->args[0] = i;
	return skb->len;
}

static int
bfd_peer_change_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bfd_session *bfd;
	int i = 0;
	int s_idx = cb->args[0];

	spin_lock(&tbl_lock);
	for (i = 0; i < 2 * BFD_SESSION_HASH_SIZE; i++) {
		if (i < s_idx)
			continue;
		bfd = v4v6_proto.nbr_tbl[i];
		while (bfd) {
			if (bfd->dirty && (bfd_peer_change_fill_info
					   (skb, bfd, NETLINK_CB(cb->skb).pid,
					    cb->nlh->nlmsg_seq,
					    BFD_GETCHANGE) <= 0)) {
				goto done;
			}
			bfd = bfd->nbr_next;
		}
	}

 done:
	spin_unlock(&tbl_lock);
	cb->args[0] = i;
#ifdef __KERNEL__
	return skb->len;
#else
	return 0;
#endif
}

#if 0
static int test_done(struct netlink_callback *cb)
{
	blog_info("entered %s", __FUNCTION__);
	return 0;
}
#endif

static inline bool
bfd_timers_changed(struct bfd_interface *bif, struct bfd_nl_linkinfo *link)
{
	if (bif->v_mintx != link->mintx)
		goto diff;
	if (bif->v_minrx != link->minrx)
		goto diff;
	if (bif->v_mult != link->mult)
		goto diff;

	return false;
 diff:
	return true;
}

static int bfd_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct bfd_nl_peerinfo *peer;
	struct bfd_nl_linkinfo *link;
	struct bfd_nl_echo *echo;
	int *ifindex;
	int *slow_timer;
	int err = 0;
	char addr_buf[128];

	if (IS_DEBUG_NETLINK && nlh->nlmsg_type != 19) {
		blog_debug("bfd_nl_rcv: type=%d, len=%d, ack=%d",
			   nlh->nlmsg_type,
			   nlh->nlmsg_len, nlh->nlmsg_flags & NLM_F_ACK);
	}

	if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
		return 0;

	switch (nlh->nlmsg_type) {
	case BFD_NEWPEER:
		peer = NLMSG_DATA(nlh);

		if (IS_DEBUG_NETLINK && peer)
			blog_debug("NEWPEER : %s/%d\n",
				   v4v6_proto.addr_print(&peer->dst.sa,
							 addr_buf),
				   peer->ifindex);
		if (peer) {
			err = bfd_session_add(&v4v6_proto, peer);
		} else {
			err = EINVAL;
		}
		break;
	case BFD_DELPEER:
		peer = NLMSG_DATA(nlh);

		if (IS_DEBUG_NETLINK && peer)
			blog_debug("DELPEER : %s/%d\n",
				   v4v6_proto.addr_print(&peer->dst.sa,
							 addr_buf),
				   peer->ifindex);
		if (peer)
			err = bfd_session_delete(&v4v6_proto, &peer->dst.sa,
						 peer->ifindex,
						 peer->session_type);
		else
			err = EINVAL;
		break;
	case BFD_DEL_ALL:
		if (IS_DEBUG_NETLINK)
			blog_debug("DEL_ALL \n");
		err = bfd_session_delete_all();
		break;

	case BFD_GETCHANGE:
		if (!(nlh->nlmsg_flags & NLM_F_DUMP)) {
			err = EINVAL;
			break;
		}
		{
			struct netlink_dump_control control = {
				.dump = bfd_peer_change_dump,
				.done = NULL,
				.data = NULL,
				.min_dump_alloc = 0,
			};

			return netlink_dump_start(bfd_nls, skb, nlh, &control);
		}
		break;
	case BFD_GETPEER:
		// TBD fix this..
#ifndef __KERNEL__
		break;
#endif
		if (!(nlh->nlmsg_flags & NLM_F_DUMP)) {
			err = EINVAL;
			break;
		}
		{
			struct netlink_dump_control control = {
				.dump = bfd_peer_dump,
				.done = NULL,
				.data = NULL,
				.min_dump_alloc = 0,
			};

			return netlink_dump_start(bfd_nls, skb, nlh, &control);
		}
		break;
	case BFD_CLEAR_STATS:
		if (IS_DEBUG_NETLINK)
			blog_debug("CLEAR_STATS");

#ifndef __KERNEL__
		break;
#endif
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST)) {
			err = EINVAL;
			break;
		}
		peer = NLMSG_DATA(nlh);
		if (peer) {
			err =
                           bfd_session_clear_stats(&v4v6_proto, peer->vrf_fd, 
                                                   &peer->dst.sa,
						    peer->ifindex,
						    peer->session_type);
		} else {
			if (IS_DEBUG_NETLINK)
				blog_debug("CLEAR_STATS: no peer");
		}

		break;
	case BFD_ADMINDOWN:
		break;
	case BFD_SETSLOW:
		slow_timer = NLMSG_DATA(nlh);

		if (slow_timer && (master->slow_timer != *slow_timer)) {
			master->slow_timer = *slow_timer;
			bfd_sessions_change_slow_timer();
		} else {
			err = EINVAL;
		}
		break;
	case BFD_ECHO:
		echo = NLMSG_DATA(nlh);

		if (echo) {
			struct bfd_interface *bif =
			    bfd_interface_get(echo->ifindex);

			if (bif) {
				bif->echo_on = echo->echo_on;
				bfd_interface_change_timer_and_toggle_echo(bif);
			} else {
				err = ENOMEM;
			}
		} else {
			err = EINVAL;
		}
		break;
	case BFD_RESETLINK:
		ifindex = NLMSG_DATA(nlh);

		if (ifindex) {
			err = bfd_interface_reset(*ifindex);
		} else {
			err = EINVAL;
		}
		break;
	case BFD_SETLINK:
		link = NLMSG_DATA(nlh);

		if (link) {
			struct bfd_interface *bif =
			    bfd_interface_get(link->ifindex);
			if (bif) {
				if (IS_DEBUG_NETLINK)
					blog_debug
					    ("BFD_SETLINK: if=%s mintx=%d, "
					     "minrx=%d, mult=%d", bif->name,
					     link->mintx, link->minrx,
					     link->mult);
				if (bfd_timers_changed(bif, link)) {
					bif->v_mintx = link->mintx;
					bif->v_minrx = link->minrx;
					bif->v_mult = link->mult;
					bif->is_default = false;
					bfd_interface_change_timer(bif);
				}
			} else
				err = ENOMEM;
		} else
			err = EINVAL;
		break;
	case BFD_SETFLAG:
		break;
	case BFD_CLEAR_COUNTER:
		break;
	case BFD_CLEAR_SESSION:
		break;
	case BFD_SETDSCP:
		peer = NLMSG_DATA(nlh);

		if (peer)
			err =
                           bfd_session_set_dscp(&v4v6_proto, peer->vrf_fd,
                                                &peer->dst.sa,
						 peer->ifindex, peer->dscp);
		else
			err = EINVAL;
		break;
	case BFD_SETDEFAULTS:
		link = NLMSG_DATA(nlh);

		if (link) {
			if (IS_DEBUG_NETLINK)
				blog_debug
				    ("BFD_SETDEFAULTS: mintx=%d, minrx=%d, mult=%d",
				     link->mintx, link->minrx, link->mult);
			bfd_interface_set_defaults(link->mintx, link->minrx,
						   link->mult);
		} else
			err = EINVAL;
		break;
	default:
		err = EINVAL;
		break;
	}
	return err;
}

/* Receive Handler */
static void bfd_nl_rcv_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int err;
	uint32_t rlen;

	while (skb->len >= NLMSG_SPACE(0)) {
		err = 0;
		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			return;

		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		/* parse client message */
		err = bfd_nl_rcv_msg(skb, nlh);

		if (err || nlh->nlmsg_flags & NLM_F_ACK) {
			if (IS_DEBUG_NETLINK)
				blog_debug("bfd_nl: send ack");
			netlink_ack(skb, nlh, err);
		}

		skb_pull(skb, rlen);
	}
}

/* Notify function */
void bfd_nl_send(struct bfd_session *bfd)
{
	unsigned int size;
	struct sk_buff *skb;
	struct bfd_nl_peerinfo *data;
	struct nlmsghdr *nlh;
	int group = bfd->notif_group;

	if (!bfd_nls)
		return;

	size = NLMSG_SPACE(sizeof(struct bfd_nl_peerinfo));
	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb) {
		blog_err("skb_alloc() failed.");
		return;
	}

	nlh = NLMSG_PUT(skb, 0, bfd_nl_seq++, NLMSG_DONE, size - sizeof(*nlh));
	nlh->nlmsg_type = BFD_NEWPEER;

	data = (struct bfd_nl_peerinfo *)NLMSG_DATA(nlh);

	bfd_peer_stat_fill((struct bfd_nl_peerstat *)data, bfd);

	if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION) {
		group = 2;
        }
	if (IS_DEBUG_NETLINK) {
		blog_info("sending netlink message to group:%d\n", group );
        }


	NETLINK_CB(skb).dst_group = group;
	netlink_broadcast(bfd_nls, skb, 0, group, GFP_ATOMIC);
#ifndef __KERNEL__
	free(skb);
#else
 nlmsg_failure:
	return;
#endif
}

int bfd_netlink_init(void)
{
	bfd_nls =
	    netlink_kernel_create(&init_net, NETLINK_BFD, 1, bfd_nl_rcv_skb,
				  NULL, THIS_MODULE);

	if (!bfd_nls) {
		blog_err("Failed to create new netlink socket(%u) for bfd",
			 NETLINK_BFD);
	}
	return 0;
}

void bfd_netlink_finish(void)
{
	netlink_kernel_release(bfd_nls);
	return;
}
