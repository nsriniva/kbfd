
#ifdef __KERNEL__
#include <net/sock.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/pkt_sched.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <linux/filter.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_v4v6.h"
#include "kbfd_session.h"
#include "kbfd_packet.h"
#include "kbfd_log.h"
#include "kbfd_interface.h"
#include "kbfd.h"
#include "kbfd_feature.h"

#ifndef __KERNEL__
#include <stdio.h>
#endif

static struct bfd_feature_vector *feat_vect[];
static void *bfd_vxlan_tunnel_get_saddr(struct bfd_session *bfd,
					size_t * addr_size);
static void *bfd_vxlan_tunnel_get_daddr(struct bfd_session *bfd, void *saddr);

static int
bfd_feature_tx_init(struct bfd_session *bfd, struct bfd_nl_peerinfo *peer,
		    int feat_type)
{
	// ret #0
	struct sock_filter reject_all_packets_code[] = {
		{6, 0, 0, 0},
	};

	struct sock_fprog reject_all_packets_bpf = {
		.len = ARRAY_SIZE(reject_all_packets_code),
		.filter = reject_all_packets_code,
	};
	mm_segment_t oldfs;
	int err = 0;

	if (sock_create_ns(bfd->netns, AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL),
			&bfd->feat->tx_sock) < 0) {
		blog_err("Error creating feature(%d) tx socket.\n", feat_type);
		err = -1;
		goto sock_err;
	}

	bfd->feat->l2dst.sll_ifindex = bfd_interface_index(bfd->bif);
	bfd->feat->l2dst.sll_family = AF_PACKET;
	bfd->feat->l2dst.sll_halen = (unsigned char)htons(6);

	if ((err = bfd->feat->tx_sock->ops->bind(bfd->feat->tx_sock,
						 (struct sockaddr *)
						 &bfd->feat->l2dst,
						 sizeof(struct sockaddr_ll)))
	    < 0) {
		if (err != -ENODEV)
			blog_err("Error(%d) binding to interface(%d:%s)\n",
				 err, bfd_interface_index(bfd->bif),
				 bfd_interface_name(bfd->bif));
		err = -2;
		goto bind_err;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	if (sock_setsockopt(bfd->feat->tx_sock,
			    SOL_SOCKET, SO_ATTACH_FILTER,
			    (char *)&reject_all_packets_bpf,
			    sizeof(reject_all_packets_bpf)) < 0) {
		blog_err("Error setting BPF filter for feature(%d) tx socket.",
			 feat_type);
		err = -3;
		goto filter_err;
	}

	bfd->feat->vect->update_dmac(bfd);
	goto done;

 bind_err:
 filter_err:
	sock_release(bfd->feat->tx_sock);
 sock_err:
 done:
	return err;
}

static void
bfd_vxlan_tunnel_init_packet(struct bfd_session *bfd,
			     struct bfd_nl_vxlan_tunnel_peerinfo *peer)
{
	struct vxlan_bfd_pkt *vpkt = (struct vxlan_bfd_pkt *)bfd->feat->payload;
	struct vxlanhdr *vhdr = (struct vxlanhdr *)vpkt;
	struct bfd_vxlan_encap_pkt *bpkt = &vpkt->bfdpkt;
	struct ethhdr *eth = (struct ethhdr *)bpkt;
	struct iphdr *iph = &bpkt->iph;
	struct udphdr *udph = &bpkt->udph;
	struct sockaddr_in *inner_src = &VXLAN_TUNNEL_PRIV(bfd)->inner_src.sin;
	u_int32_t udp_len;
	unsigned short dport = htons((unsigned short)BFD_CONTROL_PORT);
	unsigned short sport = htons(bfd->sport);
	unsigned short h_proto = htons(ETH_P_IP);

	if (IS_DEBUG_BSM) {
		char buf[256];
		blog_debug("bfd_vxlan_tunnel_init_packet : vpkt(%p), vhdr(%p),\
                      bpkt(%p), eth(%p), iph(%p), udph(%p),peer(%s)", 
                      vpkt, vhdr, bpkt, eth, iph, udph, 
                      bfd->proto->addr_print(bfd->dst, buf));
	}
	// why memcpy?  Alignment...
	memcpy(&vhdr->vx_flags, &VXLAN_TUNNEL_PRIV(bfd)->flags,
	       sizeof(vhdr->vx_flags));
	memcpy(&vhdr->vx_vni, &VXLAN_TUNNEL_PRIV(bfd)->vni,
	       sizeof(vhdr->vx_vni));
	memcpy(eth->h_dest, VXLAN_TUNNEL_PRIV(bfd)->inner_dmac, ETH_ALEN);
	memcpy(eth->h_source, VXLAN_TUNNEL_PRIV(bfd)->inner_smac, ETH_ALEN);
	memcpy(&eth->h_proto, &h_proto, sizeof(eth->h_proto));
	udp_len = sizeof(*udph) + sizeof(struct bfd_ctrl_packet);
	init_ipv4_hdr(iph, udp_len, true);
	udp_len = htons(udp_len);
	update_ip_hdr(iph, &(inner_src->sin_addr),
		      &(((struct sockaddr_in *)bfd->dst)->sin_addr), 4);
	memcpy(&udph->source, &sport, sizeof(udph->source));
	memcpy(&udph->dest, &dport, sizeof(udph->dest));
	memcpy(&udph->len, &udp_len, sizeof(udph->len));
}

static int
bfd_vxlan_tunnel_tx_init(struct bfd_session *bfd, struct bfd_nl_peerinfo *peer,
		   int feat_type)
{
	mm_segment_t oldfs;
	int err = 0;
	struct bfd_nl_vxlan_tunnel_peerinfo *vpeer =
	    (struct bfd_nl_vxlan_tunnel_peerinfo *)peer;
	int on = 1;

	if (sock_create_ns(bfd->netns, AF_INET, SOCK_RAW, IPPROTO_RAW,
			&bfd->feat->tx_sock) < 0) {
		blog_err("Error creating vxlan tunnel(%d) tx socket.\n", feat_type);
		goto sock_err;
	}

	bfd->feat->l3v4dst.sin_family = AF_INET;
	bfd->feat->l3v4dst.sin_addr.s_addr =
	    VXLAN_TUNNEL_PRIV(bfd)->outer_dst.sin.sin_addr.s_addr;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = bfd->feat->tx_sock->ops->setsockopt(bfd->feat->tx_sock,
						  IPPROTO_IP, IP_HDRINCL,
						  (char *)&on, sizeof(on));

	if (err) {
		blog_err("Error setting  IPPROTO_IP/IP_HDRINCL for feat(%d) tx "
			 "socket.", feat_type);
		goto sockopt_err;
	}
	bfd_vxlan_tunnel_init_packet(bfd, vpeer);
	goto done;

 sockopt_err:
	sock_release(bfd->feat->tx_sock);

 sock_err:
	err = -1;
 done:
	return err;
}

static void
bfd_echo_get_udp_ports(struct bfd_session *bfd, u_int16_t * sport,
		       u_int16_t * dport)
{
	*sport = *dport = htons(BFD_ECHO_PORT);
}

static void
bfd_lag_get_udp_ports(struct bfd_session *bfd, u_int16_t * sport,
		      u_int16_t * dport)
{
	*dport = htons(BFD_CONTROL_PORT);
	*sport = htons(bfd->sport);
}

static void bfd_echo_set_payload(struct bfd_session *bfd)
{
	ECHO_PKT(bfd)->my_disc = bfd->cpkt.my_disc;
	ECHO_PKT(bfd)->your_disc = bfd->cpkt.your_disc;
}

static void bfd_lag_set_payload(struct bfd_session *bfd)
{
	memcpy(LAG_PKT(bfd), &bfd->cpkt, sizeof(bfd->cpkt));
}

inline bool bfd_feat_active(struct bfd_session *bfd, int feat_type)
{
	return (bfd->feat &&
		bfd->feat->tx_sock
		&& (bfd->feat->vect == feat_vect[feat_type]));
}

static bool bfd_echo_active(struct bfd_session *bfd)
{
	return (bfd_interface_echo_on(bfd->bif));
}

static bool bfd_lag_enabled(struct bfd_session *bfd)
{
	return true;
}

static void *bfd_feature_get_saddr(struct bfd_session *bfd, size_t * addr_size)
{
	return bfd->proto->get_addr(bfd->src, addr_size);
}

static void *bfd_echo_get_daddr(struct bfd_session *bfd, void *saddr)
{
	return saddr;
}

static void *bfd_lag_get_daddr(struct bfd_session *bfd, void *saddr)
{
	return bfd->proto->get_addr(bfd->dst, NULL);
}

static void bfd_feature_free(struct bfd_session *bfd)
{
#ifdef __KERNEL__
	if (bfd->feat->_neigh) {
		neigh_release(bfd->feat->_neigh);
	}
#endif
	if (bfd->feat->tx_sock)
		sock_release(bfd->feat->tx_sock);
}

static bool bfd_feature_update_dmac(struct bfd_session *bfd, u_int32_t ifindex)
{
#ifdef __KERNEL__
	if (bfd->feat->valid_dmac ||
	    !(bfd->feat->_neigh ||
	      (bfd->feat->_neigh = bfd->proto->get_neigh(bfd, ifindex))))
		goto done;

	memcpy(bfd->feat->l2dst.sll_addr, bfd->feat->_neigh->ha, ETH_ALEN);
	bfd->feat->valid_dmac = true;
 done:
#endif
	return bfd->feat->valid_dmac;
}

static bool bfd_echo_update_dmac(struct bfd_session *bfd)
{
	return bfd_feature_update_dmac(bfd, bfd_interface_index(bfd->bif));
}

static bool bfd_lag_update_dmac(struct bfd_session *bfd)
{
	if (!bfd->lag_session)
		return false;
	return bfd_feature_update_dmac(bfd, 
                                       bfd_interface_index(bfd->lag_session->bif));
}

static void
bfd_vxlan_tunnel_get_udp_ports(struct bfd_session *bfd, u_int16_t * sport,
			       u_int16_t * dport)
{
	*dport = htons(VXLAN_TUNNEL_PRIV(bfd)->outer_dport);
	*sport = htons(VXLAN_TUNNEL_PRIV(bfd)->outer_sport);
}

static void bfd_vxlan_tunnel_set_payload(struct bfd_session *bfd)
{
	char buf[256];
	struct vxlan_bfd_pkt *vx_payload = VXLAN_PKT(bfd);
	struct bfd_vxlan_encap_pkt  *bfdpkt = &vx_payload->bfdpkt;
        void *saddr, *daddr;
        size_t addr_size = 0;
	if (IS_DEBUG_CTRL_PACKET)
		blog_debug("bfd_vxlan_tunnel_set_payload=>: peer(%s)",
			   bfd->proto->addr_print(bfd->dst, buf));

	memcpy(&bfdpkt->payload, &bfd->cpkt, sizeof(bfd->cpkt));
        saddr = bfd_vxlan_tunnel_get_saddr(bfd, &addr_size);
        if (!saddr) {
	   blog_err("saddr is null for vxlan tunnel");
           return;
        }
        daddr = bfd_vxlan_tunnel_get_daddr(bfd, saddr);
        if (!daddr) {
	   blog_err("daddr is null for vxlan tunnel");
           return;
        }
        // Update udp checksum
        update_udp_hdr(&bfdpkt->udph, &bfdpkt->payload, sizeof(bfdpkt->payload),
                       saddr, daddr, addr_size);
}

static bool bfd_vxlan_tunnel_active(struct bfd_session *bfd)
{
	return bfd_feat_active(bfd, BFD_VXLAN_FEATURE);
}

void *bfd_vxlan_tunnel_get_saddr(struct bfd_session *bfd,
					size_t * addr_size)
{
	return bfd->proto->get_addr(&VXLAN_TUNNEL_PRIV(bfd)->outer_src.sa, addr_size);
}

void *bfd_vxlan_tunnel_get_daddr(struct bfd_session *bfd, void *saddr)
{
	return bfd->proto->get_addr(&VXLAN_TUNNEL_PRIV(bfd)->outer_dst.sa, NULL);
}

/*
 * Session related Echo processing code
 */

#ifdef __KERNEL__
static void bfd_reset_echo_tx(struct work_struct *_work)
{
	struct bfd_echo_priv *priv =
	    container_of(_work, struct bfd_echo_priv, reset_echo_tx);
	struct bfd_session *bfd = priv->bfd;

	bfd_reset_echo_tx_timer(bfd);
	bfd_session_release(bfd, ECHO_TX_RESET);
}

static void bfd_reset_echo_exp(struct work_struct *_work)
{
	struct bfd_echo_priv *priv =
	    container_of(_work, struct bfd_echo_priv, reset_echo_exp);
	struct bfd_session *bfd = priv->bfd;

	bfd_reset_echo_expire_timer(bfd);
	bfd_session_release(bfd, ECHO_EXP_RESET);
}

void bfd_reset_echo_tx_timer_q(struct bfd_session *bfd)
{
	if (!bfd_session_marked_deleted(bfd) &&
	    bfd->feat->vect->enabled(bfd) &&
	    queue_work(master->echo_tx_reset_wq,
		       &ECHO_PRIV(bfd)->reset_echo_tx))
		bfd_session_grab(bfd, ECHO_TX_RESET);
}

void bfd_reset_echo_expire_timer_q(struct bfd_session *bfd)
{
	if (!bfd_session_marked_deleted(bfd) &&
	    bfd->feat->vect->enabled(bfd) &&
	    queue_work(master->echo_exp_reset_wq,
		       &ECHO_PRIV(bfd)->reset_echo_exp))
		bfd_session_grab(bfd, ECHO_EXP_RESET);
}

void bfd_echo_xmit_timeout(struct work_struct *_work)
{
	struct delayed_work *work =
	    container_of(_work, struct delayed_work, work);
	struct bfd_echo_priv *priv =
	    container_of(work, struct bfd_echo_priv, t_echo_tx_work);
	struct bfd_session *bfd = priv->bfd;

#ifdef __KERNEL__
	INIT_COMPLETION(ECHO_PRIV(bfd)->echo_xmit_completion);
	if (mutex_trylock(&ECHO_PRIV(bfd)->echo_xmit_lock)) {
#endif
		/* reset timer before send processing(avoid self synchronization) */
		bfd_start_echo_xmit_timer(bfd);

               	if (!bfd_session_marked_deleted(bfd) 
                    && bfd->feat->vect->enabled(bfd)
                    && GET_ECHO_PRIV_FIELD(bfd, echo_start)
                    && GET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv))
	        	bfd->proto->xmit_feature_packet(bfd);

#ifdef __KERNEL__
		mutex_unlock(&ECHO_PRIV(bfd)->echo_xmit_lock);
	}
	complete_all(&ECHO_PRIV(bfd)->echo_xmit_completion);
#endif
	bfd_session_release(bfd, ECHO_TX_TIMER);
	return;
}

void bfd_start_echo_xmit_timer(struct bfd_session *bfd)
{
        int jitter, echo_tx;

        /*
         * The actual echo tx interval is zero, so
         * disable echo transmission.
         */
	if (!(echo_tx = GET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv)))
		return;
	/* jitter is 0% -> 25%. if detectmult == 1, max 90% */
	get_random_bytes(&jitter, 4);
	jitter = 75 + jitter % 26;

	if (!bfd_session_marked_deleted(bfd)
            && GET_ECHO_PRIV_FIELD(bfd, echo_start)
	    && queue_delayed_work(master->tx_echo_wq,
				  &ECHO_PRIV(bfd)->t_echo_tx_work,
				  usecs_to_jiffies(echo_tx) *
				  jitter / 100))
		bfd_session_grab(bfd, ECHO_TX_TIMER);
}

void bfd_stop_echo_xmit_timer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
	bfd_stop_timer(bfd, &ECHO_PRIV(bfd)->t_echo_tx_work, ECHO_TX_TIMER,
		       &ECHO_PRIV(bfd)->echo_xmit_lock,
		       &ECHO_PRIV(bfd)->echo_xmit_completion, true);
#else
	bfd_stop_timer(bfd, &ECHO_PRIV(bfd)->t_echo_tx_work, ECHO_TX_TIMER,
		       NULL, NULL, true);
#endif
}

void bfd_reset_echo_tx_timer(struct bfd_session *bfd)
{
	bfd_stop_echo_xmit_timer(bfd);
	bfd_start_echo_xmit_timer(bfd);
	return;
}

void bfd_detect_echo_timeout(struct work_struct *_work)
{
	struct delayed_work *work =
	    container_of(_work, struct delayed_work, work);
	struct bfd_echo_priv *priv =
	    container_of(work, struct bfd_echo_priv, t_echo_rx_expire);
	struct bfd_session *bfd = priv->bfd;

#ifdef __KERNEL__
	INIT_COMPLETION(ECHO_PRIV(bfd)->echo_expire_completion);
	if (mutex_trylock(&ECHO_PRIV(bfd)->echo_expire_lock)) {
#endif
                if (!bfd_session_marked_deleted(bfd) 
                    && GET_ECHO_PRIV_FIELD(bfd, echo_start)
                    && GET_ECHO_PRIV_FIELD(bfd, echo_detect_time))
                   bfd_bsm_event(bfd, BSM_Echo_Timer_Expired);

#ifdef __KERNEL__
		mutex_unlock(&ECHO_PRIV(bfd)->echo_expire_lock);
	}
	complete_all(&ECHO_PRIV(bfd)->echo_expire_completion);
#endif
	bfd_session_release(bfd, ECHO_RX_TIMER);
	return;
}

void bfd_stop_echo_expire_timer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
	bfd_stop_timer(bfd, &ECHO_PRIV(bfd)->t_echo_rx_expire, ECHO_RX_TIMER,
		       &ECHO_PRIV(bfd)->echo_expire_lock,
		       &ECHO_PRIV(bfd)->echo_expire_completion, false);
#else
	bfd_stop_timer(bfd, &ECHO_PRIV(bfd)->t_echo_rx_expire, ECHO_RX_TIMER,
		       NULL, NULL, false);
#endif
}

inline void bfd_start_echo_expire_timer(struct bfd_session *bfd)
{
        int echo_detect;
        /*
         * Echo failure detect time is zero - disable echo failure
         * detection.
         */
        if (!(echo_detect = GET_ECHO_PRIV_FIELD(bfd, echo_detect_time)))
           return;

	if (!bfd_session_marked_deleted(bfd)
            && GET_ECHO_PRIV_FIELD(bfd, echo_start)
 	    && queue_delayed_work(master->echo_expire_wq,
				  &ECHO_PRIV(bfd)->t_echo_rx_expire,
				  usecs_to_jiffies(echo_detect)))
		bfd_session_grab(bfd, ECHO_RX_TIMER);
}

void bfd_reset_echo_expire_timer(struct bfd_session *bfd)
{
	bfd_stop_echo_expire_timer(bfd);
	bfd_start_echo_expire_timer(bfd);
}
#endif				/* __KERNEL */

static void bfd_echo_add_session(struct bfd_session *bfd,
				 struct bfd_nl_peerinfo *peer)
{
	if (bfd->feat) {
		ECHO_PRIV(bfd)->bfd = bfd;
#ifdef __KERNEL__
		mutex_init(&ECHO_PRIV(bfd)->echo_expire_lock);
		init_completion(&ECHO_PRIV(bfd)->echo_expire_completion);
		mutex_init(&ECHO_PRIV(bfd)->echo_xmit_lock);
		init_completion(&ECHO_PRIV(bfd)->echo_xmit_completion);
		INIT_DELAYED_WORK(&ECHO_PRIV(bfd)->t_echo_tx_work,
				  bfd_echo_xmit_timeout);
		INIT_DELAYED_WORK(&ECHO_PRIV(bfd)->t_echo_rx_expire,
				  bfd_detect_echo_timeout);
		INIT_WORK(&ECHO_PRIV(bfd)->reset_echo_tx, bfd_reset_echo_tx);
		INIT_WORK(&ECHO_PRIV(bfd)->reset_echo_exp, bfd_reset_echo_exp);
#endif
	}

}

static void bfd_echo_del_session(struct bfd_session *bfd)
{
	if (bfd->feat) {
#ifdef __KERNEL__
		if (cancel_work_sync(&ECHO_PRIV(bfd)->reset_echo_tx))
			bfd_session_release(bfd, ECHO_TX_RESET);
		if (cancel_work_sync(&ECHO_PRIV(bfd)->reset_echo_exp))
			bfd_session_release(bfd, ECHO_EXP_RESET);
		bfd_stop_echo_xmit_timer(bfd);
		bfd_stop_echo_expire_timer(bfd);
#endif
	}

}

static void bfd_vxlan_tunnel_add_session(struct bfd_session *bfd,
				         struct bfd_nl_peerinfo *peer)
{
	char buf[256];

	if (IS_DEBUG_BSM)
		blog_debug("bfd_vxlan_tunnel_add_session: peer(%s), feat(%p)",
			   bfd->proto->addr_print(bfd->dst, buf), bfd->feat);
	if (bfd->feat) {
		struct bfd_nl_vxlan_tunnel_peerinfo *vpeer =
		    (struct bfd_nl_vxlan_tunnel_peerinfo *)peer;
		// Fill up bfd_vxlan_tunnel_priv fields of bfd from peer
		// There is only IPV4 support
		VXLAN_TUNNEL_PRIV(bfd)->outer_dst.sin.sin_family = AF_INET;
		VXLAN_TUNNEL_PRIV(bfd)->outer_dst.sin.sin_addr.s_addr =
		    vpeer->outer_dst.sin.sin_addr.s_addr;
		VXLAN_TUNNEL_PRIV(bfd)->outer_src.sin.sin_family = AF_INET;
		VXLAN_TUNNEL_PRIV(bfd)->outer_src.sin.sin_addr.s_addr =
		    vpeer->outer_src.sin.sin_addr.s_addr;
		VXLAN_TUNNEL_PRIV(bfd)->outer_sport = vpeer->outer_sport;
		VXLAN_TUNNEL_PRIV(bfd)->outer_dport = vpeer->outer_dport;
		VXLAN_TUNNEL_PRIV(bfd)->flags = htonl(vpeer->flags);
		VXLAN_TUNNEL_PRIV(bfd)->vni = htonl(vpeer->vni);
		VXLAN_TUNNEL_PRIV(bfd)->inner_src.sin.sin_family = AF_INET;
		VXLAN_TUNNEL_PRIV(bfd)->inner_src.sin.sin_addr.s_addr =
		    vpeer->inner_src.sin.sin_addr.s_addr;
		memcpy(VXLAN_TUNNEL_PRIV(bfd)->inner_dmac, vpeer->inner_dmac,
		       ETH_ALEN);
		memcpy(VXLAN_TUNNEL_PRIV(bfd)->inner_smac, vpeer->inner_smac,
		       ETH_ALEN);
                VXLAN_TUNNEL_PRIV(bfd)->mintx = vpeer->mintx;
                VXLAN_TUNNEL_PRIV(bfd)->minrx = vpeer->minrx;
                VXLAN_TUNNEL_PRIV(bfd)->mult = vpeer->mult;
	}

}

static void bfd_vxlan_tunnel_del_session(struct bfd_session *bfd)
{
	char buf[256];
	if (IS_DEBUG_CTRL_PACKET)
		blog_debug("bfd_vxlan_tunnel_del_session=>: peer(%s)",
			   bfd->proto->addr_print(bfd->dst, buf));
}

void bfd_feat_session_del(struct bfd_session *bfd)
{
	if (bfd->feat && bfd->feat->vect->del_session)
		bfd->feat->vect->del_session(bfd);
}

static struct bfd_feature_vector echo_vec = {
	.enabled = bfd_echo_active,
	.set_payload = bfd_echo_set_payload,
	.get_udp_ports = bfd_echo_get_udp_ports,
	.get_saddr = bfd_feature_get_saddr,
	.get_daddr = bfd_echo_get_daddr,
	.update_dmac = bfd_echo_update_dmac,
	.free = bfd_feature_free,
	.add_session = bfd_echo_add_session,
	.del_session = bfd_echo_del_session,
	.tx_init = bfd_feature_tx_init,
	.set_sll_protocol = true,
};

static struct bfd_feature_vector lag_vec = {
	.enabled = bfd_lag_enabled,
	.set_payload = bfd_lag_set_payload,
	.get_udp_ports = bfd_lag_get_udp_ports,
	.get_saddr = bfd_feature_get_saddr,
	.get_daddr = bfd_lag_get_daddr,
	.update_dmac = bfd_lag_update_dmac,
	.free = bfd_feature_free,
	.tx_init = bfd_feature_tx_init,
	.set_sll_protocol = true,
};

static struct bfd_feature_vector vxlan_tunnel_vec = {
	.enabled = bfd_vxlan_tunnel_active,
	.set_payload = bfd_vxlan_tunnel_set_payload,
	.get_udp_ports = bfd_vxlan_tunnel_get_udp_ports,
	.get_saddr = bfd_vxlan_tunnel_get_saddr,
	.get_daddr = bfd_vxlan_tunnel_get_daddr,
	.update_dmac = 0,
	.free = bfd_feature_free,
	.add_session = bfd_vxlan_tunnel_add_session,
	.del_session = bfd_vxlan_tunnel_del_session,
	.tx_init = bfd_vxlan_tunnel_tx_init,
	.set_sll_protocol = false,
};

static struct bfd_feature_vector *feat_vect[] =
    { &echo_vec, &lag_vec, &vxlan_tunnel_vec };

u_int32_t feat_pkt_size[] =
    { sizeof(struct bfd_echo_packet), sizeof(struct bfd_ctrl_packet),
	VXLAN_BFD_PKT_ALLOC_SIZE
};

u_int32_t feat_priv_size[] =
    { sizeof(struct bfd_echo_priv), 0, sizeof(struct bfd_vxlan_tunnel_priv) };

static void
bfd_vxlan_tunnel_init_packet(struct bfd_session *bfd,
			     struct bfd_nl_vxlan_tunnel_peerinfo *peer);


void delete_bfd_feature(struct bfd_session *bfd)
{
	if (bfd->feat) {
		bfd->feat->vect->free(bfd);
		FREE_BFD_FEATURE(bfd);
	}
}

int alloc_bfd_feature(struct bfd_session *bfd, struct bfd_nl_peerinfo *peer,
		      int err_start)
{
	int ret = 0, feat_type = BFD_ECHO_FEATURE;
	char buf[256];

	/*
	 * If the LAG capability has been enabled we disable
	 * the echo function irrespective of whether echo 
	 * has been enabled or not.
	 */
	if (bfd->session_type == BFD_MICRO_SESSION) {
		feat_type = BFD_LAG_FEATURE;
	} else if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION) {
		feat_type = BFD_VXLAN_FEATURE;
	} else if (bfd->session_type != BFD_NORMAL_SESSION) {
		goto done;
	}

	ALLOC_BFD_FEATURE(bfd, feat_type);

	bfd->feat->vect = feat_vect[feat_type];
	bfd->feat->pkt_size = FEATURE_PKT_SIZE(bfd, feat_type);
	bfd->feat->payload = bfd->feat->pkt + bfd->proto->hdr_len(bfd);
	bfd->feat->payload_len = feat_pkt_size[feat_type];
	if (IS_DEBUG_BSM)
		blog_debug
		    ("alloc_bfd_feature: peer(%s), feature type(%d),add(%p)",
		     bfd->proto->addr_print(bfd->dst, buf), feat_type,
		     bfd->feat->vect->add_session);

	if (bfd->feat->vect->add_session)
		bfd->feat->vect->add_session(bfd, peer);

	bfd->proto->init_hdrs(bfd);

	if (!(ret = bfd->feat->vect->tx_init(bfd, peer, feat_type)))
		goto done;

	ret += err_start;
	FREE_BFD_FEATURE(bfd);
 done:
	return ret;
}

int bfd_feature_init(void)
{
	/* Workqueue for echo send process */
	master->tx_echo_wq = create_singlethread_workqueue("kbfd_echo_tx");
	if (!master->tx_echo_wq) {
		blog_err("failed create echo tx workqueue");
	}
	/* Workqueue for echo receive expire */
	master->echo_expire_wq =
	    create_singlethread_workqueue("kbfd_echo_rx_expire");
	if (!master->echo_expire_wq) {
		blog_err("failed create echo expire workqueue");
	}

	/* Workqueue for echo tx reset */
	master->echo_tx_reset_wq =
	    alloc_workqueue("kbfd_echo_tx_reset", WQ_MEM_RECLAIM, 0);
	if (!master->echo_tx_reset_wq) {
		blog_err("failed create echo tx reset workqueue");
	}
	/* Workqueue for echo exp reset */
	master->echo_exp_reset_wq =
	    alloc_workqueue("kbfd_echo_exp_reset", WQ_MEM_RECLAIM, 0);
	if (!master->echo_exp_reset_wq) {
		blog_err("failed create echo exo reset workqueue");
	}

	return 0;
}

int bfd_feature_finish(void)
{
	if (master->tx_echo_wq) {
		destroy_workqueue(master->tx_echo_wq);
		master->tx_echo_wq = NULL;
	}

	if (master->echo_expire_wq) {
		destroy_workqueue(master->echo_expire_wq);
		master->echo_expire_wq = NULL;
	}

	if (master->echo_tx_reset_wq) {
		destroy_workqueue(master->echo_tx_reset_wq);
		master->echo_tx_reset_wq = NULL;
	}

	if (master->echo_exp_reset_wq) {
		destroy_workqueue(master->echo_exp_reset_wq);
		master->echo_exp_reset_wq = NULL;
	}
	return 0;
}
