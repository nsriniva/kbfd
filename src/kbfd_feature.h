
#ifndef __KBFD_FEATURE_H__
#define __KBFD_FEATURE_H__

#include <linux/if_packet.h>

#include "kbfd_packet.h"
#include "kbfd_v4v6.h"

#ifndef INIT_COMPLETION
#define INIT_COMPLETION(x) reinit_completion(&x)
#endif

struct bfd_feature_vector {
	bool(*enabled) (struct bfd_session *);
	void (*set_payload) (struct bfd_session *);
	void (*get_udp_ports) (struct bfd_session *, u_int16_t * sport,
			       u_int16_t * dport);
	void *(*get_saddr) (struct bfd_session *, size_t * addr_size);
	void *(*get_daddr) (struct bfd_session *, void *saddr);
	int (*tx_init) (struct bfd_session *, struct bfd_nl_peerinfo *,
			int feat_type);
	 bool(*update_dmac) (struct bfd_session *);
	void (*free) (struct bfd_session *);
	void (*add_session) (struct bfd_session *, struct bfd_nl_peerinfo *);
	void (*del_session) (struct bfd_session *);
	bool set_sll_protocol;
};

struct bfd_echo_priv {
	bool echo_start;
	struct bfd_session *bfd;
#ifdef __KERNEL__
	struct mutex echo_expire_lock;
	struct completion echo_expire_completion;
	struct mutex echo_xmit_lock;
	struct completion echo_xmit_completion;
#endif
	struct delayed_work t_echo_tx_work;
	struct delayed_work t_echo_rx_expire;
	struct work_struct reset_echo_tx;
	struct work_struct reset_echo_exp;
	u_int32_t echo_detect_time;
	u_int32_t act_echo_tx_intv;
	u_int32_t peer_echo_rx_intv;
};

struct bfd_vxlan_tunnel_priv {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} outer_dst;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} outer_src;
	u_int16_t outer_sport;
	u_int16_t outer_dport;
	u_int32_t flags;
	u_int32_t vni;
	// Inner dst is the dst field from the nl_peerinfo struct
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} inner_src;
	unsigned char inner_dmac[ETH_ALEN];
	// inner source mac is the same as outer source mac
	unsigned char inner_smac[ETH_ALEN];
        u_int32_t mintx;           
        u_int32_t minrx;              
        u_int32_t mult;
};

struct bfd_vxlan_encap_pkt {
	struct ethhdr eth;
	struct iphdr iph;
	struct udphdr udph;
	struct bfd_ctrl_packet payload;
} __attribute__ ((packed));

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

struct vxlan_bfd_pkt {
	struct vxlanhdr vxlan_hdr;
	struct bfd_vxlan_encap_pkt bfdpkt;
} __attribute__ ((packed));

#define offset(x) offsetof(struct bfd_vxlan_encap_pkt, x)

#define up_size(x)     ((x/4 + 1)*4)
#define alloc_size_(x) ((x%4)?up_size(x):x)
#define alloc_size(x)  alloc_size_(sizeof(x))
#define VXLAN_BFD_PKT_ALLOC_SIZE (alloc_size(struct vxlan_bfd_pkt))

struct l2_addr {
	bool _valid_dmac;
	struct sockaddr_ll _dst;
	struct neighbour *_neigh;
};

struct bfd_feature {
	void *priv;
	struct bfd_feature_vector *vect;
	struct socket *tx_sock;
	union {
		struct l2_addr l2addr;
		struct sockaddr_in l3v4addr;
	} dest;
	void *payload;
	u_int32_t payload_len;
	size_t pkt_size;
	char pkt[0];
};

#define l2dst dest.l2addr._dst
#define l3v4dst dest.l3v4addr

#define _neigh dest.l2addr._neigh
#define valid_dmac dest.l2addr._valid_dmac

#define BFD_ECHO_FEATURE 0
#define BFD_LAG_FEATURE  1
#define BFD_VXLAN_FEATURE 2

extern u_int32_t feat_pkt_size[];

extern u_int32_t feat_priv_size[];

#define FEATURE_PKT_SIZE(bfd, type) (feat_pkt_size[(type)] + \
                                     (bfd)->proto->hdr_len((bfd)))

#define BFD_FEATURE_SIZE(bfd, type) (sizeof(struct bfd_feature) + \
                                     FEATURE_PKT_SIZE((bfd),(type)))

#define BFD_FEATURE_PRIV_SIZE(bfd, type) (feat_priv_size[(type)] + \
                                          BFD_FEATURE_SIZE((bfd),(type)))

#define ALLOC_BFD_FEATURE(bfd, type) { (bfd)->feat =            \
      kzalloc(BFD_FEATURE_PRIV_SIZE((bfd),(type)), GFP_KERNEL); \
   if (!(bfd)->feat) goto done;                                 \
   if (feat_priv_size[(type)])                                  \
      bfd->feat->priv = (((char *)bfd->feat) +                  \
			   BFD_FEATURE_SIZE(bfd, feat_type));   \
   }

#define FREE_BFD_FEATURE(bfd) {kfree((bfd)->feat);(bfd)->feat = NULL;}

extern int alloc_bfd_feature(struct bfd_session *bfd,
			     struct bfd_nl_peerinfo *peer, int err_start);
extern void delete_bfd_feature(struct bfd_session *bfd);

#define ECHO_PRIV(bfd) ((struct bfd_echo_priv *)(bfd)->feat->priv)

#define VXLAN_TUNNEL_PRIV(bfd) ((struct bfd_vxlan_tunnel_priv *)(bfd)->feat->priv)

#define ECHO_PKT(bfd) ((struct bfd_echo_packet *)(bfd)->feat->payload)
#define LAG_PKT(bfd) ((struct bfd_ctrl_packet *)(bfd)->feat->payload)
#define VXLAN_PKT(bfd) ((struct vxlan_bfd_pkt *)(bfd)->feat->payload)

extern inline bool bfd_feat_active(struct bfd_session *bfd, int feat_type);

#define ECHO_ACTIVE(bfd) (bfd_feat_active((bfd), BFD_ECHO_FEATURE))
#define LAG_ACTIVE(bfd) (bfd_feat_active((bfd), BFD_LAG_FEATURE))

#define GET_ECHO_PRIV_FIELD(bfd, x) (ECHO_ACTIVE((bfd)) ? ECHO_PRIV((bfd))->x : 0)

#define SET_ECHO_PRIV_FIELD(bfd, x, val) (ECHO_ACTIVE((bfd)) ? (ECHO_PRIV((bfd))->x = (val)) : 0)

void bfd_feat_session_del(struct bfd_session *bfd);

void bfd_start_echo_xmit_timer(struct bfd_session *);
inline void bfd_start_echo_expire_timer(struct bfd_session *);
void bfd_echo_xmit_timeout(struct work_struct *);
void bfd_stop_echo_xmit_timer(struct bfd_session *);

void bfd_detect_echo_timeout(struct work_struct *);
void bfd_stop_echo_expire_timer(struct bfd_session *);

void bfd_reset_echo_tx_timer(struct bfd_session *);
void bfd_reset_echo_expire_timer(struct bfd_session *);
void bfd_reset_echo_tx_timer_q(struct bfd_session *);
void bfd_reset_echo_expire_timer_q(struct bfd_session *);

int bfd_feature_init(void);
int bfd_feature_finish(void);

#endif				/* __KBFD_FEATURE_H__ */
