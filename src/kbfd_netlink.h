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

#ifndef __KBFD_NETLINK_H__
#define __KBFD_NETLINK_H__

#ifndef NETLINK_BFD
/* Protocol Name Define */
#define NETLINK_BFD (NETLINK_GENERIC + 1)
#endif

/*
 * netlink message type
 */
#define  BFD_NEWPEER                         (NLMSG_MIN_TYPE + 1)	/* Add BFD Session */
#define  BFD_DELPEER                         (NLMSG_MIN_TYPE + 2)	/* Delete BFD Session */
#define  BFD_GETPEER                         (NLMSG_MIN_TYPE + 3)	/* Get Peer Information */
#define  BFD_ADMINDOWN                       (NLMSG_MIN_TYPE + 4)	/* Set Session to AdminDown */
#define  BFD_SETLINK                         (NLMSG_MIN_TYPE + 5)	/* Set Interface Parameter */
#define  BFD_SETFLAG                         (NLMSG_MIN_TYPE + 6)	/* Set Debug Flag Parameter */
#define  BFD_CLEAR_COUNTER                   (NLMSG_MIN_TYPE + 7)	/* Clear Counter */
#define  BFD_CLEAR_SESSION                   (NLMSG_MIN_TYPE + 8)	/* Re-Initialize Session */
#define  BFD_SETDSCP                         (NLMSG_MIN_TYPE + 9)	/* Set DiffServ CodePoint */
#define  BFD_GETCHANGE                       (NLMSG_MIN_TYPE + 10)	/* Get list of peer that have changed state */
#define  BFD_SETSLOW                         (NLMSG_MIN_TYPE + 11)	/* Set slow timer value */
#define  BFD_RESETLINK                       (NLMSG_MIN_TYPE + 12)	/* Reset interface bfd parameters to default */
#define  BFD_ECHO                            (NLMSG_MIN_TYPE + 13)	/* Control echo functionality */
#define  BFD_SETDEFAULTS                     (NLMSG_MIN_TYPE + 14)	/* Set default bfd parameters */
#define  BFD_CLEAR_STATS                     (NLMSG_MIN_TYPE + 15)	/* Clear Stats */
#define  BFD_DEL_ALL                         (NLMSG_MIN_TYPE + 16)	/* Delete all */
#define  BFD_CREATE_VRF                      (NLMSG_MIN_TYPE + 17)	/* Creat Vrf */
#define  BFD_DELETE_VRF                      (NLMSG_MIN_TYPE + 18)	/* Creat Vrf */

/* 
 * BFD State
 */
#define    BSM_AdminDown		             0
#define    BSM_Down		                     1
#define    BSM_Init		                     2
#define    BSM_Up		                     3
#define    BFD_BSM_STATE_MAX                         4

/*
 *  The value of VRF_NAME_SIZE is derived from from the max length
 *  of the Ip::VrfName type defined in Ira/Ip.tac
 */
#define    VRF_NAME_SIZE       101

#define PEER_STAT \
        __u8 is1hop;                      \
	__u8 state;                       \
	__u8 dscp;                        \
	__u8 session_type;                \
        __u32 vrf_fd;                     \
        __u8  notif_group;                \
	union {                           \
		struct sockaddr sa;       \
		struct sockaddr_in sin;   \
		struct sockaddr_in6 sin6; \
	} dst;                            \
	union {                           \
		struct sockaddr sa;       \
		struct sockaddr_in sin;   \
		struct sockaddr_in6 sin6; \
	} src;                            \
	int ifindex;                      \
	u_int32_t my_disc;                \
	u_int32_t your_disc;              \
	u_int32_t last_up;                \
	u_int32_t last_down;              \
	u_int32_t last_diag;              \


/* BFD session type */
typedef enum {
	BFD_NORMAL_SESSION,
	BFD_LAG_SESSION,
	BFD_MICRO_SESSION,
	BFD_VXLAN_TUNNEL_SESSION
} bfd_session_t;

extern char *session_str[];

/* Peer State Information */
struct bfd_nl_peerstat {
PEER_STAT};

/* Peer Information */
struct bfd_nl_peerinfo {
	PEER_STAT
	    /* counters */
	u_int64_t pkt_in;
	u_int64_t pkt_out;
	u_int32_t up_cnt;
	u_int32_t last_discont;	/* FIXME(not implemented) */
};

struct bfd_nl_vxlan_tunnel_peerinfo {
	struct bfd_nl_peerinfo peer_info;
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
	unsigned char inner_smac[ETH_ALEN];
	u_int32_t mintx;
	u_int32_t minrx;
	u_int32_t mult;
};

struct bfd_nl_echo {
	int ifindex;
	bool echo_on;
};

struct bfd_nl_linkinfo {
	int ifindex;
	u_int32_t mintx;
	u_int32_t minrx;
	u_int32_t mult;
	bool per_link;		/* Set to true iff the interface is a
				   port channel and the per link feature
				   has been enabled on it */
};

struct bfd_nl_vrfinfo {
        int vrf_fd;
        char vrf_name[VRF_NAME_SIZE];
        int  vrf_notif_group;
};

int bfd_netlink_init(void);
void bfd_netlink_finish(void);
void bfd_nl_send(struct bfd_session *);

#endif				/* __KBFD_NETLINK_H__ */
