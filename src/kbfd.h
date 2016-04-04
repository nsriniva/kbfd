/* 
 * BFD Headers.
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

#ifndef __BFD_H_
#define __BFD_H_

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/jiffies.h>

#else

#include "proc_compat.h"

#endif

#define BFD_MIN_TX_INTERVAL_INIT   1000000	/* 1sec=1,000,000usec */
#define BFD_MIN_RX_INTERVAL_INIT   1000000	/* 1sec=1,000,000usec */

#define BFD_SESSION_HASH_SIZE      257

struct bfd_master {
	struct bfd_session *session_tbl[2 * BFD_SESSION_HASH_SIZE];
	spinlock_t ses_tbl_lock;
	struct workqueue_struct *tx_ctrl_wq;
	struct workqueue_struct *ctrl_expire_wq;
	struct workqueue_struct *tx_reset_wq;
        struct workqueue_struct *rx_reset_wq;
	struct workqueue_struct *echo_tx_reset_wq;
	struct workqueue_struct *echo_exp_reset_wq;
	u_int32_t discriminator;
	struct workqueue_struct *tx_echo_wq;
	struct workqueue_struct *echo_expire_wq;
	u_int32_t slow_timer;
};

struct bfd_proto {
	struct bfd_session **nbr_tbl;
	spinlock_t nbr_tbl_lock;
        struct bfd_vrf **vrf_fd_tbl;
        struct bfd_vrf **vrf_name_tbl;
	u_int32_t disc[2];
	int last_sport_offset;
	 u_int32_t(*disc_hash_offset) (u_int32_t disc);
	 u_int32_t(*next_disc) (u_int32_t key);
	int (*create_ctrl_socket) (struct bfd_session *);
	struct neighbour *(*get_neigh) (struct bfd_session *,
					u_int32_t ifindex);
        struct net *(*get_netns) ( struct bfd_session *);
	 u_int32_t(*hdr_len) (struct bfd_session *);
	void (*init_hdrs) (struct bfd_session *);
	int (*xmit_feature_packet) (struct bfd_session *);
	 u_int32_t(*hash) (struct sockaddr *);
	void *(*get_addr) (struct sockaddr * addr, size_t * addr_size);
	int (*cmp) (struct sockaddr *, struct sockaddr *);
	int (*eq) (struct sockaddr *, struct sockaddr *);
	char *(*addr_print) (struct sockaddr *, char *);
	int (*namelen) (struct sockaddr *);
	int (*get_oif) (struct bfd_session *);
	int (*xmit_packet[]) (struct bfd_session *);
};

extern struct bfd_master *master;
#endif				/* __BFD_H_ */
