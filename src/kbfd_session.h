/* 
 * BFD Session Defintion.
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

#ifndef __KBFD_SESSION_H__
#define __KBFD_SESSION_H__

#include "kbfd_packet.h"
#include "kbfd_netlink.h"

#include "kbfd_interface.h"
#include "kbfd_netlink.h"
#include "kbfd_feature.h"

/*
 * BFD State Event
 */
enum { BSM_Start = 0, BSM_Recived_Down, BSM_Recived_Init, BSM_Recived_Up,
	BSM_Timer_Expired, BSM_Echo_Timer_Expired, BSM_Toggle_Admin_Down,
	BFD_BSM_EVENT_MAX
};

#define  HASH_OFFSET(p,X)             ((p)->disc_hash_offset(ntohl(X)))
#define  HASH_KEY_(p,X)               ((X) % BFD_SESSION_HASH_SIZE)
#define  HASH_KEY(p,X)                (HASH_OFFSET(p,X)+HASH_KEY_(p,X))

#ifdef __KERNEL__
//#define KBFD_REFCNT_DEBUG 1
#ifdef KBFD_REFCNT_DEBUG
//#define KBFD_REFCNT_VERBOSE 1
#endif
#endif

enum { SESSION_FIND = 0, SESSION_NEW, SESSION_ADD, SESSION_TIMERS_CHANGE,
       SESSION_NEIGH_CHANGE, RX_RESET, TX_RESET, TX_TIMER, RX_TIMER, 
       ECHO_TX_TIMER, ECHO_RX_TIMER, ECHO_TX_RESET, ECHO_EXP_RESET, 
       MAX_REF_TYPES };

struct bfd_vrf {
   
        struct bfd_vrf *fd_next;
        struct bfd_vrf *name_next;
        int vrf_fd;
        char vrf_name[VRF_NAME_SIZE];
        int  vrf_notif_group;
   
};

struct bfd_session {
	struct bfd_session *session_next;
	union {
		struct bfd_session *__nbr_next;
		struct bfd_session *__lag_session;
	} nbr_next_lag;
        int vrf_fd;
        struct net *netns;
        int notif_group;
	struct sockaddr *dst;
	struct sockaddr *src;
        /* bif is of type struct bfd_interface but vxlantunnel sessions are
         * not associated with interfaces so the pointer will be NULL.  To
         * avoid unreferencing a NULL pointer we have accessors to all bif
         * fields and we keep it as an opaque field.
         */
	void *bif;
	struct socket *tx_ctrl_sock;
	struct delayed_work t_rx_expire;
	struct delayed_work t_tx_work;
	struct bfd_proto *proto;

	u_char session_type;

	struct bfd_feature *feat;
	struct bfd_session *lag_member;
	u_int32_t sport;

	struct work_struct reset_tx;
        struct work_struct reset_rx;

	/* last recv'ed packet */
	struct bfd_ctrl_packet rpkt;

	/* received packet statistics */
	unsigned long rx_last_jiff;
	u_int32_t rx_min;
	u_int32_t rx_max;
	u_int64_t rx_sum;
	u_int64_t rx_n;

	/* sent packet */
	unsigned long tx_jiff;
	unsigned long tx_last_jiff;
	u_int32_t tx_min;
	u_int32_t tx_max;
	u_int64_t tx_sum;
	u_int64_t tx_n;

	/* control packet */
	struct bfd_ctrl_packet cpkt;
	u_int32_t auth_seq;
	u_int32_t xmit_auth_seq;
	u_int32_t auth_seq_known;
	u_int32_t detect_time;
	u_int32_t act_tx_intv;
	u_int32_t act_rx_intv;
	u_int32_t peer_tx_intv;
	u_int32_t peer_rx_intv;
	u_int32_t peer_mult;
	u_int32_t last_rcv_req_rx;

	u_char demand;
	u_char async;

	atomic_t refcnt;
#ifdef KBFD_REFCNT_DEBUG
	atomic_t refcnt_pertype[MAX_REF_TYPES];
#endif
	u_char deleted;

	/* Used to mark sessions that have changed state but not yet retrieved
	   from user space via BFD_GETCHANGE */
	u_char dirty;
   
        void *rx_reset_deferred;
        int   rx_expire_cpu;
        int   tx_cpu;
        void *tx_reset_deferred;
   
#ifdef __KERNEL__
	struct mutex rx_expire_lock;
	struct completion rx_expire_completion;
	struct mutex tx_timeout_lock;
	struct completion tx_timeout_completion;
#endif
	/* For MIB Information(draft-ietf-bfd-mib-03.txt) */
	u_int64_t pkt_in;
	u_int64_t pkt_out;
	u_int64_t pkt_in_up;	/* pkt_in value when session went up */
	u_int64_t pkt_out_up;	/* pkt_out value when session went up */
	bool hist_logged;
	u_int32_t last_up;
	u_int32_t last_down;
	u_int32_t last_diag;
	u_int32_t up_cnt;
	u_int32_t last_discont;	/* FIXME(not implemented) */
	u_int32_t prev_tx_intv;
	u_int32_t prev_rx_intv;


	/* for kbfd tx schedule stats */
	unsigned long last_sched_jiff;
	unsigned long sec_last_sched_jiff;
	u_int32_t lateness[4];
};

#define nbr_next    nbr_next_lag.__nbr_next
#define lag_session nbr_next_lag.__lag_session

#ifdef __KERNEL__
#define current_cpu (current_thread_info()->cpu)

//#define tx_work_cpu(bfd) (work_cpu(&(bfd)->t_tx_work.work))
//#define rx_work_cpu(bfd) (work_cpu(&(bfd)->t_rx_expire.work))

#define tx_work_cpu(bfd) ((bfd)->tx_cpu)
#define rx_work_cpu(bfd) ((bfd)->rx_expire_cpu)

#define tx_work_busy(bfd) (work_busy(&(bfd)->t_tx_work.work) & WORK_BUSY_RUNNING)
#define rx_work_busy(bfd) (work_busy(&(bfd)->t_rx_expire.work) & WORK_BUSY_RUNNING)

#define cpu_rx_ident(bfd) (rx_work_cpu(bfd) == current_cpu)
#define cpu_tx_ident(bfd) (tx_work_cpu(bfd) == current_cpu)

#endif

#ifdef KBFD_REFCNT_VERBOSE
#define refcnt_dbg(f,x) printk("%s(%s) : Session(%d:%d) : %d/%d\n", __PRETTY_FUNCTION__, f, ntohl((x)->cpkt.my_disc), ntohl((x)->cpkt.your_disc), atomic_read(&(x)->refcnt), (x)->deleted)

#define bfd_session_grab(x,y) (refcnt_dbg("bfd_session_grab",x), \
                               bfd_session_grab_((x),y))
#define bfd_session_release(x,y) (refcnt_dbg("bfd_session_release",x),   \
                                  bfd_session_release_((x),y))
#else

#define bfd_session_grab(x,y)     bfd_session_grab_((x),y)
#define bfd_session_release(x,y)  bfd_session_release_((x),y)

#endif

int bfd_session_init(void);
int bfd_session_finish(void);
struct bfd_session *bfd_session_lookup(struct bfd_proto *, u_int32_t,
				       int vrf_fd, struct sockaddr *, int);
struct bfd_session *bfd_micro_session_lookup(struct bfd_session *, int);
struct bfd_nl_peer_info;
int bfd_session_add(struct bfd_proto *, struct bfd_nl_peerinfo *);
int bfd_session_delete(struct bfd_proto *, struct sockaddr *, int,
		       bfd_session_t);
int bfd_session_delete_all(void);
int bfd_session_set_dscp(struct bfd_proto *, int , struct sockaddr *, int, __u8);
int bfd_session_clear_stats(struct bfd_proto *, int, struct sockaddr *, int,
			    bfd_session_t);
int bfd_session_clear_stats_all(void);
int bfd_bsm_event(struct bfd_session *, int);
void bfd_reset_tx_timer(struct bfd_session *);
void bfd_reset_expire_timer(struct bfd_session *);
void bfd_start_xmit_timer(struct bfd_session *);
bool bfd_start_echo(struct bfd_session *);
bool bfd_stop_echo(struct bfd_session *);
int bfd_change_interval_time(struct bfd_session *, u_int32_t, u_int32_t);
void bfd_change_interval_time_q(struct bfd_session *, u_int32_t, u_int32_t);
void bfd_reset_tx_stats(struct bfd_session *);
void bfd_reset_rx_stats(struct bfd_session *);

void bfd_stop_timer(struct bfd_session *, struct delayed_work *, int,
		    struct mutex *, struct completion *, bool);

inline void bfd_session_grab_(struct bfd_session *bfd, int ref_type);
inline bool bfd_session_release_(struct bfd_session *bfd, int ref_type);

#define bfd_session_marked_deleted(bfd) ((bfd)->deleted)
#define bfd_session_mark_deleted(bfd) {(bfd)->deleted = 1;}

extern int BFD_DETECT_MULT_DEFAULT;
extern int BFD_MIN_TX_INTERVAL_DEFAULT;
extern int BFD_MIN_RX_INTERVAL_DEFAULT;

#define MIN_TX(x) ((x)->bif?(x)->bif->v_mintx:BFD_MIN_TX_INTERVAL_DEFAULT)
#define MIN_RX(x) ((x)->bif?(x)->bif->v_minrx:BFD_MIN_RX_INTERVAL_DEFAULT)

extern spinlock_t tbl_lock;

#endif				/* __KBFD_SESSION_H__ */
