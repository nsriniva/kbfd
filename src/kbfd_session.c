/* 
 *  BFD Session Management
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
#include <linux/completion.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_v4v6.h"
#include "kbfd_session.h"
#include "kbfd_packet.h"
#include "kbfd_log.h"
#include "kbfd_interface.h"
#include "kbfd.h"
#ifndef __KERNEL__
#include <stdio.h>
#endif

extern void bfd_update_tx_sched_delay(struct bfd_session *bfd);
extern int BFD_DETECT_MULT_DEFAULT;
extern int BFD_MIN_TX_INTERVAL_DEFAULT;
extern int BFD_MIN_RX_INTERVAL_DEFAULT;

static struct proc_dir_entry *kbfd_root_dir = NULL;
static struct proc_dir_entry *sessionv4_proc = NULL;
static struct proc_dir_entry *sessionv4_proc_detail = NULL;
static struct proc_dir_entry *sessionv6_proc = NULL;
static struct proc_dir_entry *sessionv6_proc_detail = NULL;
#ifdef KBFD_REFCNT_DEBUG
static struct proc_dir_entry *session_del_proc = NULL;
#endif
spinlock_t tbl_lock;

char *bfd_state_string[] = {
	"AdminDown",
	"Down",
	"Init",
	"Up",
};

char *bfd_event_string[] = {
	"Start",
	"Received_Down",
	"Received_Init",
	"Received_Up",
	"TimerExpired",
	"EchoTimerExpired",
	"Toggle_AdminDown",
};

int bfd_bsm_event(struct bfd_session *, int);

void bfd_start_xmit_timer(struct bfd_session *);
void bfd_xmit_timeout(struct work_struct *);
void bfd_stop_xmit_timer(struct bfd_session *);

void bfd_detect_timeout(struct work_struct *);
void bfd_stop_expire_timer(struct bfd_session *);

#ifdef KBFD_REFCNT_DEBUG
static struct bfd_session *deleted_sessions = NULL;
static int deleted_sessions_cnt = 0;
static DEFINE_SPINLOCK(del_lock);

static inline void print_deleted_sessions(void)
{
	struct bfd_session *bfd;
	int i = 0;

	if (deleted_sessions == NULL)
		return;
	spin_lock(&del_lock);
	bfd = deleted_sessions;
	printk(KERN_DEBUG "\n Deleted Sessions : %d", deleted_sessions_cnt);
	while (bfd) {
		char addr_buf[128];

		printk(KERN_DEBUG "Session[%d] == %s\n", i++,
		       bfd->proto->addr_print(bfd->dst, addr_buf));
	}
	spin_unlock(&del_lock);
}

static void inline add_deleted_session(struct bfd_session *bfd)
{
	bfd->session_next = bfd->nbr_next = NULL;
	if (atomic_read(&bfd->refcnt) > 1) {
		// Insert bfd into the deleted_sessions list
		// session_next == prev ptr
		// nbr_next == next ptr
		spin_lock(&del_lock);
		bfd->nbr_next = deleted_sessions;
		if (deleted_sessions)
			deleted_sessions->session_next = bfd;
		bfd->session_next = NULL;
		deleted_sessions = bfd;
		deleted_sessions_cnt++;
		spin_unlock(&del_lock);
	}
}

static void inline rem_deleted_session(struct bfd_session *bfd)
{
	if (!(bfd->session_next || bfd->nbr_next))
		if (!(deleted_sessions && (deleted_sessions == bfd)))
			return;

	spin_lock(&del_lock);
	if (bfd->nbr_next)
		bfd->nbr_next->session_next = bfd->session_next;
	deleted_sessions_cnt--;
	if (bfd->session_next) {
		bfd->session_next->nbr_next = bfd->nbr_next;
	} else {
		deleted_sessions = bfd->nbr_next;
	}
	spin_unlock(&del_lock);
}
#endif				/* KBFD_REFCNT_DEBUG */


static void bfd_session_free(struct bfd_session *bfd)
{
	if (bfd) {
		sock_release(bfd->tx_ctrl_sock);
#ifdef __KERNEL__
                put_net(bfd->netns);
#endif
		if (bfd->src) {
			kfree(bfd->src);
		}
		if (bfd->dst) {
			kfree(bfd->dst);
		}
		delete_bfd_feature(bfd);
		kfree(bfd);
	}
	return;
}

inline void bfd_session_grab_(struct bfd_session *bfd, int ref_type)
{
#ifdef KBFD_REFCNT_DEBUG
	atomic_inc(&bfd->refcnt_pertype[ref_type]);
#endif
	atomic_inc(&bfd->refcnt);
}

inline bool bfd_session_release_(struct bfd_session *bfd, int ref_type)
{
#ifdef KBFD_REFCNT_DEBUG
	atomic_dec(&bfd->refcnt_pertype[ref_type]);
#endif
	if (atomic_dec_and_test(&bfd->refcnt)) {

		if (bfd_session_marked_deleted(bfd)) {
#ifdef KBFD_REFCNT_DEBUG
			rem_deleted_session(bfd);
#endif
			bfd_session_free(bfd);
			return true;
		} else {
			char buf[256];

			blog_err("Session %s/%d leaked!",
				 bfd->proto->addr_print(bfd->dst, buf),
				 ntohl(bfd->cpkt.my_disc));
		}
	}
	return false;
}

#ifdef __KERNEL__

static void bfd_reset_tx(struct work_struct *_work)
{
	struct bfd_session *bfd =
	    container_of(_work, struct bfd_session, reset_tx);

	bfd_reset_tx_timer(bfd);
	bfd_session_release(bfd, TX_RESET);
}

static void bfd_reset_tx_timer_q(struct bfd_session *bfd)
{
	if (!bfd_session_marked_deleted(bfd) &&
	    queue_work(master->tx_reset_wq, &bfd->reset_tx))
		bfd_session_grab(bfd, TX_RESET);
}

static void bfd_reset_rx(struct work_struct *_work)
{
	struct bfd_session *bfd =
	    container_of(_work, struct bfd_session, reset_rx);

	bfd_reset_expire_timer(bfd);
	bfd_session_release(bfd, RX_RESET);
}

#if 0
static void bfd_reset_expire_timer_q(struct bfd_session *bfd)
{
	if (!bfd_session_marked_deleted(bfd) &&
	    queue_work(master->rx_reset_wq, &bfd->reset_rx))
		bfd_session_grab(bfd, RX_RESET);
}
#endif


#endif

u32 get_sys_uptime(void)
{
	struct timespec ts;

	ktime_get_ts(&ts);

	return ((ts.tv_sec * 100L) + (ts.tv_nsec / (NSEC_PER_SEC / 100L)));

}

struct bfd_session *bfd_session_lookup_(struct bfd_proto *proto,
					u_int32_t my_disc, int vrf_fd,
                                        struct sockaddr *dst,
					int ifindex, bool grab_ref)
{
	u_int32_t key;
	struct bfd_session *bfd;
#ifdef KBFD_REFCNT_VERBOSE
	char buf[256], *dst_str = "Null";

	if (proto && dst)
		dst_str = proto->addr_print(dst, buf);
	printk("\n Looking up dst(%s) disc(%d) ifindex(%d) grab_ref(%d)\n",
	       dst_str, ntohl(my_disc), ifindex, grab_ref);
#endif
	rcu_read_lock();
	if (my_disc) {
		key = HASH_KEY(proto, my_disc);
		bfd = master->session_tbl[key];
		while (bfd) {
			if (bfd->cpkt.my_disc == my_disc)
				break;
			bfd = bfd->session_next;
		}
	} else {
		key = proto->hash(dst);

		bfd = proto->nbr_tbl[key];
		while (bfd) {
                         if (proto->eq(bfd->dst, dst)&& (vrf_fd == bfd->vrf_fd))
				if (!ifindex || 
                                    bfd_interface_index(bfd->bif) == ifindex)
					break;
			bfd = bfd->nbr_next;
		}
	}
	if (bfd && grab_ref)
		bfd_session_grab(bfd, SESSION_FIND);
	rcu_read_unlock();

	return bfd;
}

static int bfd_lag_session_state(struct bfd_session *bfd)
{
	struct bfd_session *tmp = bfd->lag_member;

	while (tmp) {
		if (tmp->cpkt.state == BSM_Up) {
			return BSM_Up;
		}
		tmp = tmp->lag_member;
	}
	return BSM_Down;
}

static struct bfd_session *bfd_session_lookup_noref(struct bfd_proto *proto,
						    u_int32_t my_disc,
                                                    int vrf_fd,
						    struct sockaddr *dst,
						    int ifindex)
{
   return bfd_session_lookup_(proto, my_disc, vrf_fd, dst, ifindex, false);
}

struct bfd_session *bfd_micro_session_lookup_(struct bfd_session *lag_bfd,
					      int ifindex, bool grab_ref)
{
	struct bfd_session *bfd = 0;

	rcu_read_lock();
	for (bfd = lag_bfd->lag_member; bfd; bfd = bfd->lag_member) {
		if (bfd_interface_index(bfd->bif) == ifindex)
			break;
	}
	if (bfd && grab_ref)
		bfd_session_grab(bfd, SESSION_FIND);
	rcu_read_unlock();

	return bfd;
}

struct bfd_session *bfd_session_lookup(struct bfd_proto *proto,
				       u_int32_t my_disc, 
                                       int vrf_fd, struct sockaddr *dst,
				       int ifindex)
{
   return bfd_session_lookup_(proto, my_disc, vrf_fd, dst, ifindex, true);
}

struct bfd_session *bfd_micro_session_lookup(struct bfd_session *lag_bfd,
					     int ifindex)
{
	return bfd_micro_session_lookup_(lag_bfd, ifindex, true);
}

struct bfd_session *bfd_micro_session_lookup_noref(struct bfd_session *lag_bfd,
						   int ifindex)
{
	return bfd_micro_session_lookup_(lag_bfd, ifindex, false);
}

struct bfd_session *bfd_session_lookup_with_type(struct bfd_proto *proto,
						 u_int32_t my_disc,
                                                 int vrf_fd,
						 struct sockaddr *dst,
						 int ifindex,
						 bfd_session_t session_type)
{
	struct bfd_session *bfd = NULL;
	struct bfd_session *lag_bfd = NULL;

	if (session_type != BFD_MICRO_SESSION) {
           bfd = bfd_session_lookup(proto, 0, vrf_fd, dst, ifindex);
	} else {
		/* For micro session, check its Lag session exist first */
           lag_bfd = bfd_session_lookup(proto, 0, vrf_fd, dst, 0);
		if (!lag_bfd) {
			if (IS_DEBUG_NETLINK)
				blog_warn("Can't find Lag session");
			return lag_bfd;
		}
		bfd = bfd_micro_session_lookup(lag_bfd, ifindex);
		bfd_session_release(lag_bfd, SESSION_FIND);
	}
	return bfd;
}

inline struct bfd_session *bfd_session_new(struct bfd_proto *proto,
					   struct bfd_nl_peerinfo *peer)
{
	struct bfd_session *bfd;
	void *ptr;
	char buf[256];
#ifdef KBFD_REFCNT_DEBUG
	int i;
#endif
	int err = 0;
	struct sockaddr *dst = &peer->dst.sa, *src = &peer->src.sa;
	int ifindex = peer->ifindex;
	bfd_session_t session_type = peer->session_type;

	if (IS_DEBUG_BSM) {
		blog_info("bfd_session_new called:");
		blog_info(" src %s ", proto->addr_print(src, buf));
		blog_info(" dst %s ", proto->addr_print(dst, buf));
		blog_info(" session_type %d ", session_type);
	}
	bfd = kzalloc(sizeof(struct bfd_session), GFP_KERNEL);
	if (!bfd) {
		err = -1;
		goto done;
	}

	bfd->proto = proto;

#ifdef __KERNEL__
	mutex_init(&bfd->rx_expire_lock);
	init_completion(&bfd->rx_expire_completion);
	mutex_init(&bfd->tx_timeout_lock);
	init_completion(&bfd->tx_timeout_completion);
#endif
        bfd->vrf_fd = peer->vrf_fd;
        bfd->notif_group = peer->notif_group;
	atomic_set(&bfd->refcnt, 1);
#ifdef KBFD_REFCNT_DEBUG
	atomic_set(&bfd->refcnt_pertype[SESSION_NEW], 1);
	for (i = SESSION_FIND; i < MAX_REF_TYPES; i++)
		if (i != SESSION_NEW)
			atomic_set(&bfd->refcnt_pertype[i], 0);
#endif

	bfd->cpkt.state = BSM_Down;
	bfd->act_tx_intv = BFD_MIN_TX_INTERVAL_INIT;
	bfd->cpkt.des_min_tx_intv = htonl(BFD_MIN_TX_INTERVAL_INIT);
	bfd->act_rx_intv = BFD_MIN_RX_INTERVAL_INIT;
	bfd->cpkt.req_min_rx_intv = htonl(BFD_MIN_RX_INTERVAL_INIT);
	bfd->cpkt.detect_mult = BFD_DETECT_MULT_DEFAULT;
	bfd->cpkt.version = BFD_VERSION_1;
	bfd->cpkt.length = sizeof(struct bfd_ctrl_packet);


	ptr = kmalloc(bfd->proto->namelen(dst), GFP_KERNEL);
	bfd->dst = ptr;
	if (!bfd->dst) {
		err = -2;
		goto fail;
	}

	memcpy(bfd->dst, dst, bfd->proto->namelen(dst));
	bfd->src = kmalloc(bfd->proto->namelen(dst), GFP_KERNEL);
	if (!bfd->src) {
		err = -3;
		goto fail;
	}
	memcpy(bfd->src, src, bfd->proto->namelen(src));

        if (IS_ERR_OR_NULL(bfd->proto->get_netns(bfd))) {
                err = -4;
                goto fail;
        }
	if (bfd->proto->create_ctrl_socket(bfd)) {
		err = -5;
		goto fail;
	}
	if (session_type != BFD_VXLAN_TUNNEL_SESSION) {
#ifdef __KERNEL__
		//This implies that we cannot test BFD sessions between two IP addresses
		//over multiple interfaces/paths in the user space process variant.
		/* set output interface */
		bfd->tx_ctrl_sock->sk->sk_bound_dev_if = ifindex;
#endif
		if (ifindex == 0) {
			ifindex = bfd->proto->get_oif(bfd);
		}

		if (ifindex == 0) {
			err = -6;
			goto fail;
		}
		/* bind interface */
		bfd->bif = bfd_interface_get(ifindex);
	}
        bfd->tx_cpu = bfd->rx_expire_cpu = -1;
	bfd->session_type = session_type;
	err = alloc_bfd_feature(bfd, peer, -6);
	if (!err) {
                #ifdef __KERNEL__
	           INIT_DELAYED_WORK(&bfd->t_tx_work, bfd_xmit_timeout);
	           INIT_DELAYED_WORK(&bfd->t_rx_expire, bfd_detect_timeout);

	           INIT_WORK(&bfd->reset_tx, bfd_reset_tx);
                   INIT_WORK(&bfd->reset_rx, bfd_reset_rx);
                #else
	           INIT_DELAYED_WORK(&bfd->t_tx_work, bfd_xmit_timeout, true);
	           INIT_DELAYED_WORK(&bfd->t_rx_expire, bfd_detect_timeout, false); 
                #endif
		goto done;
        }
 fail:
	if (bfd->src)
		kfree(bfd->src);
	if (bfd->dst)
		kfree(bfd->dst);
	kfree(bfd);
	bfd = NULL;
 done:
	if (IS_DEBUG_BSM && err)
		blog_debug("Session creation failed with %d", err);
	return bfd;
}

int bfd_session_add(struct bfd_proto *proto, struct bfd_nl_peerinfo *peer)
{
	struct bfd_session *bfd, *lag_bfd = NULL;
	u_int32_t key;
	int err = 0;
	u_int32_t my_disc = 0;
	struct sockaddr *dst = &peer->dst.sa;
	int ifindex = peer->ifindex;
	bfd_session_t session_type = peer->session_type;
        int vrf_fd = peer->vrf_fd;

	if (session_type != BFD_MICRO_SESSION) {
                bfd = bfd_session_lookup_noref(proto, 0, vrf_fd, dst, ifindex);
		if (bfd) {
			if (IS_DEBUG_NETLINK)
				blog_warn
				    ("Bfd session already registered. ignore.");
			err = -EEXIST;
			return err;
		}
	} else {
		/* For micro session, check its Lag session exist first */
                lag_bfd = bfd_session_lookup_noref(proto, 0, vrf_fd, dst, 0);
		if (!lag_bfd) {
			if (IS_DEBUG_NETLINK)
				blog_warn
				    ("Lag session should be registered before micro session");
			err = -EEXIST;
			return err;
		}
		bfd = bfd_micro_session_lookup_noref(lag_bfd, ifindex);
		if (bfd) {
			if (IS_DEBUG_NETLINK)
				blog_warn
				    ("Micro session already registered. ignore.");
			err = -EEXIST;
			return err;
		}
	}

	bfd = bfd_session_new(proto, peer);
	if (!bfd) {
		if (IS_DEBUG_NETLINK)
			blog_warn("Session not created")
			    return -ENOMEM;
	}

	/* register hash */
	spin_lock(&tbl_lock);
	/* only add bfd to nbr_tbl when not micro session */
	key = proto->hash(dst);
	if (session_type != BFD_MICRO_SESSION) {
		bfd->nbr_next = proto->nbr_tbl[key];
		proto->nbr_tbl[key] = bfd;
	} else {
		/* add micro session into lag_member */
		bfd->lag_member = lag_bfd->lag_member;
		lag_bfd->lag_member = bfd;
		bfd->lag_session = lag_bfd;
	}

	/* assign unique discriminator for LAG session as well */
	my_disc = bfd->proto->next_disc(key);
	while (bfd_session_lookup_noref(bfd->proto, htonl(my_disc), 0, NULL, 0)) {
		my_disc = bfd->proto->next_disc(key);
	}
	bfd->cpkt.my_disc = htonl(my_disc);

	key = HASH_KEY(bfd->proto, bfd->cpkt.my_disc);
	bfd->session_next = master->session_tbl[key];
	master->session_tbl[key] = bfd;

	bfd_session_grab(bfd, SESSION_ADD);
	spin_unlock(&tbl_lock);

	if (session_type != BFD_LAG_SESSION)
		bfd_bsm_event(bfd, BSM_Start);

	bfd_session_release(bfd, SESSION_ADD);
	return err;
}

static inline struct bfd_session *
find_and_remove_micro_session_from_lag(struct bfd_session *lag_bfd, int ifindex)
{
	struct bfd_session *prev = NULL, *bfd = NULL;

	bfd = lag_bfd->lag_member;
	while (bfd) {
		if (bfd_interface_index(bfd->bif) == ifindex) {
			if (prev) {
				prev->lag_member = bfd->lag_member;
			} else {
				lag_bfd->lag_member = bfd->lag_member;
			}
			goto done;
		}
		prev = bfd;
		bfd = bfd->lag_member;
	}
 done:
	return bfd;
}

static inline struct bfd_session *
find_and_remove_nbr_table_entry(struct bfd_proto *proto, struct sockaddr *dst,
		int ifindex, bfd_session_t session_type)
{
	struct bfd_session *bfd = NULL, *prev = NULL;
	u_int32_t key;
	char buf[256];
	bool is_micro_session = (session_type == BFD_MICRO_SESSION);

	key = proto->hash(dst);
	bfd = proto->nbr_tbl[key];

	while (bfd) {
		if (proto->eq(bfd->dst, dst)) {
			if (is_micro_session) {
				bfd = find_and_remove_micro_session_from_lag(bfd, ifindex);
				goto done;
			} else if (!bfd->bif || 
                                   (ifindex == bfd_interface_index(bfd->bif))) {
				if ((bfd->session_type != session_type) ||
					((session_type == BFD_LAG_SESSION) && bfd->lag_member)) {
					blog_err
					("Invalid session(%s/%d,%s/%s,%p), ignore",
					proto->addr_print(bfd->dst, buf), ifindex,
					session_str[session_type],
					session_str[bfd->session_type],
					bfd->lag_member);
					bfd = NULL;
					goto done;
				}
				if (prev)
					prev->nbr_next = bfd->nbr_next;
				else
					proto->nbr_tbl[key] = bfd->nbr_next;
				break;
			}
		}
		prev = bfd;
		bfd = bfd->nbr_next;
	}
	if (IS_DEBUG_BSM)
		blog_err("Nbr table entry for %s/%d/%s - %p",
			 proto->addr_print(dst, buf), ifindex,
			 session_str[session_type], bfd);
 done:
	return bfd;
}

void bfd_log_sess_hist(struct bfd_session *bfd, bool del_req)
{
	char hist[LINE_LEN];
	char buf[256];
	u_int32_t tx_intv;
	u_int32_t rx_intv;
	/* when sess hist is logged, skip any further logging */
	if (bfd == NULL || bfd->hist_logged) {
		return;
	}
	if (del_req) {
		tx_intv = bfd->act_tx_intv;
		rx_intv = bfd->act_rx_intv;
	} else {
		tx_intv = bfd->prev_tx_intv;
		rx_intv = bfd->prev_rx_intv;
	}
	/* update session history */
	snprintf(hist, LINE_LEN,
		 "P:%sI:%sS:%dU:%uD:%uDg:%dTx:%dRx:%dDT:%dRC:%lldTC:%lld"
		 "SD:%d,%d,%d,%d,Dt:%d\n",
		 bfd->proto->addr_print(bfd->dst, buf),
                 bfd_interface_name( bfd->bif ),
		 bfd->cpkt.state, bfd->last_up, bfd->last_down, bfd->last_diag,
		 tx_intv / 1000, rx_intv / 1000,
		 bfd->detect_time / 1000,
		 //pkts_in during the session up
		 bfd->pkt_in - bfd->pkt_in_up,
		 //pkts_out during the session up                
		 bfd->pkt_out - bfd->pkt_out_up,
		 bfd->lateness[0], bfd->lateness[1], bfd->lateness[2],
		 bfd->lateness[3],
		 //Dt is del-time(systime at del), else 0
		 del_req ? get_sys_uptime() : 0);
	bfd_add_sess_hist(hist);
	bfd->hist_logged = true;
}

/* spin_lock only the find/walk-tbl part of the deletion. 
 * and avoid the spin_lock during cancel_work* or bfd_stop_*timer() as these
 * functions may sleep */
int
bfd_session_delete(struct bfd_proto *proto, struct sockaddr *dst,
		   int ifindex, bfd_session_t session_type)
{
	struct bfd_session *nbr_bfd = NULL, *prev = NULL, *session_bfd = NULL;
	int ret = 0;
	u_int32_t key;
	char buf[256];

	spin_lock(&tbl_lock);
	nbr_bfd =
	    find_and_remove_nbr_table_entry(proto, dst, ifindex, session_type);

	if (!nbr_bfd) {

		if (IS_DEBUG_BSM)
			blog_err
			    ("Nbr table entry not found for %s/%d(%s). ignore",
			     proto->addr_print(dst, buf), ifindex,
			     session_str[session_type]);

		ret = -1;
		goto finish;
	}

	key = HASH_KEY(proto, nbr_bfd->cpkt.my_disc);
	session_bfd = master->session_tbl[key];
	while (session_bfd) {
		if (session_bfd == nbr_bfd) {
			if (prev)
				prev->session_next = session_bfd->session_next;
			else
				master->session_tbl[key] =
				    session_bfd->session_next;
			goto finish;
		}
		prev = session_bfd;
		session_bfd = session_bfd->session_next;
	}

	if (IS_DEBUG_BSM)
		blog_err("Session %d(local disc) not found. ignore",
			 ntohl(nbr_bfd->cpkt.my_disc));
	ret = -1;
 finish:
	spin_unlock(&tbl_lock);

	if (ret)
		goto done;

	if (IS_DEBUG_BSM) {
		blog_info("session %s/%d, disc=%d deleted",
			  proto->addr_print(nbr_bfd->dst, buf),
			  bfd_interface_index(nbr_bfd->bif),
			  ntohl(nbr_bfd->cpkt.my_disc));
	}
	bfd_session_mark_deleted(nbr_bfd);
#ifdef __KERNEL__
	bfd_feat_session_del(nbr_bfd);
	if (cancel_work_sync(&nbr_bfd->reset_tx))
		bfd_session_release(nbr_bfd, TX_RESET);
        if (cancel_work_sync(&nbr_bfd->reset_rx))
		bfd_session_release(nbr_bfd, RX_RESET);

#endif
	bfd_log_sess_hist(nbr_bfd, true);
	bfd_stop_xmit_timer(nbr_bfd);
	bfd_stop_expire_timer(nbr_bfd);

#ifndef __KERNEL__
	delayed_work_free(&nbr_bfd->t_rx_expire);
	delayed_work_free(&nbr_bfd->t_tx_work);
#endif
	synchronize_rcu();

#ifdef KBFD_REFCNT_DEBUG
	add_deleted_session(nbr_bfd);
#endif

	bfd_session_release(nbr_bfd, SESSION_NEW);
 done:

	return ret;
}

int
bfd_session_delete_all(void)
{
	int i = 0;
	struct bfd_session *lag_bfd = NULL, *tmp_bfd;

	for (i = 0; i < 2 * BFD_SESSION_HASH_SIZE; i++) {
		struct bfd_session *bfd;

		bfd = master->session_tbl[i];
		/* first, remove all but BFD_LAG_SESSIONs */
		while (bfd) {
			tmp_bfd = bfd->session_next;
			if (bfd->session_type == BFD_LAG_SESSION) {
				bfd->session_next = lag_bfd;
				lag_bfd = bfd;
			} else {
				bfd_session_delete(bfd->proto, bfd->dst,
						   bfd_interface_index(bfd->bif),
						   bfd->session_type);
			}
			bfd = tmp_bfd;
		}
	}
	/* remove all BFD_LAG_SESSIONs */
	while (lag_bfd) {
		tmp_bfd = lag_bfd->session_next;
		bfd_session_delete(lag_bfd->proto, lag_bfd->dst,
				   bfd_interface_index(lag_bfd->bif),
				   lag_bfd->session_type);
		lag_bfd = tmp_bfd;
	}
	return 0;
}

/* Note: we are not currently using this set_dscp function. If we want to use it
 * in the future, we need to modify the lookup part for micro sessions, refer to
 * bfd_session_add and bfd_session_delete */
int
bfd_session_set_dscp(struct bfd_proto *proto, int vrf_fd, struct sockaddr *dst,
		     int ifindex, __u8 dscp)
{

	struct bfd_session *bfd;

	bfd = bfd_session_lookup(proto, 0, vrf_fd, dst, ifindex);
	if (!bfd)
		return EINVAL;

#ifdef __KERNEL__
	inet_sk(bfd->tx_ctrl_sock->sk)->tos = dscp;
#ifdef _IP_TOS2PRIO_EXPORTED
	/* can't call rt_tos2priority() as rt_tos2prio is not exported in this kernel */
	bfd->tx_ctrl_sock->sk->sk_priority = rt_tos2priority(dscp);
#else
	bfd->tx_ctrl_sock->sk->sk_priority = TC_PRIO_INTERACTIVE;
#endif

#else
	setsockopt(bfd->tx_ctrl_sock->sk->sk_socket, IPPROTO_IP, IP_TOS, &dscp,
		   sizeof(dscp));
#endif
	bfd_session_release(bfd, SESSION_FIND);
	return 0;
}

int
bfd_session_clear_stats(struct bfd_proto *proto, int vrf_fd, 
                        struct sockaddr *dst,
			int ifindex, bfd_session_t session_type)
{

	struct bfd_session *bfd;

	bfd =
           bfd_session_lookup_with_type(proto, 0, vrf_fd, dst, ifindex, session_type);
	if (!bfd) {
		if (IS_DEBUG_BSM)
			blog_info("no bfd session. ifindex: %d, type: %d ",
				  ifindex, session_type);
		return EINVAL;
	}
	bfd_reset_tx_stats(bfd);
	bfd_reset_rx_stats(bfd);
	bfd_session_release(bfd, SESSION_FIND);
	return 0;
}

void bfd_xmit_timeout(struct work_struct *_work)
{
	struct delayed_work *work =
	    container_of(_work, struct delayed_work, work);
	struct bfd_session *bfd =
	    container_of(work, struct bfd_session, t_tx_work);

#ifdef __KERNEL__
	INIT_COMPLETION(bfd->tx_timeout_completion);
	if (mutex_trylock(&bfd->tx_timeout_lock)) {
#endif
		/* reset timer before send processing(avoid self synchronization) */
		bfd_start_xmit_timer(bfd);

		if (!bfd_session_marked_deleted(bfd))
			bfd_send_ctrl_packet(bfd);
#ifdef __KERNEL__
		mutex_unlock(&bfd->tx_timeout_lock);
	}
	complete_all(&bfd->tx_timeout_completion);
#endif

	bfd_session_release(bfd, TX_TIMER);
	return;
}

void bfd_start_xmit_timer(struct bfd_session *bfd)
{
	int jitter;
	if (IS_DEBUG_BSM) {
		char buf[256];
		blog_info
		    ("bfd_start_xmit_timer:%s, act_tx_intf:%d, mark_deleted:%d",
		     bfd->proto->addr_print(bfd->dst, buf), bfd->act_tx_intv,
		     bfd_session_marked_deleted(bfd));
	}

	/* jitter is 0% -> 25%. if detectmult == 1, max 90% */
	get_random_bytes(&jitter, 4);
	jitter = 75 + jitter % ((bfd->cpkt.detect_mult == 1 ? 15 : 25) + 1);
	bfd->sec_last_sched_jiff = bfd->last_sched_jiff;
	bfd->last_sched_jiff = jiffies;
	if (!bfd_session_marked_deleted(bfd) &&
	    queue_delayed_work(master->tx_ctrl_wq, &bfd->t_tx_work,
			       usecs_to_jiffies(bfd->act_tx_intv) * jitter /
			       100)) {
		bfd_session_grab(bfd, TX_TIMER);
                bfd->tx_cpu = current_cpu;
        }
}

void
bfd_stop_timer(struct bfd_session *bfd, struct delayed_work *work,
	       int ref_type, struct mutex *lock,
	       struct completion *work_completion, bool rearming)
{
#ifdef __KERNEL__
	int ret;
	do {
		ret = 1;
		if (mutex_trylock(lock)) {
#endif
			if (cancel_delayed_work_sync(work))
				bfd_session_release(bfd, ref_type);
#ifdef __KERNEL__
			mutex_unlock(lock);
		} else {
			wait_for_completion(work_completion);
			if (rearming && (ret = cancel_delayed_work(work)))
				bfd_session_release(bfd, ref_type);
		}
	}
	while (!ret);
#endif
}

void bfd_stop_xmit_timer(struct bfd_session *bfd)
{
        bfd->tx_cpu = -1;
#ifdef __KERNEL__
	bfd_stop_timer(bfd, &bfd->t_tx_work, TX_TIMER, &bfd->tx_timeout_lock,
		       &bfd->tx_timeout_completion, true);
#else
	bfd_stop_timer(bfd, &bfd->t_tx_work, TX_TIMER, NULL, NULL, true);
#endif
}

static long bfd_reset_tx_timer_(void *bfd)
{
	bfd_stop_xmit_timer(bfd);
	bfd_start_xmit_timer(bfd);
	return 0;
}


void bfd_reset_tx_timer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
        if (bfd->tx_reset_deferred == current) {
           work_on_cpu(current_cpu, bfd_reset_tx_timer_, bfd);
           return;
        } 
#endif
        bfd_reset_tx_timer_(bfd);
 }

void bfd_detect_timeout(struct work_struct *_work)
{
	struct delayed_work *work =
	    container_of(_work, struct delayed_work, work);
	struct bfd_session *bfd =
	    container_of(work, struct bfd_session, t_rx_expire);

#ifdef __KERNEL__
	INIT_COMPLETION(bfd->rx_expire_completion);
	if (mutex_trylock(&bfd->rx_expire_lock)) {
#endif
		if (!bfd_session_marked_deleted(bfd))
			bfd_bsm_event(bfd, BSM_Timer_Expired);
#ifdef __KERNEL__
		mutex_unlock(&bfd->rx_expire_lock);
	}
	complete_all(&bfd->rx_expire_completion);
#endif
	bfd_session_release(bfd, RX_TIMER);
	return;
}

void bfd_stop_expire_timer(struct bfd_session *bfd)
{
        bfd->rx_expire_cpu = -1;
#ifdef __KERNEL__
	bfd_stop_timer(bfd, &bfd->t_rx_expire, RX_TIMER, &bfd->rx_expire_lock,
		       &bfd->rx_expire_completion, false);
#else
	bfd_stop_timer(bfd, &bfd->t_rx_expire, RX_TIMER, NULL, NULL, false);
#endif
}

static long bfd_reset_expire_timer_(void *arg)
{
        struct bfd_session *bfd = arg;
	bfd_stop_expire_timer(bfd);
	if (!bfd_session_marked_deleted(bfd) &&
	    queue_delayed_work(master->ctrl_expire_wq, &bfd->t_rx_expire,
			       usecs_to_jiffies(bfd->detect_time))) {
		bfd_session_grab(bfd, RX_TIMER);
                bfd->rx_expire_cpu = current_cpu;
        }
        return 0;
}

void bfd_reset_expire_timer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
        if (bfd->rx_reset_deferred == current) {
           work_on_cpu(current_cpu, bfd_reset_expire_timer_, bfd);
           return;
        } 
#endif
        bfd_reset_expire_timer_(bfd);
 }


static int
bfd_change_interval_time_(struct bfd_session *bfd, u_int32_t tx,
			  u_int32_t rx, bool may_sleep)
{
	u_int32_t async_rx = master->slow_timer;

	if (!GET_ECHO_PRIV_FIELD(bfd, echo_start)) {
		async_rx = rx;
	}
	if (IS_DEBUG_BSM)
		blog_info("Try to change intv TX=%d(usec), RX=%d(usec)", tx,
			  async_rx);

	/* Section 6.7.3 Description */
	if (bfd->cpkt.state == BSM_Up && tx > ntohl(bfd->cpkt.des_min_tx_intv)) {
		bfd->cpkt.poll = 1;
		if (IS_DEBUG_BSM)
			blog_info
			    ("BFD Poll Sequence is started(tx_intv change)");
	} else {
		u_int32_t last_act_tx_intv = bfd->act_tx_intv;
		bfd->act_tx_intv = tx < ntohl(bfd->last_rcv_req_rx) ?
		    ntohl(bfd->last_rcv_req_rx) : tx;
		if (last_act_tx_intv != bfd->act_tx_intv) {
			if (IS_DEBUG_BSM)
				blog_info
				    ("BFD resetting tx stats(tx_intv change)");
			bfd_reset_tx_stats(bfd);
		}
#ifdef __KERNEL__
		if (may_sleep)
                   bfd_reset_tx_timer_q(bfd);
		else 
#endif
		bfd_reset_tx_timer(bfd);

		if (IS_DEBUG_BSM)
			blog_info("New TX %d(usec)(tx_intv change)",
				  bfd->act_tx_intv);
	}

	if (bfd->cpkt.state == BSM_Up
	    && async_rx < ntohl(bfd->cpkt.req_min_rx_intv)) {
		bfd->cpkt.poll = 1;
		if (IS_DEBUG_BSM)
			blog_info
			    ("BFD Poll Sequence is started(rx_intv change).");
	} else {
		u_int32_t last_act_rx_intv = bfd->act_rx_intv;
		bfd->act_rx_intv = async_rx;
		if (last_act_rx_intv != bfd->act_rx_intv) {
			if (IS_DEBUG_BSM)
				blog_info
				    ("BFD resetting rx stats(rx_intv change)");
			bfd_reset_rx_stats(bfd);
		}
		if (IS_DEBUG_BSM)
			blog_info("New RX %d(usec)(rx_intv change)", async_rx);
	}

	bfd->cpkt.des_min_tx_intv = htonl(tx);
	bfd->cpkt.req_min_rx_intv = htonl(async_rx);
#ifdef __KERNEL__
	// cpkt.req_min_echo_rx_intv remains zero in the case of
	// kbfd.proc - the echo function is effectively disabled
	// between 2 duts if at least one of them is a namespace
	// dut.
	bfd->cpkt.req_min_echo_rx_intv = htonl(rx);
#endif
	if (bfd->bif) {
		bfd->cpkt.detect_mult = bfd_interface_v_mult(bfd->bif);
	} else if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION) {
		bfd->cpkt.detect_mult = VXLAN_TUNNEL_PRIV(bfd)->mult;
        } else {
		char buf[256];
		blog_err("Trying to change detect_mult of Session %s/%d without bif",
			 bfd->proto->addr_print(bfd->dst, buf),
			 ntohl(bfd->cpkt.my_disc));
                return 1;
        }

#ifdef __KERNEL__
	SET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv,
			    GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv));
	if (GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv)
	    && (tx > GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv)))
		SET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv, tx);
	SET_ECHO_PRIV_FIELD(bfd, echo_detect_time,
			    bfd->cpkt.detect_mult * GET_ECHO_PRIV_FIELD(bfd,
									act_echo_tx_intv));
	if (GET_ECHO_PRIV_FIELD(bfd, echo_start)) {
		if (may_sleep) {
			bfd_reset_echo_tx_timer_q(bfd);
			bfd_reset_echo_expire_timer_q(bfd);
		} else {
			bfd_reset_echo_tx_timer(bfd);
			bfd_reset_echo_expire_timer(bfd);
		}
	}
#endif

	if (IS_DEBUG_BSM)
		blog_info("Change intv TX=%d(usec), RX=%d(usec)", tx, rx);
	return 0;
}

int
bfd_change_interval_time(struct bfd_session *bfd, u_int32_t tx, u_int32_t rx)
{
	return bfd_change_interval_time_(bfd, tx, rx, false);
}

void
bfd_change_interval_time_q(struct bfd_session *bfd, u_int32_t tx, u_int32_t rx)
{
	bfd_change_interval_time_(bfd, tx, rx, true);
}

void bfd_reset_tx_stats(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("Reset tx intv statistics");

	bfd->tx_last_jiff = 0;
	bfd->tx_min = 0;
	bfd->tx_max = 0;
	bfd->tx_sum = 0;
	bfd->tx_n = 0;
}

void bfd_reset_rx_stats(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("Reset rx intv statistics");

	bfd->rx_last_jiff = 0;
	bfd->rx_min = 0;
	bfd->rx_max = 0;
	bfd->rx_sum = 0;
	bfd->rx_n = 0;
}

int bsm_ignore(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("BSM: ignored.");

	return 0;
}

int bsm_toggle_admin_down(struct bfd_session *bfd)
{
	if (bfd->cpkt.state != BSM_AdminDown) {
		/* goes to administratively down */
		bfd->cpkt.diag = BFD_DIAG_ADMIN_DOWN;
		bfd_stop_xmit_timer(bfd);
		bfd_stop_expire_timer(bfd);
	} else {
		/* wake up session */
		bfd->cpkt.diag = BFD_DIAG_NO_DIAG;
		bfd_bsm_event(bfd, BSM_Start);
	}

	return 0;
}

int bsm_start(struct bfd_session *bfd)
{
	bfd_start_xmit_timer(bfd);
	return 0;
}

int bsm_rcvd_down(struct bfd_session *bfd)
{
	if (bfd->cpkt.state == BSM_Up) {
		bfd->cpkt.diag = BFD_DIAG_NBR_SESSION_DOWN;
	}
	return 0;
}

int bsm_rcvd_init(struct bfd_session *bfd)
{
	return 0;
}

int bsm_rcvd_up(struct bfd_session *bfd)
{
	return 0;
}

int bsm_timer_expire(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("BSM:Timeout. to = %uusec", bfd->detect_time);
	bfd->cpkt.diag = BFD_DIAG_CTRL_TIME_EXPIRED;
	if (bfd->act_tx_intv != 0) {
		bfd->prev_tx_intv = bfd->act_tx_intv;
	}
	if (bfd->act_rx_intv != 0) {
		bfd->prev_rx_intv = bfd->act_rx_intv;
	}

	/* reset timer */
	bfd->cpkt.des_min_tx_intv = htonl(BFD_MIN_TX_INTERVAL_INIT);
	bfd->cpkt.req_min_rx_intv = htonl(BFD_MIN_RX_INTERVAL_INIT);
	return 0;
}

int bsm_echo_timer_expire(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("BSM:Timeout. to = %uusec",
			  GET_ECHO_PRIV_FIELD(bfd, echo_detect_time));
	bfd->cpkt.diag = BFD_DIAG_ECHO_FAILED;

	/* reset timer */
	bfd->cpkt.des_min_tx_intv = htonl(BFD_MIN_TX_INTERVAL_INIT);
	bfd->cpkt.req_min_rx_intv = htonl(BFD_MIN_RX_INTERVAL_INIT);
	return 0;
}

struct {
	int (*func) (struct bfd_session *);
	int next_state;
} BSM[BFD_BSM_STATE_MAX][BFD_BSM_EVENT_MAX] = {
	{
		/* AdminDown */
		{
		bsm_ignore, BSM_AdminDown},	/* Start */
		{
		bsm_ignore, BSM_AdminDown},	/* Received_Down */
		{
		bsm_ignore, BSM_AdminDown},	/* Received_Init */
		{
		bsm_ignore, BSM_AdminDown},	/* Received_Up */
		{
		bsm_ignore, BSM_AdminDown},	/* TimerExpired */
		{
		bsm_ignore, BSM_AdminDown},	/* EchoTimerExpired */
		{
		bsm_toggle_admin_down, BSM_Down},	/* Toggle_AdminDown */
	}, {
		/* Down */
		{
		bsm_start, BSM_Down},	/* Start */
		{
		bsm_rcvd_down, BSM_Init},	/* Received_Down */
		{
		bsm_rcvd_init, BSM_Up},	/* Received_Init */
		{
		bsm_ignore, BSM_Down},	/* Received_Up */
		{
		bsm_ignore, BSM_Down},	/* TimerExpired */
		{
		bsm_ignore, BSM_Down},	/* EchoTimerExpired */
		{
		bsm_toggle_admin_down, BSM_AdminDown},	/* Toggle_AdminDown */
	}, {
		/* Init */
		{
		bsm_ignore, BSM_Init},	/* Start */
		{
		bsm_ignore, BSM_Init},	/* Received_Down */
		{
		bsm_rcvd_down, BSM_Up},	/* Received_Init */
		{
		bsm_rcvd_up, BSM_Up},	/* Received_Up */
		{
		bsm_timer_expire, BSM_Down},	/* TimerExpired */
		{
		bsm_ignore, BSM_Init},	/* EchoTimerExpired */
		{
		bsm_toggle_admin_down, BSM_AdminDown},	/* Toggle_AdminDown */
	}, {
		/* Up */
		{
		bsm_ignore, BSM_Up},	/* Start */
		{
		bsm_rcvd_down, BSM_Down},	/* Received_Down */
		{
		bsm_ignore, BSM_Up},	/* Received_Init */
		{
		bsm_ignore, BSM_Up},	/* Received_Up */
		{
		bsm_timer_expire, BSM_Down},	/* TimerExpired */
		{
		bsm_echo_timer_expire, BSM_Down},	/* EchoTimerExpired */
		{
		bsm_toggle_admin_down, BSM_AdminDown},	/* Toggle_AdminDown */
},};

bool bfd_start_echo(struct bfd_session *bfd)
{
	if (GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv)
	    && bfd->feat->vect->enabled(bfd)
            && bfd->cpkt.state == BSM_Up) {
                SET_ECHO_PRIV_FIELD(bfd, echo_start, true);
		return true;
	}
	return false;
}

bool bfd_stop_echo(struct bfd_session * bfd)
{
	if (GET_ECHO_PRIV_FIELD(bfd, echo_start)) {
           SET_ECHO_PRIV_FIELD(bfd, echo_start, false);
           return true;
	}
	return false;
}

int bfd_bsm_event(struct bfd_session *bfd, int bsm_event)
{
	int next_state, old_state;
	char buf[256];
	struct bfd_session *lag_bfd;
	int lag_old_state;

	old_state = bfd->cpkt.state;
	next_state = (*(BSM[bfd->cpkt.state][bsm_event].func)) (bfd);

	if (!next_state)
		bfd->cpkt.state = BSM[bfd->cpkt.state][bsm_event].next_state;
	else
		bfd->cpkt.state = next_state;

	if (IS_DEBUG_BSM)
		blog_info("BSM:Event (%s)", bfd_event_string[bsm_event]);

	if (bfd->cpkt.state != old_state) {
		if (bfd->cpkt.state == BSM_Up || old_state == BSM_Up) {
			if (IS_DEBUG_BSM)
				blog_info("%s Sta Chg %s=>%s(%s)",
					  bfd->proto->addr_print(bfd->dst, buf),
					  bfd_state_string[old_state],
					  bfd_state_string[bfd->cpkt.state],
					  bfd_event_string[bsm_event]);
			/* Mark session dirty so BFD_GETCHANGE response
			   can pick it up */
			bfd->dirty = 1;

			/* notify netlink user */
			bfd_nl_send(bfd);
			/* For micro session, may also need to send notification
			 * for the corresponding lag session */
			if (bfd->session_type == BFD_MICRO_SESSION) {
				/* search lag session first */
				lag_bfd = bfd->lag_session;
				if (lag_bfd) {
					lag_old_state = lag_bfd->cpkt.state;
					lag_bfd->cpkt.state =
					    bfd_lag_session_state(lag_bfd);
					if ((lag_old_state !=
					     lag_bfd->cpkt.state)
					    && ((lag_old_state == BSM_Up)
						|| (lag_bfd->cpkt.state ==
						    BSM_Up))) {
						lag_bfd->dirty = 1;
						bfd_nl_send(lag_bfd);
					}
				}
			}
		} else if (IS_DEBUG_BSM) {
			blog_info("%s Sta Chg %s=>%s(%s)",
				  bfd->proto->addr_print(bfd->dst, buf),
				  bfd_state_string[old_state],
				  bfd_state_string[bfd->cpkt.state],
				  bfd_event_string[bsm_event]);
		}

		/* if state changed from !Up to Up, Set Tx/Rx Interval 
		   and start echo packet generation, if the echo function 
		   is enabled */
		if (old_state != BSM_Up && bfd->cpkt.state == BSM_Up) {
#ifdef __KERNEL__
			if (bfd_start_echo(bfd)) {
				bfd_start_echo_xmit_timer(bfd);
				bfd_start_echo_expire_timer(bfd);
			}
#endif
			if (bfd->bif) {
				if (bfd_change_interval_time
				    (bfd, bfd_interface_v_mintx(bfd->bif),
				     bfd_interface_v_minrx(bfd->bif))) {
					return 0;
				}
	                } else if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION) {
				if (bfd_change_interval_time
				    (bfd, VXLAN_TUNNEL_PRIV(bfd)->mintx,
				     VXLAN_TUNNEL_PRIV(bfd)->minrx)) {
					return 0;
				}
			} else {
		                char buf[256];
		                blog_err("Session %s/%d without bif",
                                         bfd->proto->addr_print(bfd->dst, buf),
                                         ntohl(bfd->cpkt.my_disc));
                                return 0;
			}

			/* set uptime */
			bfd->last_up = get_sys_uptime();
			bfd->up_cnt++;
			bfd->pkt_in_up = bfd->pkt_in;
			bfd->pkt_out_up = bfd->pkt_out;
			bfd->hist_logged = false;
			bfd->lateness[0] = 0;
			bfd->lateness[1] = 0;
			bfd->lateness[2] = 0;
			bfd->lateness[3] = 0;
		}

		/* Reset Tx Timer */
		if (bfd->cpkt.state != BSM_Up) {

#ifdef __KERNEL__
			if (bfd_stop_echo(bfd)) {
				bfd_stop_echo_xmit_timer(bfd);
				if (bsm_event != BSM_Echo_Timer_Expired)
					bfd_stop_echo_expire_timer(bfd);
			}
#endif
			bfd_change_interval_time(bfd,
                                                 BFD_MIN_TX_INTERVAL_INIT,
                                                 BFD_MIN_RX_INTERVAL_INIT);

			/* Cancel Expire timer */
			/*
			   If the event is BSM_Timer_Expired we're 
			   currently running the delayed work that we
			   cancel in bfd_stop_expire_timer(), so only
			   invoke it if the event is not BSM_Timer_Expired.
			 */
			if (bsm_event != BSM_Timer_Expired)
				bfd_stop_expire_timer(bfd);

		}
		/* set downtime */
		if (bfd->cpkt.state == BSM_Down) {
			bfd->last_down = get_sys_uptime();
			bfd->last_diag = bfd->cpkt.diag;
			bfd->cpkt.your_disc = 0;
			/* update lateness */
			bfd_update_tx_sched_delay(bfd);
			bfd_log_sess_hist(bfd, false);
		}

		/* Reset Diagnostic Code */
		if (old_state == BSM_Down) {
			bfd->cpkt.diag = BFD_DIAG_NO_DIAG;
		}
	}

	return 0;
}

#ifdef __KERNEL__
#define PEER_BUF_SIZE 500
static int
proc_session_read_detail(char *page, char **start, off_t off,
			 int count, int *eof, void *data, int tbl_start)
{
	size_t page_off = 0;
	int i = 0;
	char addr_buf[128];
	struct bfd_session *bfd;
	size_t entry_cnt = 0;
	bool lag;
	int lag_state;
        u_int32_t mult = 0;

	spin_lock(&tbl_lock);
	for (i = tbl_start; i < (tbl_start + BFD_SESSION_HASH_SIZE); i++) {
		bfd = master->session_tbl[i];
		while (bfd) {
			if (entry_cnt < (off)) {
				entry_cnt++;
				bfd = bfd->session_next;
				continue;
			}

			if (count < (page_off + PEER_BUF_SIZE)) {
				*eof = 0;
				goto done;
			}

			/* compute the aggregated result for lag-bfd */
			if ((lag = (bfd->session_type == BFD_LAG_SESSION))) {
				lag_state = bfd_lag_session_state(bfd);
			}

			page_off +=
			    sprintf(page + page_off,
				    "\nPAddr %s Intf %s State%s",
				    bfd->proto->addr_print(bfd->dst, addr_buf),
				    bfd_interface_name(bfd->bif),
				    lag ? bfd_state_string[lag_state] :
				    bfd_state_string[bfd->cpkt.state]);
			page_off +=
			    sprintf(page + page_off, "LAddr%sLD%dRD%d",
				    bfd->proto->addr_print(bfd->src, addr_buf),
				    ntohl(bfd->cpkt.my_disc),
				    ntohl(bfd->cpkt.your_disc));
			page_off +=
			    sprintf(page + page_off, "LastUp%u", bfd->last_up);
			page_off +=
			    sprintf(page + page_off, "LastDown%u",
				    bfd->last_down);
			page_off +=
			    sprintf(page + page_off, "LastDiag%u",
				    bfd->last_diag);
	                if (bfd->bif) {
		           mult = bfd_interface_v_mult(bfd->bif);
                        } else if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION) {
                           mult = VXLAN_TUNNEL_PRIV(bfd)->mult;
                        } else {
	                   if (IS_DEBUG_BSM) {
                              char buf[256];
		              blog_info("Trying to report detect_mult of Session %s/%d without bif",
                                    bfd->proto->addr_print(bfd->dst, buf),
                                    ntohl(bfd->cpkt.my_disc));
                           }
                        }
			page_off +=
			    sprintf(page + page_off, "TxInt%dRxInt%dMult%d",
				    bfd->act_tx_intv / 1000,
				    bfd->act_rx_intv / 1000,
				    mult);
			page_off +=
			    sprintf(page + page_off, "RecRxInt%dRecMult%d",
				    bfd->peer_rx_intv / 1000, bfd->peer_mult);
			page_off +=
			    sprintf(page + page_off, "RxCount%lldTxCount%lld",
				    bfd->pkt_in, bfd->pkt_out);
			page_off +=
			    sprintf(page + page_off, "Detect%u",
				    bfd->detect_time / 1000);
			/* print rx/tx statistics */
			page_off +=
			    sprintf(page + page_off, "RxMin%uRxMax%u",
				    bfd->rx_min, bfd->rx_max);
			if (bfd->rx_n == 0)
				page_off += sprintf(page + page_off, "RxAvg0");
			else
				page_off +=
				    sprintf(page + page_off, "RxAvg%llu",
					    (bfd->rx_sum / bfd->rx_n));
			if (bfd->rx_last_jiff == 0)
				page_off += sprintf(page + page_off, "RxLast0");
			else
				page_off += sprintf(page + page_off, "RxLast%u",
						    jiffies_to_msecs(jiffies -
								     bfd->
								     rx_last_jiff));
			page_off +=
			    sprintf(page + page_off, "TxMin%uTxMax%u",
				    bfd->tx_min, bfd->tx_max);
			if (bfd->tx_n == 0)
				page_off += sprintf(page + page_off, "TxAvg0");
			else
				page_off +=
				    sprintf(page + page_off, "TxAvg%llu",
					    (bfd->tx_sum / bfd->tx_n));
			if (bfd->tx_last_jiff == 0)
				page_off += sprintf(page + page_off, "TxLast0");
			else
				page_off += sprintf(page + page_off, "TxLast%u",
						    jiffies_to_msecs(jiffies -
								     bfd->
								     tx_last_jiff));
			/* print last recv'ed packet info */
			page_off +=
			    sprintf(page + page_off, "RecVer%dRecDiag%d",
				    bfd->rpkt.version, bfd->rpkt.diag);
			page_off +=
			    sprintf(page + page_off, "RecState%sRecDemand%d",
				    bfd_state_string[bfd->rpkt.state],
				    bfd->rpkt.demand);
			page_off +=
			    sprintf(page + page_off, "RecPoll%dRecFinal%d",
				    bfd->rpkt.poll, bfd->rpkt.final);
			page_off += sprintf(page + page_off, "RecLen%d",
					    /* RecMult is already captured above */
					    bfd->rpkt.length);
			page_off += sprintf(page + page_off, "RecLD%uRecRD%u",
					    ntohl(bfd->rpkt.my_disc),
					    ntohl(bfd->rpkt.your_disc));
			page_off +=
			    sprintf(page + page_off, "RecTxInt%uRecEchoInt%d",
				    /* RecRxInt is already captured above */
				    bfd->peer_tx_intv,
				    ntohl(bfd->rpkt.req_min_echo_rx_intv));
			page_off +=
			    sprintf(page + page_off, "SchedD%d,%d,%d,%d",
				    bfd->lateness[0], bfd->lateness[1],
				    bfd->lateness[2], bfd->lateness[3]);
			page_off +=
			    sprintf(page + page_off, "Echo%1d:%u",
				    GET_ECHO_PRIV_FIELD(bfd, echo_start),
				    GET_ECHO_PRIV_FIELD(bfd,
							act_echo_tx_intv) /
				    1000);
			page_off +=
			    sprintf(page + page_off, "Type%1d\n",
				    bfd->session_type);
			entry_cnt++;

			bfd = bfd->session_next;
		}
	}

	*eof = 1;

 done:
	spin_unlock(&tbl_lock);
	*start = (char *)(entry_cnt - off);
	return (page_off);
}

static int
proc_session_read_detail_v4(char *page, char **start, off_t off,
			    int count, int *eof, void *data)
{
	return proc_session_read_detail(page, start, off, count, eof, data, 0);
}

static int
proc_session_read_detail_v6(char *page, char **start, off_t off,
			    int count, int *eof, void *data)
{
	return proc_session_read_detail(page, start, off, count, eof, data,
					BFD_SESSION_HASH_SIZE);
}

#define LINE_SIZE 100

#ifdef KBFD_REFCNT_DEBUG

static int
proc_session_read_deleted(char *page, char **start, off_t off,
			  int count, int *eof, void *data)
{
	int len = 0;
	size_t j = 0;
	char buf[128];
	struct bfd_session *bfd;

	if (off == 0) {
		/* Header */
		len +=
		    sprintf(page + len,
			    "Number of deleted sessions: %d\n",
			    deleted_sessions_cnt);
		len +=
		    sprintf(page + len,
			    "DstAddr         MyDisc YoDisc If     RefCnt \n");
	}

	spin_lock(&del_lock);

	bfd = deleted_sessions;

	while (bfd) {
		if ((len + LINE_SIZE) > count) {
			*eof = 0;
			goto done;
		}
		if (j >= off) {
			int i;

			len += sprintf(page + len,
				       "%15s %6u %6u %4s(%1d) %10u",
				       bfd->proto->addr_print(bfd->dst, buf),
				       ntohl(bfd->cpkt.my_disc),
				       ntohl(bfd->cpkt.your_disc),
				       bfd_interface_name(bfd->bif),
				       atomic_read(&bfd->refcnt));
			len += sprintf(page + len, "[");
			for (i = SESSION_FIND; i < MAX_REF_TYPES; i++)
				len += sprintf(page + len, " %u",
					       atomic_read(&bfd->refcnt_pertype
							   [i]));
			len += sprintf(page + len, " ]\n");

		}
		j++;
		bfd = bfd->nbr_next;
	}

	*eof = 1;

 done:
	spin_unlock(&del_lock);
	*start = (char *)(j - off);
	return len;
}
#endif

static int
proc_session_read(char *page, char **start, off_t off,
		  int count, int *eof, void *data, int tbl_start)
{
	int len = 0;
	size_t i = 0, j = 0;
	char buf[128];
	bool lag;
	int lag_state;

	if (off == 0) {
		/* Header */
		len +=
		    sprintf(page + len,
			    "DstAddr         MyDisc YoDisc If             LUp      LDown LDiag State \n");
	}

	spin_lock(&tbl_lock);
	for (i = tbl_start; i < (tbl_start + BFD_SESSION_HASH_SIZE); i++) {
		struct bfd_session *bfd;

		bfd = master->session_tbl[i];

		while (bfd) {
			if ((len + LINE_SIZE) > count) {
				*eof = 0;
				goto done;
			}
			if (j >= off) {
				if ((lag =
				     (bfd->session_type == BFD_LAG_SESSION))) {
					lag_state = bfd_lag_session_state(bfd);
				}
				len += sprintf(page + len,
					       "%15s %6u %6u %4s(%1d) %10u %10u %5d %s\n",
					       bfd->proto->addr_print(bfd->dst,
								      buf),
					       ntohl(bfd->cpkt.my_disc),
					       ntohl(bfd->cpkt.your_disc),
					       bfd_interface_name(bfd->bif),
					       bfd_interface_index(bfd->bif),
					       bfd->last_up,
					       bfd->last_down, bfd->last_diag,
					       lag ? bfd_state_string[lag_state]
					       : bfd_state_string[bfd->cpkt.
								  state]);
			}
			j++;
			bfd = bfd->session_next;
		}
	}

	*eof = 1;

 done:
	spin_unlock(&tbl_lock);
	*start = (char *)(j - off);
	return len;
}

static int
proc_session_read_v4(char *page, char **start, off_t off,
		     int count, int *eof, void *data)
{
	return proc_session_read(page, start, off, count, eof, data, 0);
}

static int
proc_session_read_v6(char *page, char **start, off_t off,
		     int count, int *eof, void *data)
{
	return proc_session_read(page, start, off, count, eof, data,
				 BFD_SESSION_HASH_SIZE);
}

// Disable writes to /proc/kbfd/session
#ifdef BFD_SESSION_WRITE

#define MK_IP(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)

static int
proc_session_write(struct file *file, const char __user * buffer,
		   unsigned long count, void *data)
{
	char c, sw;
	unsigned int d1, d2, d3, d4;
	int ifindex;
	int rc;
	struct sockaddr_in dst;
	extern struct bfd_proto v4v6_proto;

	rc = get_user(c, buffer);
	if (rc)
		return rc;

	/* FIXME */
	memset(&dst, 0, sizeof(struct sockaddr_in));

	if (sscanf
	    (buffer, "%c %u.%u.%u.%u %u\n", &sw, &d1, &d2, &d3, &d4,
	     &ifindex) == 6) {
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = htonl(MK_IP(d1, d2, d3, d4));
		switch (sw) {
		case '+':
			bfd_normal_session_add(&v4v6_proto,
					       (struct sockaddr *)&dst,
					       ifindex);
			break;
		case '-':
			bfd_session_delete(&v4v6_proto, (struct sockaddr *)&dst,
					   ifindex);
			break;
		default:
			break;
		}
	} else {
		blog_err("input format is invalid...:");
	}

	return count;
}
#endif
#endif				// __KERNEL__

int bfd_session_init(void)
{
	/* initialize hash */
	memset(master->session_tbl, 0,
	       sizeof(struct bfd_session *) * 2 * BFD_SESSION_HASH_SIZE);
	// initialize the spin lock
	spin_lock_init(&tbl_lock);

	/* Workqueue for send process */
	master->tx_ctrl_wq =
	    alloc_workqueue("kbfd_tx", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!master->tx_ctrl_wq) {
		blog_err("failed create ctrl tx workqueue");
	}

	/* Workqueue for receive expire */
	master->ctrl_expire_wq =
	    alloc_workqueue("kbfd_rx_expire", WQ_MEM_RECLAIM, 0);
	if (!master->ctrl_expire_wq) {
		blog_err("failed create ctrl expire workqueue");
	}

	/* Workqueue for tx reset */
	master->tx_reset_wq =
	    alloc_workqueue("kbfd_tx_reset", WQ_MEM_RECLAIM, 0);
	if (!master->tx_reset_wq) {
		blog_err("failed create tx reset workqueue");
	}

	/* Workqueue for rx reset */
	master->rx_reset_wq =
	    alloc_workqueue("kbfd_rx_reset", WQ_MEM_RECLAIM, 0);
	if (!master->rx_reset_wq) {
		blog_err("failed create rx reset workqueue");
	}

	/* proc fs */
	kbfd_root_dir = proc_mkdir("kbfd", NULL);
	if (!kbfd_root_dir) {
		blog_err("kbfd init fail(proc)...:");
		return 0;
	}
#ifdef __KERNEL__
	sessionv4_proc =
	    create_proc_entry("session_v4", S_IFREG | S_IRWXUGO, kbfd_root_dir);
	if (!sessionv4_proc) {
		blog_err("kbfd init fail: Could not create session_v4 entry");
		return 0;
	}
	sessionv4_proc->read_proc = proc_session_read_v4;

	sessionv6_proc =
	    create_proc_entry("session_v6", S_IFREG | S_IRWXUGO, kbfd_root_dir);
	if (!sessionv6_proc) {
		blog_err("kbfd init fail: Could not create session_v6 entry");
		return 0;
	}

	sessionv6_proc->read_proc = proc_session_read_v6;
#ifdef BFD_SESSION_WRITE
	session_proc->write_proc = proc_session_write;
#endif
	sessionv4_proc_detail =
	    create_proc_entry("session_detail_v4", S_IFREG | S_IRWXUGO,
			      kbfd_root_dir);
	if (!sessionv4_proc_detail) {
		blog_err
		    ("kbfd init fail: Could not create session_detail_v4 entry");
		return 0;
	}

	sessionv4_proc_detail->read_proc = proc_session_read_detail_v4;
	sessionv4_proc_detail->write_proc = NULL;

	sessionv6_proc_detail =
	    create_proc_entry("session_detail_v6", S_IFREG | S_IRWXUGO,
			      kbfd_root_dir);
	if (!sessionv6_proc_detail) {
		blog_err
		    ("kbfd init fail: Could not create session_detail_v6 entry");
		return 0;
	}

	sessionv6_proc_detail->read_proc = proc_session_read_detail_v6;
	sessionv6_proc_detail->write_proc = NULL;

#ifdef KBFD_REFCNT_DEBUG
	session_del_proc =
	    create_proc_entry("session_deleted", S_IFREG | S_IRWXUGO,
			      kbfd_root_dir);
	if (!session_del_proc) {
		blog_err
		    ("kbfd init fail: Could not create session_deleted entry");
		return 0;
	}

	session_del_proc->read_proc = proc_session_read_deleted;
	session_del_proc->write_proc = NULL;
#endif

#endif
	return 0;
}

int bfd_session_finish(void)
{

	if (kbfd_root_dir) {
		if (sessionv4_proc)
			remove_proc_entry("session_v4", kbfd_root_dir);
		if (sessionv4_proc_detail)
			remove_proc_entry("session_detail_v4", kbfd_root_dir);
		if (sessionv6_proc)
			remove_proc_entry("session_v6", kbfd_root_dir);
		if (sessionv6_proc_detail)
			remove_proc_entry("session_detail_v6", kbfd_root_dir);
		remove_proc_entry("kbfd", NULL);
	}

	bfd_session_delete_all();

	if (master->ctrl_expire_wq) {
		destroy_workqueue(master->ctrl_expire_wq);
		master->ctrl_expire_wq = NULL;
	}

	if (master->tx_ctrl_wq) {
		destroy_workqueue(master->tx_ctrl_wq);
		master->tx_ctrl_wq = NULL;
	}

	if (master->tx_reset_wq) {
		destroy_workqueue(master->tx_reset_wq);
		master->tx_reset_wq = NULL;
	}
	return 0;
}
