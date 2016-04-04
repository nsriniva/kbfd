/* 
 *  BFD Interface Management
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
#include <linux/netdevice.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_interface.h"
#include "kbfd_log.h"
#include "kbfd_session.h"
#include "kbfd.h"
#include "kbfd_netlink.h"

extern int BFD_DETECT_MULT_DEFAULT;
extern int BFD_MIN_TX_INTERVAL_DEFAULT;
extern int BFD_MIN_RX_INTERVAL_DEFAULT;

static struct bfd_interface *biflist = NULL;
static DEFINE_SPINLOCK(bif_lock);
/* FIXME */
extern struct bfd_proto v4v6_proto;

#ifdef __KERNEL__
inline static void validate_ifname(struct bfd_interface *bif)
{
	struct net_device *dev;

	dev = dev_get_by_index(&init_net, bif->ifindex);
	if (dev) {
		if (bif->name && strcmp(bif->name, dev->name)) {
			kfree(bif->name);
			bif->name = NULL;
		}
		if (NULL == bif->name)
			bif->name = kstrdup(dev->name, GFP_KERNEL);
		dev_put(dev);
	}
}
#endif

inline static struct bfd_interface *bfd_interface_new(int ifindex)
{
	struct bfd_interface *bif;

	bif = kzalloc(sizeof(struct bfd_interface), GFP_KERNEL);
	if (bif) {
		bif->ifindex = ifindex;

		bif->v_mintx = BFD_MIN_TX_INTERVAL_DEFAULT;
		bif->v_minrx = BFD_MIN_RX_INTERVAL_DEFAULT;
		bif->v_mult = BFD_DETECT_MULT_DEFAULT;
		bif->is_default = true;

#ifdef __KERNEL__
		validate_ifname(bif);
#else
		memset(bif->name, 0, sizeof(bif->name));
		if_indextoname(ifindex, bif->name);
#endif
	}
	return bif;
}

struct bfd_interface *bfd_interface_get(int ifindex)
{
	struct bfd_interface *bif = biflist;

	/* lookup same interface */
	rcu_read_lock();
	while (bif) {
		if (bif->ifindex == ifindex)
			break;
		bif = bif->next;
	}
	rcu_read_unlock();

	/* found */
	if (bif) {
#ifdef __KERNEL__
		validate_ifname(bif);
#endif
		return bif;
	}

	/* then alloc new interface */
	bif = bfd_interface_new(ifindex);
	if (!bif)
		return NULL;

	spin_lock(&bif_lock);
	bif->next = biflist;
	biflist = bif;
	spin_unlock(&bif_lock);

	return bif;
}

void bfd_interface_free(struct bfd_interface *bif)
{
	synchronize_rcu();
	if (bif) {
#ifdef __KERNEL__
		if (bif->name) {
			kfree(bif->name);
		}
#endif
		kfree(bif);
	}
	return;
}

int bfd_interface_reset(int ifindex)
{
	int err = 0;
	struct bfd_interface *bif = bfd_interface_get(ifindex);

	if (!bif)
		goto fail;

	bif->v_mintx = BFD_MIN_TX_INTERVAL_DEFAULT;
	bif->v_minrx = BFD_MIN_RX_INTERVAL_DEFAULT;
	bif->v_mult = BFD_DETECT_MULT_DEFAULT;
	bif->is_default = true;
        bfd_interface_change_timer(bif);

	goto done;

 fail:
	err = EINVAL;
 done:
	return err;
}

void
bfd_interface_set_defaults(u_int32_t mintx, u_int32_t minrx, u_int32_t mult)
{
	struct bfd_interface *bif = biflist;
	// override global default with values in link
	BFD_MIN_TX_INTERVAL_DEFAULT = mintx;
	BFD_MIN_RX_INTERVAL_DEFAULT = minrx;
	BFD_DETECT_MULT_DEFAULT = mult;
	rcu_read_lock();
	while (bif) {
		if (bif->is_default) {
			bif->v_mintx = BFD_MIN_TX_INTERVAL_DEFAULT;
			bif->v_minrx = BFD_MIN_RX_INTERVAL_DEFAULT;
			bif->v_mult = BFD_DETECT_MULT_DEFAULT;
			bfd_interface_change_timer(bif);
		}
		bif = bif->next;
	}
	rcu_read_unlock();
	return;
}

static void bfd_toggle_echo(struct bfd_session *bfd)
{
	if (bfd->session_type != BFD_NORMAL_SESSION)
		return;

	if (bfd_interface_echo_on(bfd->bif)) {
		bfd_start_echo(bfd);
	} else {
		bfd_stop_echo(bfd);
	}
}

static void
bfd_interface_change_timer_(struct bfd_interface *bif, bool toggle_echo)
{
	struct bfd_session *bfd = NULL;
	int i;

	rcu_read_lock();
	for (i = 0; i < 2 * BFD_SESSION_HASH_SIZE; i++) {
		bfd = v4v6_proto.nbr_tbl[i];
		while (bfd) {
			if ((bfd->bif == bif) && (bfd->cpkt.state == BSM_Up)) {
				bfd_session_grab(bfd, SESSION_TIMERS_CHANGE);
				if (toggle_echo)
					bfd_toggle_echo(bfd);
				bfd_change_interval_time_q(bfd, bif->v_mintx,
                                                      bif->v_minrx);
				bfd_session_release(bfd, SESSION_TIMERS_CHANGE);
			}
			bfd = bfd->nbr_next;
		}
	}
	rcu_read_unlock();

	return;
}

void bfd_interface_change_timer(struct bfd_interface *bif)
{
	bfd_interface_change_timer_(bif, false);
}

void bfd_interface_change_timer_and_toggle_echo(struct bfd_interface *bif)
{
	bfd_interface_change_timer_(bif, true);
}

void bfd_sessions_change_slow_timer(void)
{
	struct bfd_session *bfd;
	int i = 0;

	rcu_read_lock();
	for (i = 0; i < 2 * BFD_SESSION_HASH_SIZE; i++) {
		bfd = v4v6_proto.nbr_tbl[i];
		while (bfd) {
			if (GET_ECHO_PRIV_FIELD(bfd, echo_start)) {
				bfd_session_grab(bfd, SESSION_TIMERS_CHANGE);
				bfd_change_interval_time_q(bfd,
						bfd_interface_v_mintx(bfd->bif),
					        bfd_interface_v_minrx(bfd->bif));
				bfd_session_release(bfd, SESSION_TIMERS_CHANGE);
			}
			bfd = bfd->nbr_next;
		}
	}
	rcu_read_unlock();
}

inline 
void bfd_interface_init()
{
#ifndef __KERNEL__
	pthread_spin_init(&bif_lock, PTHREAD_PROCESS_PRIVATE);
#endif
}
