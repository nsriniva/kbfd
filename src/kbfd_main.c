/* 
 *  BFD Main routine
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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_netlink.h"
#include "kbfd_v4v6.h"
#include "kbfd_log.h"
#include "kbfd.h"
#include "kbfd_interface.h"

struct bfd_master *master = NULL;

int BFD_DETECT_MULT_DEFAULT = 5;
int BFD_MIN_TX_INTERVAL_DEFAULT = 100000;	/* 100msec=100,000usec */
int BFD_MIN_RX_INTERVAL_DEFAULT = 100000;	/* 100msec=100,000usec */
int BFD_SLOW_TIMER_DEFAULT = 2000000;	/* 2000msec=2,000,000usec */

#ifdef __KERNEL__
module_param(BFD_DETECT_MULT_DEFAULT, int, 0000);
module_param(BFD_MIN_TX_INTERVAL_DEFAULT, int, 0000);
module_param(BFD_MIN_RX_INTERVAL_DEFAULT, int, 0000);
module_param(BFD_SLOW_TIMER_DEFAULT, int, 0000);

MODULE_PARM_DESC(BFD_DETECT_MULT_DEFAULT, " Multiplier");
MODULE_PARM_DESC(BFD_MIN_TX_INTERVAL_DEFAULT, " Min TX Interval [usec]");
MODULE_PARM_DESC(BFD_MIN_RX_INTERVAL_DEFAULT, " Min RX Interval [usec]");
MODULE_PARM_DESC(BFD_SLOW_TIMER_DEFAULT, " Slow Timer [usec]");
#endif

static int __init bfd_init(void)
{
	bfd_log_init();

	master = kmalloc(sizeof(struct bfd_master), GFP_KERNEL);
	if (!master) {
		blog_err("kmalloc error");
		return -1;
	}

	memset(master, 0, sizeof(struct bfd_master));

	master->slow_timer = BFD_SLOW_TIMER_DEFAULT;

	bfd_netlink_init();
	bfd_v4v6_init();
	bfd_session_init();
	bfd_feature_init();
	bfd_interface_init();

	if (IS_DEBUG_BSM) {
		blog_info("BFD: kbfd start");
	}
	return 0;
}

static void __exit bfd_exit(void)
{
	bfd_feature_finish();
	bfd_session_finish();
	bfd_v4v6_finish();
	bfd_netlink_finish();

	if (master)
		kfree(master);

	if (IS_DEBUG_BSM) {
		blog_info("BFD: kbfd stop");
	}

	bfd_log_finish();
}

module_init(bfd_init);
module_exit(bfd_exit);
MODULE_LICENSE("GPL");
