/* 
 *  BFD Logging Management
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

#ifndef __KBFD_lOG_H__
#define __KBFD_lOG_H__

extern int bfd_log_init(void);
extern int bfd_log_finish(void);
extern void blog(const char *, ...);

extern u32 IS_DEBUG_BSM;
extern u32 IS_DEBUG_CTRL_PACKET;
extern u32 IS_DEBUG_NETLINK;

#define LOG_PREFIX

#define blog_debug(format, args...) \
	printk(KERN_DEBUG "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_info(format, args...) \
	printk(KERN_INFO "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_notice(format, args...) \
	printk(KERN_NOTICE "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_warn(format, args...) \
	printk(KERN_WARNING "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_err(format, args...) \
	printk(KERN_ERR "BFD(%lu): " format "\n", jiffies, ##args);

#define LINE_LEN 160

/* header prints the start, total, HIST_LEN, HDR_OFFSET) */
#define HDR_FORMAT "StartLine:%d, TotalSes:%d, MaxSes:%d, HdrLen:%d\n"

#define HDR_OFFSET 1

/* Max bfd session history entries */
#define HIST_LEN 1000

/* HDR_HIST_LEN includes a header + HIST_LEN */
#define HDR_HIST_LEN HIST_LEN + HDR_OFFSET

extern void bfd_add_sess_hist(char *);

#endif				/* __KBFD_LOG_H__ */
