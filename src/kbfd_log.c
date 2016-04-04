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

#include <stdarg.h>
#ifdef __KERNEL__
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_log.h"

static struct dentry *kbfd_debug_root_dir, *kbfd_debug_dir;

static struct dentry *kbfd_debug_log_bsm, *kbfd_debug_log_ctrl_packet,
    *kbfd_debug_log_netlink;

struct kbfd_ses_hist_entries {
	char sessions[HDR_HIST_LEN][LINE_LEN];
};
u32 IS_DEBUG_BSM = 0;
u32 IS_DEBUG_CTRL_PACKET = 0;
u32 IS_DEBUG_NETLINK = 0;

struct kbfd_ses_hist {
	int total;
	int start;
	struct debugfs_blob_wrapper blob;
	struct dentry *hist_dir;
	struct dentry *hist_ses;
	struct kbfd_ses_hist_entries *ses_hist;
};

static struct kbfd_ses_hist kbfd_ses;

int bfd_log_finish()
{
	if (kbfd_debug_root_dir) {
		debugfs_remove_recursive(kbfd_debug_root_dir);
	}
	return 0;
}

int bfd_log_init()
{

	kbfd_debug_root_dir = debugfs_create_dir("kbfd", NULL);
	if (!kbfd_debug_root_dir) {
		blog_err("kbfd init fail(debug root)...:");
		return 0;
	}

	kbfd_debug_dir = debugfs_create_dir("debug", kbfd_debug_root_dir);
	if (!kbfd_debug_dir) {
		blog_err("kbfd init fail(debug)...:");
		return 0;
	}

	kbfd_debug_log_bsm =
	    debugfs_create_bool("bsm", S_IFREG | S_IRWXUGO, kbfd_debug_dir,
				&IS_DEBUG_BSM);
	if (!kbfd_debug_log_bsm) {
		blog_err("kbfd init fail: Could not create debug/bsm entry ");
		return 0;
	}

	kbfd_debug_log_ctrl_packet =
	    debugfs_create_bool("ctrl-packet", S_IFREG | S_IRWXUGO,
				kbfd_debug_dir, &IS_DEBUG_CTRL_PACKET);
	if (!kbfd_debug_log_ctrl_packet) {
		blog_err
		    ("kbfd init fail: Could not create debug/ctrl-packet entry ");
		return 0;
	}

	kbfd_debug_log_netlink =
	    debugfs_create_bool("netlink", S_IFREG | S_IRWXUGO, kbfd_debug_dir,
				&IS_DEBUG_NETLINK);
	if (!kbfd_debug_log_netlink) {
		blog_err
		    ("kbfd init fail: Could not create debug/netlink entry ");
		return 0;
	}

	kbfd_ses.hist_dir = debugfs_create_dir("history", kbfd_debug_root_dir);
	if (!kbfd_ses.hist_dir) {
		blog_err("kbfd init fail(history)...:");
		return 0;
	}

	kbfd_ses.ses_hist = (struct kbfd_ses_hist_entries *)
	    kmalloc(sizeof(struct kbfd_ses_hist_entries), GFP_KERNEL);
	if (!kbfd_ses.ses_hist) {
		blog_err("kbfd init could not kmalloc ses_hist...:");
		return 0;
	}
	memset(kbfd_ses.ses_hist, 0, sizeof(struct kbfd_ses_hist_entries));
	snprintf(kbfd_ses.ses_hist->sessions[0], LINE_LEN, HDR_FORMAT,
		 kbfd_ses.start, kbfd_ses.total, HIST_LEN, HDR_OFFSET);

	kbfd_ses.blob.data = (void *)kbfd_ses.ses_hist;
	kbfd_ses.blob.size = sizeof(struct kbfd_ses_hist_entries);

	kbfd_ses.hist_ses = debugfs_create_blob("session", S_IRUGO | S_IWUSR,
						kbfd_ses.hist_dir,
						&kbfd_ses.blob);
	if (!kbfd_ses.hist_ses) {
		blog_err
		    ("kbfd init fail: Could not create session blob entry ");
		return 0;
	}

	return 0;
}

void blog(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	printk(LOG_PREFIX format, args);
	va_end(args);
}

void bfd_add_sess_hist(char *entry)
{
	int new_idx = 0;
	int entry_len = 0;
	if (!kbfd_ses.ses_hist || !entry) {
		return;
	}
	if (kbfd_ses.total == HIST_LEN) {
		/* total sessions is at max. total remains at max, start loops */
		new_idx = kbfd_ses.start;
		kbfd_ses.start = (new_idx + 1) % HIST_LEN;

	} else {
		/* total sessions is less than max. start remains at 0, total++ */
		new_idx = kbfd_ses.total;
		kbfd_ses.total++;
	}
	entry_len = strlen(entry);

	strncpy(kbfd_ses.ses_hist->sessions[new_idx + HDR_OFFSET], entry,
		entry_len > LINE_LEN ? LINE_LEN : entry_len);
	/* update header */
	snprintf(kbfd_ses.ses_hist->sessions[0], LINE_LEN, HDR_FORMAT,
		 kbfd_ses.start + HDR_OFFSET, kbfd_ses.total, HIST_LEN,
		 HDR_OFFSET);

	return;
}
