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
#ifndef __KBFD_INTERFACE_H__
#define __KBFD_INTERFACE_H__

struct bfd_interface {
	struct bfd_interface *next;
	int ifindex;

	u_int32_t v_mintx;
	u_int32_t v_minrx;
	u_int32_t v_mult;
	bool is_default;

	bool echo_on;
	bool per_link;

#ifdef __KERNEL__
	char *name;
#else
	char name[IFNAMSIZ];
#endif
};

struct bfd_interface *bfd_interface_get(int);
int bfd_interface_reset(int);
void bfd_interface_set_defaults(u_int32_t, u_int32_t, u_int32_t);
void bfd_interface_free(struct bfd_interface *);
void bfd_interface_change_timer(struct bfd_interface *);
void bfd_interface_change_timer_and_toggle_echo(struct bfd_interface *);
void bfd_sessions_change_slow_timer(void);
void bfd_interface_init(void);

static inline u_int32_t bfd_interface_v_minrx(struct bfd_interface *bif)
{
	if (bif) {
		return bif->v_minrx;
	} else {
		return 0;
	}
}
static inline u_int32_t bfd_interface_v_mintx(struct bfd_interface *bif)
{
	if (bif) {
		return bif->v_mintx;
	} else {
		return 0;
	}
}

static inline u_int32_t bfd_interface_v_mult(struct bfd_interface *bif)
{
	if (bif) {
		return bif->v_mult;
	} else {
		return 0;
	}
}

static inline int bfd_interface_index(struct bfd_interface *bif)
{
	if (bif) {
		return bif->ifindex;
	} else {
		return 0;
	}
}

static inline char *bfd_interface_name(struct bfd_interface *bif)
{
	if (bif && bif->name) {
		return bif->name;
	} else {
                return "Unknown";
	}
}

static inline bool bfd_interface_echo_on(struct bfd_interface *bif)
{
	if (bif) {
		return bif->echo_on;
	} else {
                return false;
	}
}

static inline bool bfd_interface_per_link(struct bfd_interface *bif)
{
	if (bif) {
		return bif->per_link;
	} else {
                return false;
	}
}

#endif				/* __KBFD_INTERFACE_H__ */
