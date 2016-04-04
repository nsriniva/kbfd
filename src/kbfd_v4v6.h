/* 
 *  BFD for IPv4 and IPv6 (1-hop)
 *
 * base from draft-ietf-bfd-v4v6-1hop-05.txt
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
#ifndef __KBFD_V4V6_H__
#define __KBFD_V4V6_H__

#ifdef __KERNEL__
#include <linux/ip.h>
#include <linux/ipv6.h>
#endif

#define  BFD_CONTROL_PORT           3784
#define  BFD_ECHO_PORT              3785
#define  BFD_MULTI_CONTROL_PORT     4784
#define  BFD_SRC_CONTROL_PORT_BEGIN 49152
#define  BFD_SRC_CONTROL_PORT_END   65535
#define BFD_SRC_CONTROL_PORT_RANGE \
        (BFD_SRC_CONTROL_PORT_END - BFD_SRC_CONTROL_PORT_BEGIN + 1)

#define DISC_START_V6 (UINT_MAX >> 1)

#ifdef __KERNEL__

typedef int pthread_t;
#endif
struct vrf_recv {
   struct socket *rx_ctrl_sock;
   struct completion recv_thread_complete;
   pthread_t recv_thread_pid;
   struct socket *rx_echo_sock;
   struct completion echo_thread_complete;
   pthread_t echo_thread_pid;
   int vrf_fd;
};
/*
 * BFD_SESSION_HASH_SIZE if x >= DISC_START_V6 else 0
 */
#define DISC_HASH_OFFSET(x) (((x)/DISC_START_V6)*BFD_SESSION_HASH_SIZE)

#ifndef IN6_IS_ADDR_V4MAPPED

#define IN6_IS_ADDR_V4MAPPED(x) (ipv6_addr_type(x) == IPV6_ADDR_MAPPED)

#define SK_REUSE_ADDR(sock) sock->sk->sk_reuse = 1

#endif

union ip_pktinfo_union {
	struct in_pktinfo pkti;
	struct in6_pktinfo pkti6;
};

struct udppkt {
	struct udphdr udp_hdr;
	char payload[0];
};

struct ip4_udppkt {
	struct iphdr ip_hdr;
	struct udppkt udp_pkt;
};

struct ip6_udppkt {
	struct ipv6hdr ip6_hdr;
	struct udppkt udp_pkt;
};


int bfd_v4v6_init(void);
int bfd_v4v6_finish(void);
#define iphdr_set_addr(iph,addr_type,addr,addr_size) memcpy(&(iph->addr_type), addr, addr_size)
#define iphdr_set_addrs_m(iph, src, dst, addr_size) \
      iphdr_set_addr(iph, saddr, src, addr_size); \
   iphdr_set_addr(iph, daddr, dst, addr_size);

void update_ip_hdr(void *_iph, void *src, void *dst, size_t addr_size);
void update_udp_hdr(struct udphdr *udph, void *payload, u_int32_t payload_len,
		    void *saddr, void *daddr, u_int32_t addr_size);
void init_ipv4_hdr(struct iphdr *iph, u_int32_t udp_len, bool unaligned );

int sock_create_ns(struct net *netns, int family, int type, int protocol, 
                   struct socket **res);
#endif				/* __KBFD_V4V6_H__ */
