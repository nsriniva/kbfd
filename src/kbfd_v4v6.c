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

#ifdef __KERNEL__
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/pkt_sched.h>
#include <linux/jhash.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/flow.h>
#include <net/ip6_route.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <net/neighbour.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <asm/unaligned.h>
#include <linux/err.h>
#else
#include "proc_compat.h"
#endif
#include <linux/netfilter.h>

#include "kbfd_interface.h"
#include "kbfd_log.h"
#include "kbfd_session.h"
#include "kbfd.h"
#include "kbfd_packet.h"
#include "kbfd_v4v6.h"

struct bfd_session *v4v6_nbr_tbl[2 * BFD_SESSION_HASH_SIZE];
/*
static DECLARE_COMPLETION(recv_threadcomplete);
static DECLARE_COMPLETION(echo_threadcomplete);
#ifdef __KERNEL__
static int recv_thread_pid, echo_thread_pid;
#else
static pthread_t recv_thread_pid, echo_thread_pid;
#endif
*/
static atomic_t ip_ident;
//static struct socket *rx_ctrl_sock = NULL;
//static struct socket *echo_sock = NULL;
struct vrf_recv info;
int recv_thread_err = -1;
int echo_thread_err = -1;

struct bfd_proto v4v6_proto;

static inline void
ipv6_addr_copy(struct in6_addr *a1, const struct in6_addr *a2)
{
	memcpy(a1, a2, sizeof(struct in6_addr));
}

static inline void *bfd_v4v6_get_ipaddress(struct sockaddr *addr,
					   size_t * addr_size)
{
	switch (addr->sa_family) {
	case AF_INET:
		if (addr_size)
			*addr_size = 4;
		return &((struct sockaddr_in *)addr)->sin_addr;
	case AF_INET6:
		if (addr_size)
			*addr_size = 16;
		return &((struct sockaddr_in6 *)addr)->sin6_addr;
	default:
		return NULL;
	}
}

static inline u32 addr_hash_(const u32 * addr, int addr_len)
{
	if (addr_len == 1) {
		return *addr;
	} else {
		__u32 word;

		/* 
		 * We perform the hash function over the last 64 bits of the address
		 * This will include the IEEE address token on links that support it.
		 */

		word = (__force u32) (addr[2] ^ addr[3]);
		word ^= (word >> 16);
		word ^= (word >> 8);

		return (word ^ (word >> 4));

	}
}

/*
 * To avoid having to check address families we do not allow v4 and v6
 * neighbors to be on the same hash chain.  We keep v4 entries in the first
 * half of available hash buckets and v6 in the second.
 */

static inline u_int32_t addr_hash(void *addr, size_t addr_size)
{
	return (BFD_SESSION_HASH_SIZE * (addr_size / 16) +
		(addr_hash_(addr, addr_size / 4) % BFD_SESSION_HASH_SIZE));
}

static u_int32_t bfd_v4v6_hash(struct sockaddr *key)
{
	void *addr;
	size_t addr_size = 0;

	addr = bfd_v4v6_get_ipaddress(key, &addr_size);

	/* 
	 * An offset of BFD_SESSION_HASH_SIZE is added to the hash value
	 * for IPv6 addresses.
	 */
	return addr_hash(addr, addr_size);
}

static inline int addreq(const u32 * addr1, const u32 * addr2, size_t size)
{
	if (size == 1)
		return !(addr1[0] ^ addr2[0]);

	return !((addr1[0] ^ addr2[0]) | (addr1[1] ^ addr2[1]) |
		 (addr1[2] ^ addr2[2]) | (addr1[3] ^ addr2[3]));
}

/* 
 * Compares 2 addresses. It does not check whether they belong to the same 
 * address family because callers ensure that only addresses of the same
 * family are compared; something made trivial by the separation of IP
 * and IPv6 hash chains mentioned above. Returns 0 if there's a match.
 */
static int bfd_v4v6_cmp(struct sockaddr *val1, struct sockaddr *val2)
{
	void *addr1, *addr2;
	size_t addr_size = 0;

	addr1 = bfd_v4v6_get_ipaddress(val1, &addr_size);
	addr2 = bfd_v4v6_get_ipaddress(val2, &addr_size);
	return memcmp(addr1, addr2, addr_size);
}

/* 
 * Checks if 2 addresses are equal . It does not check whether they belong to 
 * the same address family because callers ensure that only addresses of the 
 * same family are compared; something made trivial by the separation of IP
 * and IPv6 hash chains mentioned above. Returns 1 if there's a match.
 */

static int bfd_v4v6_eq(struct sockaddr *val1, struct sockaddr *val2)
{
	void *addr1, *addr2;
	size_t addr_size = 0;

	addr1 = bfd_v4v6_get_ipaddress(val1, &addr_size);
	addr2 = bfd_v4v6_get_ipaddress(val2, &addr_size);
	return addreq(addr1, addr2, addr_size / 4);
}

#ifdef __KERNEL__
static inline int bfd_v4v6_eq2(struct sockaddr *val1, u32 * addr)
{
	void *addr1;
	size_t addr_size;

	addr1 = bfd_v4v6_get_ipaddress(val1, &addr_size);
	return addreq(addr1, addr, addr_size / 4);
}
#endif

char *bfd_v4v6_print(struct sockaddr *addr, char *buf)
{
	if (addr->sa_family == AF_INET) {
#ifdef __KERNEL__
		sprintf(buf, "%pI4", &(((struct sockaddr_in *)addr)->sin_addr));
#else
		inet_ntop(AF_INET,
			  &(((struct sockaddr_in *)addr)->sin_addr),
			  buf, INET_ADDRSTRLEN);
#endif
	} else if (addr->sa_family == AF_INET6) {
#ifdef __KERNEL__
		if (ipv6_addr_type(&((struct sockaddr_in6 *)addr)->sin6_addr)
		    == IPV6_ADDR_MAPPED) {
#else
		if (IN6_IS_ADDR_V4MAPPED
		    (&((struct sockaddr_in6 *)addr)->sin6_addr)) {
			char tmp[INET_ADDRSTRLEN];
#endif
			struct in_addr in;

			memcpy(&in, (char *)
			       &(((struct sockaddr_in6 *)addr)->sin6_addr) + 12,
			       4);
#ifdef __KERNEL__
			sprintf(buf, "V6MAP %pI4", &in);
#else
			if (inet_ntop(AF_INET, &in, tmp, INET_ADDRSTRLEN))
				sprintf(buf, "V6MAP %s", tmp);
#endif
		} else {
#ifdef __KERNEL__
			sprintf(buf, "%pI6c",
				&(((struct sockaddr_in6 *)addr)->sin6_addr));
#else
			inet_ntop(AF_INET6,
				  &(((struct sockaddr_in6 *)addr)->sin6_addr),
				  buf, INET6_ADDRSTRLEN);
#endif
		}
	} else {
		sprintf(buf, "unknown family(%d)", addr->sa_family);
	}
	return buf;
}

static int bfd_v4v6_namelen(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
		break;
	default:
		break;
	}
	return 0;
};

static int bfd_v4v6_get_oif_(struct sockaddr *addr)
{
#ifdef __KERNEL__
	struct flowi fl;
	struct dst_entry *dst;
	int ifindex = 0;

	switch (addr->sa_family) {
	case AF_INET:
		memset(&fl, 0, sizeof(fl));
		fl.u.ip4.daddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		dst =
		    (struct dst_entry *)ip_route_output_key(&init_net,
							    &fl.u.ip4);
		ifindex = dst ? (dst->dev ? dst->dev->ifindex : 0) : 0;
		break;
	case AF_INET6:
		memset(&fl, 0, sizeof(fl));
		fl.u.ip6.daddr = ((struct sockaddr_in6 *)addr)->sin6_addr;
		dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);
		ifindex = dst ? (dst->dev ? dst->dev->ifindex : 0) : 0;
		break;
	default:
		break;
	}
	if (ifindex == 0) {
		char addr_buf[128];

		blog_warn("Unable to compute egress interface for peer: %s\n",
			  bfd_v4v6_print(addr, addr_buf));
	}
#endif
	return 0;
};

static int bfd_v4v6_get_oif(struct bfd_session *bfd)
{
	struct sockaddr *addr = bfd->dst;

	if (bfd->session_type == BFD_VXLAN_TUNNEL_SESSION)
		addr = &(VXLAN_TUNNEL_PRIV(bfd)->outer_dst.sa);
	return bfd_v4v6_get_oif_(addr);
}

int sock_create_ns(struct net *netns, int family, int type, int protocol, 
                   struct socket **res)
{
#ifdef __KERNEL__
   return __sock_create(netns, family, type, protocol, res, 0);
#else
   return sock_create(family, type, protocol, res);
#endif
}

static int bfd_v4v6_create_ctrl_socket(struct bfd_session *bfd)
{
	struct sockaddr_in6 saddr;	/* FIXME */
	int ttl;
	int tos;
	struct socket *sock;
	int err = 0;
	int sport;
	int i;

	if ((err = sock_create_ns(bfd->netns, AF_INET6, SOCK_DGRAM, 
                                  IPPROTO_UDP, &sock)) < 0) {
		blog_err("Error creating tx control socket. err= %d", err);
	}
	/* bind port */
	SK_REUSE_ADDR(sock);

	saddr.sin6_family = AF_INET6;
	ipv6_addr_set(&saddr.sin6_addr, 0, 0, 0, 0);

	for (i = 0; i < BFD_SRC_CONTROL_PORT_RANGE; i++) {
		if (++bfd->proto->last_sport_offset ==
		    BFD_SRC_CONTROL_PORT_RANGE)
			bfd->proto->last_sport_offset = 0;

		sport =
		    bfd->proto->last_sport_offset + BFD_SRC_CONTROL_PORT_BEGIN;
		saddr.sin6_port = htons((unsigned short)sport);
		if ((err = sock->ops->bind(sock, (struct sockaddr *)&saddr,
					   sizeof(struct sockaddr_in6))) == 0) {
			bfd->sport = sport;
			break;
		}
	}

	if (i == BFD_SRC_CONTROL_PORT_RANGE) {
		blog_err("Error bind control tx_socket. %d", err);
		return -1;
	}

	/* ttl is 255 and dscp 48(CS6 - rfc2474) */
	ttl = 255;
	tos = 0x30 << 2;
#ifdef __KERNEL__
	inet_sk(sock->sk)->uc_ttl = ttl;
	inet_sk(sock->sk)->pinet6->hop_limit = ttl;
	inet_sk(sock->sk)->tos = tos;
	inet_sk(sock->sk)->pinet6->tclass = tos;
#ifdef _IP_TOS2PRIO_EXPORTED
	/* can't call rt_tos2priority() as rt_tos2prio is not exported in this kernel */
	sock->sk->sk_priority = rt_tos2priority(dscp);
#else
	sock->sk->sk_priority = TC_PRIO_INTERACTIVE;
#endif

#else
	setsockopt(sock->sk->sk_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	setsockopt(sock->sk->sk_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,
		   sizeof(ttl));
	setsockopt(sock->sk->sk_socket, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	setsockopt(sock->sk->sk_socket, IPPROTO_IPV6, IPV6_TCLASS, &tos,
		   sizeof(tos));
#endif

	((struct sockaddr_in *)bfd->dst)->sin_port =
	    htons((unsigned short)BFD_CONTROL_PORT);
	bfd->tx_ctrl_sock = sock;

	return 0;
}

#ifdef __KERNEL__
static int
#else
static void *
#endif
bfd_v4v6_recv_thread(void *data)
{
	struct sockaddr_in6 client, our_addr;	/* FIXME */
	char buffer[sizeof(struct bfd_ctrl_packet)];
	int len, addr_size;
	struct msghdr msg;
	struct iovec iov;
	int ifindex = 0;
	int rcvttl = 0;
	struct sched_param param;
	static int init = 0;
	/* For IP_PKTINFO */
	char cbuffer[CMSG_SPACE(sizeof(union ip_pktinfo_union)) +
		     CMSG_SPACE(sizeof(rcvttl))];
	struct cmsghdr *cmh = (struct cmsghdr *)cbuffer;
	struct cmsghdr *cmhp;
	union ip_pktinfo_union *pkti_u;
        struct vrf_recv *info = data;
#ifdef __KERNEL__
	struct cpumask allowed_cpus;
#endif

	daemonize("kbfd_v4v6_rx");
	allow_signal(SIGTERM);

#ifndef __KERNEL__
	// proc mask
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIG_TX);
	sigaddset(&mask, SIG_RX_EXP);
	if (pthread_sigmask(SIG_BLOCK, &mask, NULL) == -1) {
		printf("\n sigprocmask failed: %d!\n", errno);
		fflush(stdout);
		// assert(0); 
	}
#endif
	if (init == 0) {
		param.sched_priority = MAX_RT_PRIO - 1;
		sched_setscheduler(current, SCHED_RR, &param);
		init++;
#ifdef __KERNEL__
		/* on multi core system, don't use cpu1 which handle irq load */
		cpumask_setall(&allowed_cpus);
		if (nr_cpu_ids > 1) {
			cpumask_clear_cpu(1, &allowed_cpus);
		}
		set_cpus_allowed_ptr(current, &allowed_cpus);
#endif
	}

	if (info->rx_ctrl_sock->sk == NULL) {
		blog_err("rx_ctrl_sock->sk is NULL!\n");
		return 0;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_name = &client;
	msg.msg_flags = 0;

	while (!signal_pending(current)) {
		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		iov.iov_base = buffer;
		iov.iov_len = sizeof(buffer);

		len = sock_recvmsg(info->rx_ctrl_sock, &msg, sizeof(buffer), 0);

		if (len <= 0) {
			blog_info("recvmsg len(%d) <= 0", len);
			continue;
		}

		if (IS_DEBUG_CTRL_PACKET) {
			blog_info("RECVMSG(%d)", len);
		}
		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		for (cmhp = CMSG_FIRSTHDR(&msg); cmhp;
		     cmhp = CMSG_NXTHDR(&msg, cmhp)) {
			if (cmhp->cmsg_level == IPPROTO_IP) {
				if (cmhp->cmsg_type == IP_PKTINFO) {
					pkti_u = (union ip_pktinfo_union *)
					    CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti.ipi_ifindex;
					our_addr.sin6_family = AF_INET;
					((struct sockaddr_in *)
					 &our_addr)->sin_addr =
					    pkti_u->pkti.ipi_addr;
				} else if (cmhp->cmsg_type == IP_TTL) {
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			} else if (cmhp->cmsg_level == IPPROTO_IPV6) {
				if (cmhp->cmsg_type == IPV6_PKTINFO) {
					pkti_u = (union ip_pktinfo_union *)
					    CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti6.ipi6_ifindex;
					our_addr.sin6_family = AF_INET6;
					our_addr.sin6_addr =
					    pkti_u->pkti6.ipi6_addr;
				} else if (cmhp->cmsg_type == IPV6_HOPLIMIT) {
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			}
		}

		if (IS_DEBUG_CTRL_PACKET) {
			char dbg_buffer[255];
			blog_info("ouraddr = %s ttl=%d iif=%d",
				  bfd_v4v6_print((struct sockaddr *)&our_addr,
						 dbg_buffer), rcvttl, ifindex);
		}

		/* Peer address */
		info->rx_ctrl_sock->ops->getname(info->rx_ctrl_sock,
                                                 (struct sockaddr *)&client,
                                                 &addr_size, 1);
		if (IN6_IS_ADDR_V4MAPPED(&(client.sin6_addr))) {
			struct sockaddr_in sin;

			memset(&sin, 0, sizeof(struct sockaddr_in));
			sin.sin_family = AF_INET;
			memcpy(&sin.sin_addr, (char *)&(client.sin6_addr) + 12,
			       4);
			memcpy(&client, &sin, sizeof(struct sockaddr_in));
		}

		/* GTSM check */
		if (rcvttl != 255) {
			blog_warn("%s: GTSM check failure. TTL=%d",
				  bfd_v4v6_print((struct sockaddr *)&client,
						 buffer), rcvttl);
			continue;
		}

		bfd_recv_ctrl_packet(&v4v6_proto, info->vrf_fd, 
                                     (struct sockaddr *)&client,
				     (struct sockaddr *)&our_addr,
				     ifindex, buffer, len);

	}

#ifdef __KERNEL__
	complete(&info->recv_thread_complete);
#endif
	return 0;
}

#ifdef __KERNEL__
static int
#else
static void *
#endif
bfd_v4v6_echo_thread(void *data)
{
	struct sockaddr_in6 client, our_addr;	/* FIXME */
	char buffer[sizeof(struct bfd_echo_packet)];
	int len, addr_size;
	struct msghdr msg;
	struct iovec iov;
	int ifindex = 0;
	int rcvttl = 0;
	struct sched_param param;
	static int init = 0;
	/* For IP_PKTINFO */
	char cbuffer[CMSG_SPACE(sizeof(union ip_pktinfo_union)) +
		     CMSG_SPACE(sizeof(rcvttl))];
	struct cmsghdr *cmh = (struct cmsghdr *)cbuffer;
	struct cmsghdr *cmhp;
	union ip_pktinfo_union *pkti_u;

        struct vrf_recv *info = data;

	daemonize("kbfd_v4v6_echo");
	allow_signal(SIGTERM);

#ifndef __KERNEL__
	// proc mask
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIG_TX);
	sigaddset(&mask, SIG_RX_EXP);
	if (pthread_sigmask(SIG_BLOCK, &mask, NULL) == -1) {
		printf("\n sigprocmask failed: %d!\n", errno);
		fflush(stdout);
		// assert(0); 
	}
#endif
	if (init == 0) {
		param.sched_priority = MAX_RT_PRIO - 1;
		sched_setscheduler(current, SCHED_RR, &param);
		init++;
	}

	if (info->rx_echo_sock->sk == NULL) {
		blog_err("echo_sock->sk is NULL!\n");
		return 0;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_name = &client;
	msg.msg_flags = 0;

	while (!signal_pending(current)) {
		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		iov.iov_base = buffer;
		iov.iov_len = sizeof(buffer);

		len = sock_recvmsg(info->rx_echo_sock, &msg, sizeof(buffer), 0);

		if (len <= 0) {
			blog_info("recvmsg len(%d) <= 0", len);
			continue;
		}

		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		for (cmhp = CMSG_FIRSTHDR(&msg); cmhp;
		     cmhp = CMSG_NXTHDR(&msg, cmhp)) {
			if (cmhp->cmsg_level == IPPROTO_IP) {
				if (cmhp->cmsg_type == IP_PKTINFO) {
					pkti_u = (union ip_pktinfo_union *)
					    CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti.ipi_ifindex;
					our_addr.sin6_family = AF_INET;
					((struct sockaddr_in *)
					 &our_addr)->sin_addr =
					    pkti_u->pkti.ipi_addr;
				} else if (cmhp->cmsg_type == IP_TTL) {
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			} else if (cmhp->cmsg_level == IPPROTO_IPV6) {
				if (cmhp->cmsg_type == IPV6_PKTINFO) {
					pkti_u = (union ip_pktinfo_union *)
					    CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti6.ipi6_ifindex;
					our_addr.sin6_family = AF_INET6;
					ipv6_addr_copy(&our_addr.sin6_addr,
						       &pkti_u->
						       pkti6.ipi6_addr);
				} else if (cmhp->cmsg_type == IPV6_HOPLIMIT) {
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			}
		}

#ifdef ECHO_DEBUG
		{
			char dbg_buffer[255];
			blog_info("ECHO <= ouraddr = %s ttl=%d iif=%d",
				  bfd_v4v6_print((struct sockaddr *)&our_addr,
						 dbg_buffer), rcvttl, ifindex);
		}
#endif

		/* Peer address */
		info->rx_echo_sock->ops->getname(info->rx_echo_sock,
					(struct sockaddr *)&client, &addr_size,
					1);
		if (IN6_IS_ADDR_V4MAPPED(&(client.sin6_addr))) {
			struct sockaddr_in sin;

			memset(&sin, 0, sizeof(struct sockaddr_in));
			sin.sin_family = AF_INET;
			memcpy(&sin.sin_addr, (char *)&(client.sin6_addr) + 12,
			       4);
			memcpy(&client, &sin, sizeof(struct sockaddr_in));
		}

		bfd_recv_echo_packet(&v4v6_proto, (struct sockaddr *)&client,
				     (struct sockaddr *)&our_addr,
				     ifindex, buffer, len);

	}

	blog_err("Echo thread exiting!\n");
#ifdef __KERNEL__
	complete(&info->echo_thread_complete);
#endif
	return 0;
}

static void
bfd_kill_thread(int thread_pid, struct completion *threadcomplete, char *name)
{
#ifdef __KERNEL__
	struct pid *thread_pid_struct = NULL;
	thread_pid_struct = find_get_pid(thread_pid);
	if (thread_pid_struct) {
		kill_pid(thread_pid_struct, SIGTERM, 0);
		wait_for_completion(threadcomplete);
	}
#else
	void *res;

	printf("\n Going to kill %s thread!\n", name);
	fflush(stdout);
	pthread_kill(thread_pid, SIGTERM);
	pthread_join(thread_pid, &res);
#endif

}

#define iphdr_set_addr(iph,addr_type,addr,addr_size) memcpy(&(iph->addr_type), addr, addr_size)
#define iphdr_set_addrs_m(iph, src, dst, addr_size) \
   iphdr_set_addr(iph, saddr, src, addr_size); \
   iphdr_set_addr(iph, daddr, dst, addr_size);

void update_ip_hdr(void *_iph, void *src, void *dst, size_t addr_size)
{
	if (addr_size == 4) {
		struct iphdr *iph = _iph;
		iphdr_set_addrs_m(iph, src, dst, addr_size);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	} else {
		struct ipv6hdr *iph = _iph;
		iphdr_set_addrs_m(iph, src, dst, addr_size);
	}
}

static u_int16_t
csum_magic(void *saddr, void *daddr, size_t addr_size,
	   size_t udp_len, struct udphdr *udph, unsigned payload_csum)
{
	if (addr_size == 4) {
		return csum_tcpudp_magic(*((u_int32_t *) saddr),
					 *((u_int32_t *) daddr),
					 udp_len, IPPROTO_UDP,
					 csum_partial(udph, sizeof(*udph),
						      payload_csum));
	} else {
		return csum_ipv6_magic(saddr,
				       daddr,
				       udp_len, IPPROTO_UDP,
				       csum_partial(udph, sizeof(*udph),
						    payload_csum));
	}
}

void update_udp_hdr(struct udphdr *udph, void *payload,
		    u_int32_t payload_len, void *saddr,
		    void *daddr, u_int32_t addr_size)
{
	unsigned payload_csum;

	payload_csum = csum_partial(payload, payload_len, 0);
	udph->check = 0;

	udph->check = csum_magic(saddr, daddr, addr_size, ntohs(udph->len),
				 udph, payload_csum);
	if (udph->check == 0)
		udph->check = CSUM_MANGLED_0;
}

static void *bfd_v4v6_update_feature_packet(struct bfd_session *bfd)
{
	void *ret = NULL;
	void *saddr, *daddr;
	size_t addr_size = 0;
	struct bfd_feature_vector *vect = NULL;

	if (!(bfd->feat && (vect = bfd->feat->vect) && vect->enabled(bfd))) {
		goto finish;
	}

	if (vect->update_dmac && !vect->update_dmac(bfd)) {
		ret = (void *)-1;
		goto finish;
	}

	if (!(saddr = vect->get_saddr(bfd, &addr_size))) {
		ret = (void *)-2;
		goto finish;
	}

	daddr = vect->get_daddr(bfd, saddr);
	vect->set_payload(bfd);

	update_udp_hdr((void *)((char *)bfd->feat->payload -
				sizeof(struct udphdr)), bfd->feat->payload,
		       bfd->feat->payload_len, saddr, daddr, addr_size);

	update_ip_hdr(bfd->feat->pkt, saddr, daddr, addr_size);
	ret = bfd->feat->pkt;

 finish:
	return ret;
}

void init_ipv4_hdr(struct iphdr *ipho, u_int32_t udp_len, bool unaligned)
{
        struct iphdr *iph;
        if (unaligned) {
           struct iphdr tmpHdr;
           memset(&tmpHdr, 0, sizeof(tmpHdr));
           iph = &tmpHdr;
        } else {
           iph = ipho;
        }

        iph->version = 4;
	iph->ihl = 5;
	/* dscp 48(CS6 - rfc2474) */
	iph->tos = 0x30 << 2;
        iph->tot_len = htons(sizeof(*iph) + udp_len);
	iph->id = 0;
	/* Set [DF] in iph */
	iph->frag_off = htons(IP_DF);
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        if (unaligned) {
           memcpy(ipho, iph, sizeof(*ipho));
        }
}

static void init_ipv6_hdr(struct ipv6hdr *iph, u_int32_t udp_len)
{
	iph->version = 6;
	iph->payload_len = htons(udp_len);
	iph->hop_limit = 255;
	iph->nexthdr = IPPROTO_UDP;
}

static void bfd_v4v6_init_headers(struct bfd_session *bfd)
{
	struct udphdr *udph =
	    (struct udphdr *)((char *)bfd->feat->payload -
			      sizeof(struct udphdr));
	u_int32_t udp_len;

	udp_len = sizeof(*udph) + bfd->feat->payload_len;
	udph->len = htons(udp_len);
	bfd->feat->vect->get_udp_ports(bfd, &udph->source, &udph->dest);

	if (bfd->dst->sa_family == AF_INET) {

		init_ipv4_hdr((void *)bfd->feat->pkt, udp_len, false);
		if (bfd->feat->vect->set_sll_protocol)
			bfd->feat->l2dst.sll_protocol =
			    (unsigned short)htons(ETH_P_IP);
	} else {

		init_ipv6_hdr((void *)bfd->feat->pkt, udp_len);
		if (bfd->feat->vect->set_sll_protocol)
			bfd->feat->l2dst.sll_protocol =
			    (unsigned short)htons(ETH_P_IPV6);
	}
}

#ifdef __KERNEL__
static struct neighbour *bfd_v4v6_get_neigh(struct bfd_session *bfd,
					    u_int32_t ifindex)
{
	struct neighbour *ret = NULL;
	struct net_device *tx_dev;

	tx_dev = dev_get_by_index(&init_net, ifindex);
	if (!tx_dev)
		goto done;

	switch (bfd->dst->sa_family) {
	case AF_INET:
		ret = neigh_lookup(&arp_tbl,
				   &(((struct sockaddr_in *)bfd->
				      dst)->sin_addr), tx_dev);
		break;
	case AF_INET6:
		ret = neigh_lookup(&nd_tbl,
				   &(((struct sockaddr_in6 *)bfd->
				      dst)->sin6_addr), tx_dev);
		break;
	default:
		break;
	}

	if (ret && !(ret->nud_state & NUD_VALID)) {
		neigh_release(ret);
		ret = NULL;
	}
	dev_put(tx_dev);
 done:
	return ret;
}
#endif

static int bfd_v4v6_send_msg(void *pkt, size_t pkt_size, void *addr,
			     size_t addr_size, struct socket *sock,
			     struct bfd_session *bfd)
{
	mm_segment_t oldfs;
	int len;
	struct msghdr msg;
	struct iovec iov;
	char buf[256];
	if (IS_DEBUG_CTRL_PACKET) {
		blog_debug("add(%s),size(%d),pkt_size(%d)",
			   bfd->proto->addr_print(addr, buf),
			   (int)addr_size, (int)pkt_size);
	}

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = addr;
	msg.msg_namelen = addr_size;

	iov.iov_base = pkt;
	iov.iov_len = pkt_size;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	bfd->tx_jiff = jiffies;
	len = sock_sendmsg(sock, &msg, iov.iov_len);
	set_fs(oldfs);
	if ((len < 0) && IS_DEBUG_CTRL_PACKET) {
		blog_err("sock_sendmsg returned: %d", len);
	}

	return len;
}

static int bfd_v4v6_xmit_packet(struct bfd_session *bfd)
{
	struct bfd_ctrl_packet pkt;
	size_t pkt_size = sizeof(pkt);
	char buf[256];

	memcpy(&pkt, &bfd->cpkt, pkt_size);

	if (IS_DEBUG_CTRL_PACKET)
		blog_info("SEND=>: Ctrl Pkt to %s",
			  bfd->proto->addr_print(bfd->dst, buf));
	return bfd_v4v6_send_msg(&pkt, pkt_size, bfd->dst,
				 bfd->proto->namelen(bfd->dst),
				 bfd->tx_ctrl_sock, bfd);
}

static int bfd_v4v6_xmit_feature_packet(struct bfd_session *bfd)
{
	char buf[256];
	void *feat_pkt = bfd_v4v6_update_feature_packet(bfd);

	if (IS_DEBUG_CTRL_PACKET)
		blog_debug("SEND=>: Feature Pkt to peer(%s)",
			   bfd->proto->addr_print(bfd->dst, buf));

	if (IS_ERR_OR_NULL(feat_pkt)) {
		if (IS_DEBUG_CTRL_PACKET)
			blog_debug("Update feature packet returned with %ld\n",
				   PTR_ERR(feat_pkt));

		goto finish;
	}

	return bfd_v4v6_send_msg(feat_pkt, bfd->feat->pkt_size, &bfd->feat->l2dst,
				 sizeof(bfd->feat->l2dst), bfd->feat->tx_sock,
				 bfd);

 finish:
	return -1;
}

static int bfd_v4v6_xmit_vxlan_tunnel_packet(struct bfd_session *bfd)
{
	char buf[256];
	void *feat_pkt = bfd_v4v6_update_feature_packet(bfd);

	if (IS_DEBUG_CTRL_PACKET)
		blog_debug("SEND=>: Xmit VXLAN Tunnel Pkt to peer(%s)",
			   bfd->proto->addr_print(bfd->dst, buf));

	if (IS_ERR_OR_NULL(feat_pkt)) {
		if (IS_DEBUG_CTRL_PACKET)
			blog_debug("Update feature packet returned with %ld\n",
				   PTR_ERR(feat_pkt));

		goto finish;
	}


	return bfd_v4v6_send_msg(feat_pkt, bfd->feat->pkt_size, 
                                 &bfd->feat->l3v4dst,
				 sizeof(bfd->feat->l3v4dst),
				 bfd->feat->tx_sock, bfd);

 finish:
	return -1;
}

#ifdef __KERNEL__
static void neigh_replace(struct bfd_session *bfd, struct neighbour *n)
{
	if (n != bfd->feat->_neigh) {
		neigh_hold(n);
		if (bfd->feat->_neigh)
			neigh_release(bfd->feat->_neigh);
		bfd->feat->_neigh = n;
		bfd->feat->valid_dmac = false;
		bfd_v4v6_update_feature_packet(bfd);
	}
}

void check_neigh_update(struct neighbour *neigh)
{
	int addr_len = neigh->tbl->key_len;
	u32 *addr = (u32 *) neigh->primary_key;
	int ifidx = neigh->dev->ifindex;
	u_int32_t key;
	struct bfd_session *bfd;

	if (!(neigh->nud_state & NUD_CONNECTED))
		goto done;

	rcu_read_lock();
	key = addr_hash(addr, addr_len);
	bfd = v4v6_nbr_tbl[key];
	while (bfd) {
		if (bfd_v4v6_eq2(bfd->dst, addr)
		    && (bfd_interface_index(bfd->bif) == ifidx))
			break;
		bfd = bfd->nbr_next;
	}

	if (bfd && ((bfd->session_type != BFD_NORMAL_SESSION) || bfd->feat)) {
		bfd_session_grab(bfd, SESSION_NEIGH_CHANGE);
	} else {
		bfd = NULL;
	}
	rcu_read_unlock();

	if (bfd) {
		if (bfd->session_type == BFD_LAG_SESSION) {
			struct bfd_session *micro = bfd->lag_member;

			for (; micro; micro = micro->lag_member) {
				bfd_session_grab(micro, SESSION_NEIGH_CHANGE);
				neigh_replace(micro, neigh);
				bfd_session_release(micro,
						    SESSION_NEIGH_CHANGE);
			}
		} else {
			neigh_replace(bfd, neigh);
		}
		bfd_session_release(bfd, SESSION_NEIGH_CHANGE);
	}
 done:
	return;
}

static int
netevent_cb(struct notifier_block *nb, unsigned long event, void *data)
{
	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		check_neigh_update(data);
		break;
	case NETEVENT_REDIRECT:
	default:
		break;
	}
	return 0;
}

static struct notifier_block bfd_netevent_nb = {
	.notifier_call = netevent_cb
};

#endif

static void
release_recv_info(struct vrf_recv *info )
{
		if (info->rx_echo_sock)
			sock_release(info->rx_echo_sock);
		if (info->rx_ctrl_sock)
			sock_release(info->rx_ctrl_sock);
                if (info->recv_thread_pid)
                        bfd_kill_thread(info->recv_thread_pid, 
                                        &info->recv_thread_complete, "recv" );
                if (info->echo_thread_pid)
                        bfd_kill_thread(info->echo_thread_pid, 
                                        &info->echo_thread_complete, "echo" );


                memset(info, 0, sizeof(*info));
}

#ifdef __KERNEL__

static struct net *
__bfd_v4v6_get_netns(int vrf_fd)
{
   struct net *ret;

   if (vrf_fd) {
      struct file *fp;
      struct proc_inode *ei;

      fp = fget(vrf_fd);
      if (IS_ERR(fp))
         return ERR_CAST(fp);
      
      ei = PROC_I(fp->f_dentry->d_inode);
      
      ret = get_net(ei->ns);
      
      fput(fp);
   } else {
      ret = get_net(&init_net);
   }

   return ret;
}

static struct net *
bfd_v4v6_get_netns(struct bfd_session *bfd)
{
   return (bfd->netns = __bfd_v4v6_get_netns(bfd->vrf_fd));
}

#endif

static int init_recv_info(struct vrf_recv *info)
{
        int err = 0;
	struct sockaddr_in6 s6addr;
	mm_segment_t oldfs;
	int val = 1;
        struct net *netns = NULL;

#ifdef __KERNEL__

        init_completion(&info->recv_thread_complete);
        init_completion(&info->echo_thread_complete);
        netns = __bfd_v4v6_get_netns(info->vrf_fd);
#endif
   
	/* Control Packet Socket */
	if (sock_create_ns(netns, AF_INET6, 
                          SOCK_DGRAM, IPPROTO_UDP, &info->rx_ctrl_sock) < 0) {
		blog_err("Error creating rx control socket.");
		err = -EIO;
		goto end;
	}

	/* bind port */
	SK_REUSE_ADDR(info->rx_ctrl_sock);

	s6addr.sin6_family = AF_INET6;
	ipv6_addr_set(&s6addr.sin6_addr, 0, 0, 0, 0);
	s6addr.sin6_port = htons((unsigned short)BFD_CONTROL_PORT);
	err = info->rx_ctrl_sock->ops->bind(info->rx_ctrl_sock,
				      (struct sockaddr *)&s6addr,
				      sizeof(struct sockaddr_in6));
	if (err) {
		blog_err("Error bind control rx_socket. %d", err);
		sock_release(info->rx_ctrl_sock);
		err = -EIO;
		goto end;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	err = info->rx_ctrl_sock->ops->setsockopt(info->rx_ctrl_sock, 
                                                  IPPROTO_IP,
                                                  IP_PKTINFO,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_ctrl_sock->ops->setsockopt(info->rx_ctrl_sock, 
                                                  IPPROTO_IP,
                                                  IP_RECVTTL,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_ctrl_sock->ops->setsockopt(info->rx_ctrl_sock, 
                                                  IPPROTO_IPV6,
                                                  IPV6_RECVPKTINFO,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_ctrl_sock->ops->setsockopt(info->rx_ctrl_sock, 
                                                  IPPROTO_IPV6,
                                                  IPV6_RECVHOPLIMIT,
                                                  (char __user *)&val, 
                                                  sizeof(val));

	set_fs(oldfs);
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}

	/* Start Control Thread */
#ifdef __KERNEL__
	info->recv_thread_pid =
	    kernel_thread(bfd_v4v6_recv_thread, info, CLONE_KERNEL);
	recv_thread_err = 0;
	if (info->recv_thread_pid < 0)
		recv_thread_err = -1;
#else
	recv_thread_err = pthread_create(&info->recv_thread_pid, NULL,
					 bfd_v4v6_recv_thread, info);
#endif
	if (recv_thread_err < 0) {
		blog_err("failed create recv thread");
                release_recv_info(info);
		return -EIO;
	}


	/* Echo Packet Socket */
	if (sock_create_ns(netns, AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &info->rx_echo_sock)
            < 0) {
		blog_err("Error creating echo socket.");
		err = -EIO;
		goto end;
	}

	SK_REUSE_ADDR(info->rx_echo_sock);

	s6addr.sin6_family = AF_INET6;
	ipv6_addr_set(&s6addr.sin6_addr, 0, 0, 0, 0);
	s6addr.sin6_port = htons((unsigned short)BFD_ECHO_PORT);
	err = info->rx_echo_sock->ops->bind(info->rx_echo_sock,
				   (struct sockaddr *)&s6addr,
				   sizeof(struct sockaddr_in6));
	if (err) {
		blog_err("Error bind echo socket. %d", err);
		sock_release(info->rx_echo_sock);
		err = -EIO;
		goto end;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	err = info->rx_echo_sock->ops->setsockopt(info->rx_echo_sock, 
                                                  IPPROTO_IP,
                                                  IP_PKTINFO,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_echo_sock->ops->setsockopt(info->rx_echo_sock, 
                                                  IPPROTO_IP,
                                                  IP_RECVTTL,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_echo_sock->ops->setsockopt(info->rx_echo_sock, 
                                                  IPPROTO_IPV6,
                                                  IPV6_RECVPKTINFO,
                                                  (char __user *)&val, 
                                                  sizeof(val));
	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	err = info->rx_echo_sock->ops->setsockopt(info->rx_echo_sock, 
                                                  IPPROTO_IPV6,
                                                  IPV6_RECVHOPLIMIT,
                                                  (char __user *)&val, 
                                                  sizeof(val));

	if (err) {
		blog_warn("setsockopt failure (%d)", err);
	}
	/* Start Echo Thread */
#ifdef __KERNEL__
	info->echo_thread_pid =
	    kernel_thread(bfd_v4v6_echo_thread, &info, CLONE_KERNEL);
	echo_thread_err = 0;
	if (info->echo_thread_pid < 0)
		echo_thread_err = -1;
#else
	echo_thread_err = pthread_create(&info->echo_thread_pid, NULL,
					 bfd_v4v6_echo_thread, info);
#endif
	if (echo_thread_err < 0) {
		blog_err("failed create echo thread");
                release_recv_info(info);
		return -EIO;
	}
  end:
        return err;
   
}


int bfd_v4v6_init(void)
{
	int err;

        memset(&info, 0, sizeof(info));

        if ((err = init_recv_info(&info))) 
           goto end;
	/* initialize neighbor table */
	memset(v4v6_nbr_tbl, 0,
	       sizeof(struct bfd_session *) * 2 * BFD_SESSION_HASH_SIZE);

#ifdef _KERNEL__
	register_netevent_notifier(&bfd_netevent_nb);
#endif

	atomic_set(&ip_ident, 0);

 end:
	return err;
}

int bfd_v4v6_finish(void)
{
        release_recv_info(&info);

#ifdef __KERNEL__
	unregister_netevent_notifier(&bfd_netevent_nb);
#endif
	return 0;
}

static u_int32_t bfd_v4v6_disc_hash_offset(u_int32_t disc)
{
	return DISC_HASH_OFFSET(disc);
}

static u_int32_t bfd_v4v6_next_discriminator(u_int32_t key)
{
	/*
	 * if v4 address key < BFD_SESSION_HASH_SIZE
	 * if v6 address key >= BFD_SESSION_HASH_SIZE
	 */
	return ++(v4v6_proto.disc[key / BFD_SESSION_HASH_SIZE]);
}

static u_int32_t bfd_v4v6_packet_header_len(struct bfd_session *bfd)
{
	if (bfd->dst->sa_family == AF_INET) {
		return sizeof(struct ip4_udppkt);
	} else {
		return sizeof(struct ip6_udppkt);
	}
}


struct bfd_proto v4v6_proto = {
	.disc = {0, DISC_START_V6},
	.last_sport_offset = BFD_SRC_CONTROL_PORT_RANGE - 1,
	.create_ctrl_socket = bfd_v4v6_create_ctrl_socket,
	.hdr_len = bfd_v4v6_packet_header_len,
	.init_hdrs = bfd_v4v6_init_headers,
	.xmit_feature_packet = bfd_v4v6_xmit_feature_packet,
	.xmit_packet =
	    {bfd_v4v6_xmit_packet, NULL, bfd_v4v6_xmit_feature_packet,
	     bfd_v4v6_xmit_vxlan_tunnel_packet},
	.nbr_tbl = v4v6_nbr_tbl,
	.hash = bfd_v4v6_hash,
	.cmp = bfd_v4v6_cmp,
	.eq = bfd_v4v6_eq,
	.addr_print = bfd_v4v6_print,
	.namelen = bfd_v4v6_namelen,
	.get_oif = bfd_v4v6_get_oif,
	.get_addr = bfd_v4v6_get_ipaddress,
#ifdef __KERNEL__
	.get_neigh = bfd_v4v6_get_neigh,
        .get_netns = bfd_v4v6_get_netns,
#endif
	.disc_hash_offset = bfd_v4v6_disc_hash_offset,
	.next_disc = bfd_v4v6_next_discriminator,
};
