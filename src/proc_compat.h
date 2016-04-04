/* 
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
 * Copyright (C) Arista Networks, 2013
 */

#ifndef KBFD_PROC_COMPAT_H
#define KBFD_PROC_COMPAT_H

#include <asm/byteorder.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>

#include <stdio.h>
#include <assert.h>

#define UINT_MAX   (~0U)

#define SIG_TX SIGUSR1
#define SIG_RX_EXP SIGUSR2
#define NETLINK_BFD  NETLINK_GENERIC

#define S_IRUGO            (S_IRUSR|S_IRGRP|S_IROTH)
#define S_IRWXUGO       (S_IRWXU|S_IRWXG|S_IRWXO)
#define NSEC_PER_SEC    1000000000L

#define CLONE_KERNEL    (CLONE_FS | CLONE_FILES | CLONE_SIGHAND)

typedef enum { false = 0, true = 1 } bool;

typedef u_int32_t u32;
typedef u_int16_t u16;
typedef unsigned short umode_t;

typedef pthread_spinlock_t spinlock_t;
typedef int atomic_t;

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#define DEFINE_SPINLOCK(x) spinlock_t x
#define spin_lock(x) pthread_spin_lock(x)
#define spin_unlock(x) pthread_spin_unlock(x)

#define spin_lock_init(x) pthread_spin_init(x, PTHREAD_PROCESS_PRIVATE)

static inline void atomic_set(atomic_t * v, int i)
{
	__sync_lock_test_and_set(v, i);
}

static inline int atomic_read(atomic_t * v)
{
	return __sync_fetch_and_add(v, 0);
}

static inline void atomic_inc(atomic_t * v)
{
	__sync_add_and_fetch(v, 1);
}

static inline int atomic_sub_return(int i, atomic_t * v)
{
	return __sync_sub_and_fetch(v, i);
}

#define atomic_dec_and_test(v)          (atomic_sub_return(1, (v)) == 0)

#define ktime_get_ts(x) clock_gettime(CLOCK_REALTIME, x)

#define daemonize(x)

#define signal_pending(x) _signal_pending()

#define __init
#define __exit
#define __force

#define current 0

#define kfree free

struct nlmsg {
	struct nlmsghdr nlm;
	char data[0];
};

struct sk_buff {
	struct msghdr hdr;
	int len;
	u32 pid;
	u32 dst_group;
	char data[0];		//struct nlmsg 
};

typedef void (*sk_buff_cb) (struct sk_buff * skb);

struct sock {
	int sk_socket;
	sk_buff_cb cb;
};

#define KERNEL_DS 0
extern void netlink_kernel_release(struct sock *sk);

typedef int mm_segment_t;

static inline mm_segment_t get_fs()
{
	return 1;
}

static inline void set_fs(mm_segment_t ds)
{
	return;
}

struct socket;

struct proto_ops {

	int (*getname) (struct socket * sock, struct sockaddr * addr,
			int *sockaddr_len, int peer);
	int (*bind) (struct socket * sock, struct sockaddr * myaddr,
		     int sockaddr_len);
	int (*setsockopt) (struct socket * sock, int level, int optname,
			   const void *optval, socklen_t optlen);
};

struct socket {
	struct sock *sk;
	struct proto_ops *ops;
	struct sock data[0];
};

struct net_device;

/* The struct ipv6hdr definition is taken from /usr/include/linux/ipv6.h
   because inclusion of linux/ipv6.h results in redefinition errors.
*/
/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 priority:4, version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 version:4, priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8 flow_lbl[3];

	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;

	struct in6_addr saddr;
	struct in6_addr daddr;
};

#define SK_REUSE_ADDR(sock) { int val = 1; setsockopt(sock->sk->sk_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));}

extern int sock_create(int family, int type, int proto, struct socket **res);

extern int sock_setsockopt(struct socket *sock, int level, int op,
			   char *optval, unsigned int optlen);

extern int sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags);
extern int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
extern void sock_release(struct socket *sock);

#define NETLINK_CB(skb) (*skb)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct netlink_callback {
	int args[1];
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct nlmsg nlm;
};

#define skb_tail_pointer(skb) NULL
#define skb_trim(skb, a)
#define NLMSG_NEW(skb, pid, seq, event, peer_size, flags) new_nlmsg(skb, pid, seq, event, peer_size, flags)
#define NLMSG_PUT(skb, pid, seq, type, len) \
        NLMSG_NEW(skb, pid, seq, type, len, 0)

#define MAX_RT_PRIO (sched_get_priority_max(SCHED_FIFO)+1)

struct completion {
	unsigned int done;
//wait_queue_head_t wait;
};

#define COMPLETION_INITIALIZER(work) \
   {0 /*,__WAIT_QUEUE_HEAD_INITIALIZER((work).wait)*/ }

#define DECLARE_COMPLETION(work) \
   struct completion work = COMPLETION_INITIALIZER(work)

struct work_struct;
typedef void (*work_func_t) (struct work_struct * work);

struct work_struct {
	long data;
	work_func_t func;
};

struct delayed_work {
	struct work_struct work;
	struct sigevent sev;
	timer_t timer_id;
	void *ctx;		// pointer to bfd_session 
	//struct timer_list timer;
};

struct workqueue_struct {

};

struct file {

};

typedef int (*init_func_t) (void);
typedef void (*exit_func_t) (void);

init_func_t get_init_func(void);
exit_func_t get_exit_func(void);

int init_module(void);
void exit_module(void);

#define module_init(func)                              \
   init_func_t get_init_func(void)                     \
   { return func;}                                     \
   int init_module(void) __attribute__((alias(#func)));

#define module_exit(func)                              \
   exit_func_t get_exit_func(void)                     \
   { return func;}                                     \
   void exit_module(void) __attribute__((alias(#func)));

#define MODULE_LICENSE(x) char *module_license=x

typedef int (*proc_write_t) (struct file *, const char *, unsigned long,
			     void *);
typedef int (*proc_read_t) (char *, char **, off_t, int, int *, void *);

struct proc_dir_entry {
	char *name;
	proc_write_t write_proc;
	proc_read_t read_proc;
};

struct dentry {
	char *name;
};

struct debugfs_blob_wrapper {
	void *data;
	unsigned long size;
};

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})

#define __user

#define jiffies get_jiffies()

extern unsigned long get_jiffies(void);

extern void uspin_lock(u_int32_t * lock);
extern struct workqueue_struct *create_singlethread_workqueue(char *name);

#define WQ_MEM_RECLAIM 1 << 3
#define WQ_HIGHPRI 1 << 4

extern struct workqueue_struct *alloc_workqueue(char *name, int flags,
						int max_active);

extern struct proc_dir_entry *proc_mkdir(char *name,
					 struct proc_dir_entry *parent);
extern struct proc_dir_entry *create_proc_entry(char *name, int flags, struct proc_dir_entry
						*parent);
extern void remove_proc_entry(const char *name, struct proc_dir_entry *parent);
extern void debugfs_remove_recursive(struct dentry *dentry);
extern struct dentry *debugfs_create_dir(const char *name,
					 struct dentry *parent);
extern struct dentry *debugfs_create_bool(const char *name, umode_t mode,
					  struct dentry *parent, u32 * value);
extern struct dentry *debugfs_create_blob(const char *name, mode_t mode,
					  struct dentry *parent,
					  struct debugfs_blob_wrapper *blob);

extern struct nlmsghdr *new_nlmsg(struct sk_buff *skb, u32 pid, u32 seq,
				  int event, size_t peer_size,
				  unsigned int flags);

extern void get_random_bytes(void *bytes, size_t sz);

extern int allow_signal(int signum);

extern int _signal_pending(void);

extern void rcu_read_lock(void);
extern void rcu_read_unlock(void);
extern void synchronize_rcu(void);

struct rt_mutex {
	int i;
};


extern void complete(struct completion *c);

void rt_mutex_lock(struct rt_mutex *lock);
bool rt_mutex_trylock(struct rt_mutex *lock);
void rt_mutex_unlock(struct rt_mutex *lock);

extern unsigned long usecs_to_jiffies(const unsigned int u);
extern unsigned int jiffies_to_msecs(const unsigned long j);
extern unsigned int jiffies_to_usecs(const unsigned long j);

extern bool delayed_work_pending(struct delayed_work *dwork);

extern bool queue_delayed_work(struct workqueue_struct *wq,
			       struct delayed_work *dwork, unsigned long delay);

extern bool cancel_delayed_work_sync(struct delayed_work *dwork);
extern bool cancel_delayed_work(struct delayed_work *dwork);

struct net {
	int i;
};

struct mutex {
	int i;
};


struct module {
	int i;
};

#define THIS_MODULE NULL


extern struct net init_net;

extern void destroy_workqueue(struct workqueue_struct *wq);

struct netlink_dump_control {
	int (*dump) (struct sk_buff * skb, struct netlink_callback *);
	int (*done) (struct netlink_callback *);
	void *data;
	u16 min_dump_alloc;
};

typedef int (*dump_fn) (struct sk_buff * skb, struct netlink_callback *);

typedef int gfp_t;

extern int netlink_broadcast(struct sock *sockfd, struct sk_buff *skb,
			     u32 pid, u32 group, gfp_t allocation);

extern int netlink_dump_start(struct sock *sockfd, struct sk_buff *skb,
			      const struct nlmsghdr *nlh,
			      struct netlink_dump_control *control);

extern struct sock *netlink_kernel_create(struct net *net, int unit,
					  unsigned int groups,
					  void (*input) (struct sk_buff *
							 skb),
					  struct mutex *cb_mutex,
					  struct module *module);

extern void INIT_DELAYED_WORK(struct delayed_work *work,
			      work_func_t timeout_fn, bool tx_work);
extern void delayed_work_free(struct delayed_work *work);

extern void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err);

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)(((char *)(skb)) + sizeof(*skb));
}

#define GFP_ATOMIC 0
#define GFP_KERNEL 1

static inline void *kmalloc(size_t size, int flags)
{
	return malloc(size);
}

static inline void *kzalloc(size_t size, int flags)
{
	return calloc(1, size);
}

extern unsigned char *skb_pull(struct sk_buff *skb, unsigned int len);

static inline struct sk_buff *alloc_skb(size_t size, int flag)
{
	struct sk_buff *retval = NULL;
	retval = malloc((sizeof(*retval) + size));
	return retval;
}

static inline int
ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

static inline void
ipv6_addr_set(struct in6_addr *addr, __be32 w1, __be32 w2, __be32 w3, __be32 w4)
{
	addr->s6_addr32[0] = w1;
	addr->s6_addr32[1] = w2;
	addr->s6_addr32[2] = w3;
	addr->s6_addr32[3] = w4;
}

unsigned short ip_fast_csum(unsigned char *buff, unsigned short len_ip_header);
unsigned short int csum_tcpudp_magic(unsigned long saddr, unsigned long daddr,
				     unsigned short len, unsigned short proto,
				     unsigned int sum);
unsigned int csum_partial(struct udphdr *buff, unsigned len, unsigned int sum);
__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr, __u32 len,
			unsigned short proto, __wsum sum);
// CSUM_MANGLED_0 is used when there is a chksum calculation and the value is 0
// on user space we don't calculate the chksum so we want it to be 0.
#define CSUM_MANGLED_0 ((__force __sum16)0)

#define KERN_DEBUG   
#define KERN_INFO    
#define KERN_NOTICE  
#define KERN_WARNING 
#define KERN_ERR     
int printk(const char *fmt, ...);


#define current_cpu -1
#endif				// KBFD_PROC_COMPAT_H
