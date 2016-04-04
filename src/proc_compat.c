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

#include "proc_compat.h"
#include "kbfd_log.h"
#include <assert.h>
#include <stdarg.h> 

#define NL_MSG_MAX_SIZE 1024

static int random_fd = -1;

struct net init_net = { 0 };

static pthread_t wait_thread;

static struct sock nl_sock = { -1, NULL };

static int
getname_ip(struct socket *sock, struct sockaddr *addr,
	   int *sockaddr_len, int peer)
{

	return getpeername(sock->sk->sk_socket, addr,
			   (socklen_t *) sockaddr_len);
}

static int
bind_ip(struct socket *sock, struct sockaddr *myaddr, int sockaddr_len)
{

	return bind(sock->sk->sk_socket, myaddr, sockaddr_len);
}

static int
setsockopt_ip(struct socket *sock, int level, int optname,
	      const void *optval, socklen_t optlen)
{

	return setsockopt(sock->sk->sk_socket, level, optname, optval, optlen);
}

static struct proto_ops ip_ops = {.getname = getname_ip,.bind =
	    bind_ip,.setsockopt = setsockopt_ip
};

int sock_create(int family, int type, int proto, struct socket **res)
{
	int ret = 0;

	*res = malloc(sizeof(struct socket) + sizeof(struct sock));
	(*res)->sk = (*res)->data;
	(*res)->ops = &ip_ops;

	if ((ret = socket(family, type, proto)) < 0) {
		free(*res);
		return ret;
	}
	(*res)->sk->sk_socket = ret;
	return ret;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	free(wq);
}

bool cancel_delayed_work_sync(struct delayed_work *dwork)
{
	struct itimerspec its;
	bool ret = false;

	ret = delayed_work_pending(dwork);
	// stop the timer
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;
	if (timer_settime(dwork->timer_id, 0, &its, NULL) == -1)
		printf("timer_settime failed\n");
	return ret;

}

bool cancel_delayed_work(struct delayed_work * dwork)
{
	return cancel_delayed_work_sync(dwork);
}

bool delayed_work_pending(struct delayed_work * dwork)
{
	struct itimerspec its;

	// stop the timer
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;
	if (timer_gettime(dwork->timer_id, &its) == -1) {
		printf("timer_gettime failed\n");
		return false;
	}
	return (its.it_value.tv_sec > 0);
}

bool
queue_delayed_work(struct workqueue_struct * wq, struct delayed_work * dwork,
		   unsigned long delay)
{
	struct itimerspec its;

	// start the timer
	its.it_value.tv_sec = (delay / 1000000);
	its.it_value.tv_nsec = ((delay % 1000000) * 1000);
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;
	if (timer_settime(dwork->timer_id, 0, &its, NULL) == -1)
		return false;
	return true;
}

void rcu_read_lock(void)
{

}

void rcu_read_unlock(void)
{

}

void synchronize_rcu(void)
{

}

void complete(struct completion *c)
{

}

bool rt_mutex_trylock(struct rt_mutex *lock)
{
   bool ret = true;

   return ret;
}

void rt_mutex_lock(struct rt_mutex *lock)
{

}

void rt_mutex_unlock(struct rt_mutex *lock)
{

}


unsigned long usecs_to_jiffies(const unsigned int u)
{

	return u;
}

unsigned int jiffies_to_msecs(const unsigned long j)
{

	return j;
}

unsigned int jiffies_to_usecs(const unsigned long j)
{

	return j;
}

struct workqueue_struct *create_singlethread_workqueue(char *name)
{
	struct workqueue_struct *retval = NULL;
	retval = malloc(sizeof(struct workqueue_struct));
	return retval;
}

struct workqueue_struct *alloc_workqueue(char *name, int flags, int max_active)
{
	struct workqueue_struct *retval = NULL;
	retval = malloc(sizeof(struct workqueue_struct));
	return retval;
}

struct dentry *debugfs_create_bool(const char *name, umode_t mode,
				   struct dentry *parent, u32 * value)
{
	struct dentry *retval = NULL;

	return retval;
}

struct dentry *debugfs_create_blob(const char *name, mode_t mode,
				   struct dentry *parent,
				   struct debugfs_blob_wrapper *blob)
{
	struct dentry *retval = NULL;

	return retval;
}

struct dentry *debugfs_create_dir(const char *name, struct dentry *parent)
{
	struct dentry *retval = NULL;

	return retval;
}

void debugfs_remove_recursive(struct dentry *dentry)
{

}

struct proc_dir_entry *proc_mkdir(char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry *retval = NULL;

	return retval;
}

void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{

}

struct proc_dir_entry *create_proc_entry(char *name, int flags,
					 struct proc_dir_entry *parent)
{
	struct proc_dir_entry *retval = NULL;

	return retval;
}

static void *wait_func(void *arg)
{
	int retval = 0;
	int i, len, err;
	struct timespec ts;
	char buffer[NL_MSG_MAX_SIZE];
	struct iovec iov[1];
	struct msghdr msg;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	sigset_t mask;
	fd_set read_fd;

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	// proc mask
	sigemptyset(&mask);
	sigaddset(&mask, SIG_TX);
	sigaddset(&mask, SIG_RX_EXP);
	if (pthread_sigmask(SIG_BLOCK, &mask, NULL) == -1) {
		printf("\n sigprocmask failed: %d!\n", errno);
		fflush(stdout);
		assert(0);
	}

	FD_ZERO(&read_fd);
	FD_SET(nl_sock.sk_socket, &read_fd);

	for (i = 0;; i++) {
		err = pselect(1, &read_fd, NULL, NULL, &ts, &mask);
		if (err == -1) {
			if (errno == EINTR) {
				//continue;
			} else {
				printf("pselect failed: %d\n", errno);
				fflush(stdout);
				exit(1);
			}
		}

		memset(&msg, 0, sizeof(msg));
		memset(iov, 0, sizeof(iov));
		iov[0].iov_base = buffer;
		iov[0].iov_len = sizeof(buffer);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;

		len = recvmsg(nl_sock.sk_socket, &msg, 0);
		if (len <= 0) {
			printf("len < 0");
			fflush(stdout);
			continue;
		}
		skb = alloc_skb(len, 0);
		nlh = nlmsg_hdr(skb);
		memcpy(nlh, buffer, len);
		skb->len = len;
		if (nlh->nlmsg_type != 26)
			printf("nlh type: %d len:%d\n", nlh->nlmsg_type, len);
		fflush(stdout);
		nl_sock.cb(skb);
		free(skb);
	}

	return (void *)retval;
}

void netlink_kernel_release(struct sock *sk)
{
	close(sk->sk_socket);
}

struct sock *netlink_kernel_create(struct net *net, int unit,
				   unsigned int groups,
				   void (*input) (struct sk_buff * skb),
				   struct mutex *cb_mutex,
				   struct module *module)
{
	nl_sock.sk_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_sock.sk_socket < 0)
		return NULL;

	struct sockaddr_nl netlinkAddr = { AF_NETLINK, 0, 0, 1 };
	if (bind
	    (nl_sock.sk_socket, (struct sockaddr *)&netlinkAddr,
	     sizeof(netlinkAddr))) {
		printf("netlink_create failed...\n");
		goto err;
	}
	nl_sock.cb = input;

	if (pthread_create(&wait_thread, NULL, wait_func, NULL))
		goto err;

	return &nl_sock;

 err:
	close(nl_sock.sk_socket);
	nl_sock.sk_socket = -1;
	nl_sock.cb = NULL;
	return NULL;
}

int
netlink_dump_start(struct sock *sockfd, struct sk_buff *skb,
		   const struct nlmsghdr *nlh,
		   struct netlink_dump_control *control)
{

	int retval = 0;

	return retval;
}

void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err)
{

}

int
netlink_broadcast(struct sock *sockfd, struct sk_buff *skb, u32 pid,
		  u32 group, gfp_t allocation)
{

	int retval = 0;
	struct sockaddr_nl netlinkAddr = { AF_NETLINK, 0, 0, group };
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nl_msg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&netlinkAddr;
	msg.msg_namelen = sizeof(netlinkAddr);

	nl_msg = nlmsg_hdr(skb);
	iov.iov_base = (void *)nl_msg;
	iov.iov_len = nl_msg->nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	retval = sendmsg(sockfd->sk_socket, &msg, 0);
	return retval;
}

struct nlmsghdr *new_nlmsg(struct sk_buff *skb, u32 pid, u32 seq, int event,
			   size_t peer_size, unsigned int flags)
{
	struct nlmsghdr *nlh = NULL;

	nlh = nlmsg_hdr(skb);
	nlh->nlmsg_type = event;
	nlh->nlmsg_len = peer_size;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;
	return nlh;
}

unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	unsigned char *retval = NULL;

	skb->len = 0;
	return retval;
}

int
sock_setsockopt(struct socket *sock, int level, int op, char *optval,
		unsigned int optlen)
{
	return setsockopt(sock->sk->sk_socket, level, op, optval, optlen);
}

int
sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	return recvmsg(sock->sk->sk_socket, msg, flags);
}

int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	return sendmsg(sock->sk->sk_socket, msg, 0);
}

void sock_release(struct socket *sock)
{
	close(sock->sk->sk_socket);
}

void get_random_bytes(void *bytes, size_t num)
{
	if (random_fd >= 0) {
		read(random_fd, bytes, num);
	} else {
		memset(bytes, 0, num);
	}
}

int allow_signal(int signum)
{

	sigset_t sigs;

	sigfillset(&sigs);
	sigdelset(&sigs, signum);
	return pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}

int _signal_pending(void)
{
	sigset_t sigs;
	int i;
	sigemptyset(&sigs);
	sigpending(&sigs);
	if (!sigisemptyset(&sigs)) {
		for (i = 1; i <= 32; i++) {
			if (sigismember(&sigs, i) && (i != SIG_TX)
			    && (i != SIG_RX_EXP)) {
				return 1;
			}
		}
	}
	return 0;
}

unsigned long get_jiffies(void)
{
	unsigned long retval = 0;

	return retval;
}

void bfd_timeout_fn(int sig, siginfo_t * siginfo, void *ctx)
{
	struct delayed_work *dwork;
	timer_t *timer_id;

	timer_id = (timer_t *) siginfo->si_value.sival_ptr;
	dwork = container_of(timer_id, struct delayed_work, timer_id);

	// call the corresponding timeout func
	dwork->work.func(&dwork->work);
}

void
INIT_DELAYED_WORK(struct delayed_work *work, work_func_t timeout_fn,
		  bool tx_work)
{
	struct sigevent sev;
	int sig;

	if (tx_work) {
		sig = SIG_TX;
	} else {
		sig = SIG_RX_EXP;
	}

	work->work.func = timeout_fn;
	// create a timer
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = sig;
	sev.sigev_value.sival_ptr = &work->timer_id;
	if (timer_create(CLOCK_MONOTONIC, &sev, &work->timer_id) == -1) {
		printf("\n timer_create failed: %d!\n", errno);
		fflush(stdout);
		assert(0);
	}
}

void delayed_work_free(struct delayed_work *work)
{
	// TBD more cleanup ?
	timer_delete(work->timer_id);
}

int main(int argc, char *argv[])
{

	struct sigaction sa;

	random_fd = open("/dev/urandom", O_RDONLY);
	openlog("BFD", LOG_CONS | LOG_PERROR, LOG_USER);

	// set up a sigaction for the proces 
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = bfd_timeout_fn;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIG_TX, &sa, NULL) == -1) {
		printf("\n sigaction failed: %d!\n", errno);
		fflush(stdout);
		assert(0);
	}
	if (sigaction(SIG_RX_EXP, &sa, NULL) == -1) {
		printf("\n sigaction failed: %d!\n", errno);
		fflush(stdout);
		assert(0);
	}

	init_module();
	printf("\n Waiting for thread join !\n");
	fflush(stdout);
	pthread_join(wait_thread, NULL);
	printf("\n Done waiting for threaf join!\n");
	fflush(stdout);

	// exit_module();

	close(random_fd);

	exit(0);
}

unsigned short ip_fast_csum(unsigned char *buff, unsigned short len_ip_header)
{
	unsigned sum = 0;
	int i;
	len_ip_header *= 4;
	/* Accumulate checksum */
	for (i = 0; i < len_ip_header - 1; i += 2) {
		unsigned short word16 = *(unsigned short *)&buff[i];
		sum += word16;
	}
        /* ip header is always even but just making sure this function is
         * not changed and used without taking care of odd-sized case */
        assert( len_ip_header % 2 == 0 );
	/* Fold to get the ones-complement result */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	/* Invert to get the negative in ones-complement arithmetic */
	return (unsigned short)~sum;
}

unsigned short int csum_tcpudp_magic(unsigned long saddr, unsigned long daddr,
				     unsigned short len, unsigned short proto,
				     unsigned int sum)
{
	return 0;
}

unsigned int csum_partial(struct udphdr *buff, unsigned len, unsigned int sum)
{
	return 0;
}

__sum16 csum_ipv6_magic(const struct in6_addr * saddr,
			const struct in6_addr * daddr, __u32 len,
			unsigned short proto, __wsum sum)
{
	return 0;
}

int printk(const char *fmt, ...)
{
   // There is very little that can be done from an interrupt context
   // which is the case where this function might be called on a 
   // namespace dut.  We write to the output if tracing is enabled
   // which is the Bfd agent output file.
   va_list args;
   va_start (args, fmt);
   vprintf (fmt, args);
   va_end (args);
   return 0;
}

