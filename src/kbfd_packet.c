/* 
 *  BFD packet handling routine
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
#include <linux/workqueue.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/completion.h>
#include <linux/delay.h>
#else
#include "proc_compat.h"
#endif

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_log.h"
#include "kbfd_netlink.h"
#include "kbfd.h"

void bfd_update_tx_sched_delay(struct bfd_session *bfd)
{
	int sched_delay = 0;
	if (bfd && bfd->sec_last_sched_jiff != 0) {
		sched_delay =
		    jiffies_to_usecs(jiffies - bfd->sec_last_sched_jiff);
		if (sched_delay < bfd->act_tx_intv) {
			bfd->lateness[0]++;
		} else if (sched_delay < (bfd->act_tx_intv * 2)) {
			bfd->lateness[1]++;
		} else if (sched_delay < (bfd->act_tx_intv * 3)) {
			bfd->lateness[2]++;
		} else {
			bfd->lateness[3]++;
		}
		bfd->sec_last_sched_jiff = 0;
	}
}

int bfd_send_ctrl_packet(struct bfd_session *bfd)
{
	u_int32_t tx_intv = 0;
	int len = -1;
	int (*xmit) (struct bfd_session *) =
	    bfd->proto->xmit_packet[bfd->session_type];
	if (IS_DEBUG_CTRL_PACKET) {
		blog_info("Called bfd_send_ctrlPacket");
	}

	if (!xmit)
		goto finish;

	bfd_update_tx_sched_delay(bfd);
	len = xmit(bfd);

	if (len <= 0)
		goto finish;

	/* timestamp last ctrl pkt send time */
	if (!bfd->cpkt.final) {
		// Skip the statistics calculation when bfd->cpkt.final is set
		// because this packet might not be scheduled and could skew the
		// statistics calculation
		if (bfd->tx_last_jiff != 0) {
			tx_intv =
			    jiffies_to_msecs(bfd->tx_jiff - bfd->tx_last_jiff);
			if (tx_intv < bfd->tx_min || bfd->tx_min == 0)
				bfd->tx_min = tx_intv;
			if (tx_intv > bfd->tx_max)
				bfd->tx_max = tx_intv;
			bfd->tx_sum += tx_intv;
			bfd->tx_n++;
		}		/* else skip stat calculation for first packet */
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info
			    ("tx_jiff: %lu, tx_last_jiff: %lu, tx_intv: %u, pkt_out: %llu",
			     bfd->tx_jiff, bfd->tx_last_jiff, tx_intv,
			     bfd->pkt_out);
		}
		bfd->tx_last_jiff = bfd->tx_jiff;
	}
	/* Packet Count */
	bfd->pkt_out++;
	/* force final bit set to 0 */
	bfd->cpkt.final = 0;

 finish:
	return len;
}

int
bfd_recv_echo_packet(struct bfd_proto *proto, struct sockaddr *src,
		     struct sockaddr *dst, int ifindex, char *buffer, int len)
{
	struct bfd_echo_packet *epkt;
	struct bfd_session *bfd;
	char buf[256];

	if (IS_DEBUG_CTRL_PACKET)
		blog_info("RECV<=: Echo Pkt from %s, iif=%d",
			  proto->addr_print(src, buf), ifindex);

	epkt = (struct bfd_echo_packet *)buffer;

	if ((bfd = bfd_session_lookup(proto, epkt->my_disc, 0, NULL, 0)) == NULL) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info
			    ("couldn't find session with Discriminator %d. Discarded",
			     epkt->my_disc);
		}
		return -1;
	}
#ifdef __KERNEL__
	if (GET_ECHO_PRIV_FIELD(bfd, echo_start))
		bfd_reset_echo_expire_timer(bfd);
#endif

	bfd_session_release(bfd, SESSION_FIND);
	return 0;
}
static inline void
reset_rx_tx_defer(struct bfd_session *bfd)
{
   bfd->tx_reset_deferred = bfd->rx_reset_deferred = NULL;
}

static inline void
check_tx_reset_defer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
   bfd->tx_reset_deferred = NULL;
   if (cpu_tx_ident(bfd) && tx_work_busy(bfd)){
      /*
       * The tx timeout work function is ready to execute
       * or has already started to execute but has been
       * preempted by the real time rx thread - wait for
       * the tx timeout function to complete.
       */
      bfd->tx_reset_deferred = current;
   }
#endif
}

static inline void
check_packet_work_defer(struct bfd_session *bfd)
{
#ifdef __KERNEL__
   bfd->rx_reset_deferred = NULL;
   if (cpu_rx_ident(bfd) && rx_work_busy(bfd)){
      /*
       * The tx timeout work function is ready to execute
       * or has already started to execute but has been
       * preempted by the real time rx thread - wait for
       * the tx timeout function to complete.
       */
      bfd->rx_reset_deferred = current;
   }
#endif
}

static inline void
bfd_reset_tx_timer_defer(struct bfd_session *bfd)
{
        check_tx_reset_defer(bfd);
        bfd_reset_tx_timer(bfd);
}


int
bfd_recv_ctrl_packet(struct bfd_proto *proto, int vrf_fd, struct sockaddr *src,
		     struct sockaddr *dst, int ifindex, char *buffer, int len)
{
	struct bfd_ctrl_packet *cpkt;
	struct bfd_session *bfd, *lag_bfd;
	char buf[256];
	int poll_seq_end = 0;
	unsigned long rx_jiff;
	u_int32_t rx_intv = 0;
	u_int32_t old_detect_time;

	if (IS_DEBUG_CTRL_PACKET)
		blog_info("RECV<=: Ctrl Pkt from %s, iif=%d",
			  proto->addr_print(src, buf), ifindex);

	cpkt = (struct bfd_ctrl_packet *)buffer;

	/* Section 6.7.6 check */

	/* If the version number is not correct (1), the packet MUST be */
	/* discarded. */
	if (cpkt->version != BFD_VERSION_1) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info("version isn't 1. Discarded");
		}
		return -1;
	}

	/* If the Length field is less than the minimum correct value (24 if */
	/* the A bit is clear, or 26 if the A bit is set), the packet MUST be */
	/* discarded. */
	if ((!cpkt->auth && cpkt->length < BFD_CTRL_LEN) ||
	    (cpkt->auth && cpkt->length < BFD_CTRL_AUTH_LEN)) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_warn("length is short. Discarded");
		}
		return -1;
	}

	/* If the Length field is greater than the payload of the */
	/* encapsulating protocol, the packet MUST be discarded. */
	if (cpkt->length > len) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_warn("length is too long. Discarded. %d>%d",
				  cpkt->length, len);
		}
		return -1;
	}

	/* If the Detect Mult field is zero, the packet MUST be discarded. */
	if (cpkt->detect_mult == 0) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_warn("Detect Multi field is zero. Discarded");
		}
		return -1;
	}

	/* If the My Discriminator field is zero, the packet MUST be discarded. */
	if (cpkt->my_disc == 0) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_warn("My Discriminator field is zero. Discarded");
		}
		return -1;
	}

	/* If the Your Discriminator field is nonzero, it MUST be used to */
	/* select the session with which this BFD packet is associated.  If */
	/* no session is found, the packet MUST be discarded. */
	if (cpkt->your_disc) {
		if ((bfd =
		     bfd_session_lookup(proto, cpkt->your_disc, 0, NULL,
					0)) == NULL) {
			if (IS_DEBUG_CTRL_PACKET) {
				blog_info
				    ("couldn't find session with Discriminator field. Discarded");
			}
			return -1;
		}
	} else {
		/* If the Your Discriminator field is zero and the State field is not
		   Down or AdminDown, the packet MUST be discarded. */
		if (cpkt->state != BSM_AdminDown && cpkt->state != BSM_Down) {
			if (IS_DEBUG_CTRL_PACKET) {
				blog_warn
				    ("Received state is not Down or AdminDown. Discarded");
			}
			return -1;
		}

		/* If the Your Discriminator field is zero, the session MUST be
		   selected based on some combination of other fields, possibly
		   including source addressing information, the My Discriminator
		   field, and the interface over which the packet was received.  The
		   exact method of selection is application-specific and is thus
		   outside the scope of this specification.  If a matching session is
		   not found, a new session may be created, or the packet may be
		   discarded.  This choice is outside the scope of this
		   specification. */
		bfd = bfd_session_lookup(proto, 0, vrf_fd, src, 0);
		if (bfd && bfd->session_type == BFD_LAG_SESSION) {
			lag_bfd = bfd;
			bfd = bfd_micro_session_lookup(lag_bfd, ifindex);
			bfd_session_release(lag_bfd, SESSION_FIND);
		}
		if (!bfd) {
			if (IS_DEBUG_CTRL_PACKET) {
				blog_info
				    ("couldn't find session without Discriminator field. Discarded");
				blog_info("src %s",
					  proto->addr_print(src, buf));
			}
			return -1;
		}
	}

	/* timestamp last ctrl pkt receive time */
	if (!cpkt->poll) {
		// If receiving a packet with poll bit set, skip the statistics
		// calculation
		rx_jiff = jiffies;
		if (bfd->rx_last_jiff != 0) {
			rx_intv = jiffies_to_msecs(rx_jiff - bfd->rx_last_jiff);
			if (rx_intv < bfd->rx_min || bfd->rx_min == 0)
				bfd->rx_min = rx_intv;
			if (rx_intv > bfd->rx_max)
				bfd->rx_max = rx_intv;
			bfd->rx_sum += rx_intv;
			bfd->rx_n++;
		}		/* skip stat calculation for first packet */
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info
			    ("rx_jiff: %lu, rx_last_jiff: %lu, rx_intv: %u, pkt_in: %llu",
			     rx_jiff, bfd->rx_last_jiff, rx_intv, bfd->pkt_in);
		}
		bfd->rx_last_jiff = rx_jiff;
	}

	/* save the latest received ctrl packet */
	memcpy(&bfd->rpkt, cpkt, sizeof(struct bfd_ctrl_packet));

	/* mark our address */
	memcpy(bfd->src, dst, bfd->proto->namelen(dst));
	/* Packet Count */
	bfd->pkt_in++;

	/* If the A bit is set and no authentication is in use (bfd.AuthType
	   is zero), the packet MUST be discarded.
	   If the A bit is clear and authentication is in use (bfd.AuthType
	   is nonzero), the packet MUST be discarded. */
	if (cpkt->auth != bfd->cpkt.auth) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info("Auth type isn't same. Discarded");
		}
		bfd_session_release(bfd, SESSION_FIND);
		return -1;
	}

	/* If the A bit is set, the packet MUST be authenticated under the
	   rules of section 6.6, based on the authentication type in use
	   (bfd.AuthType.)  This may cause the packet to be discarded. */
	if (cpkt->auth) {
		if (IS_DEBUG_CTRL_PACKET) {
			blog_info("Packet has Authentication");
		}
		/* FIXME authentication process */
	}

	/* Set bfd.RemoteDiscr to the value of My Discriminator. */
	bfd->cpkt.your_disc = cpkt->my_disc;

	/* If the Required Min Echo RX Interval field is zero, the
	   transmission of Echo packets, if any, MUST cease. */
#ifdef __KERNEL__
	if (GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv) !=
	    ntohl(cpkt->req_min_echo_rx_intv)) {

                if (!SET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv,
                                         ntohl(cpkt->req_min_echo_rx_intv))) {
                   
                   SET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv, 0);
                   SET_ECHO_PRIV_FIELD(bfd, echo_detect_time, 0);
                   bfd_stop_echo(bfd);
                } else {
                   
                   long tx, rx;
                   
                   tx = ntohl(bfd->cpkt.des_min_tx_intv);
                   rx = GET_ECHO_PRIV_FIELD(bfd, peer_echo_rx_intv);

                   tx = SET_ECHO_PRIV_FIELD(bfd, act_echo_tx_intv, tx<rx?rx:tx);
                   SET_ECHO_PRIV_FIELD(bfd, echo_detect_time, 
                                       bfd->cpkt.detect_mult*tx);
        
                   if (bfd_start_echo(bfd)) {
                      
                      bfd_reset_echo_tx_timer(bfd);
                      bfd_reset_echo_expire_timer(bfd);
                   }
                }
        }


#endif

	/* If Demand mode is active, a Poll Sequence is being transmitted by
	   the local system, and the Final (F) bit in the received packet is
	   set, the Poll Sequence MUST be terminated. */
	/* FIXME */

	/* If Demand mode is not active, the Final (F) bit in the received
	   packet is set, and the local system has been transmitting packets
	   with the Poll (P) bit set, the Poll (P) bit MUST be set to zero in
	   subsequent transmitted packets. */
	/* permit session from loopback interface */
	if (!bfd->cpkt.demand && cpkt->final
	    && (bfd->cpkt.poll || (ifindex == 1))) {
		bfd->cpkt.poll = 0;
		poll_seq_end = 1;
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD Poll Sequence is done.");

		bfd->act_tx_intv =
		    ntohl(bfd->cpkt.des_min_tx_intv) <
		    ntohl(cpkt->
			  req_min_rx_intv) ? ntohl(cpkt->req_min_rx_intv) :
		    ntohl(bfd->cpkt.des_min_tx_intv);
		bfd->act_rx_intv = ntohl(bfd->cpkt.req_min_rx_intv);
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD resetting tx/rx stats.");
		bfd_reset_tx_stats(bfd);
		bfd_reset_rx_stats(bfd);
	}
        
	/* Update the active transmit interval if the peer's min_rx has
	 * changed and either a poll sequence has not been initiated on the 
	 * local side or the active transmit interval will decrease as a
	 * result of the peer's min_rx change (per Sec 6.8.3 ).
	 */

	if (!bfd->cpkt.demand && cpkt->poll &&
	    (bfd->peer_rx_intv != ntohl(cpkt->req_min_rx_intv))) {

		int act_tx_intv =
		    ntohl(bfd->cpkt.des_min_tx_intv) <
		    ntohl(cpkt->
			  req_min_rx_intv) ? ntohl(cpkt->req_min_rx_intv) :
		    ntohl(bfd->cpkt.des_min_tx_intv);

		if (!bfd->cpkt.poll || (act_tx_intv < bfd->act_tx_intv)) {

			bfd->act_tx_intv = act_tx_intv;

			if (IS_DEBUG_CTRL_PACKET)
				blog_info("BFD resetting tx stats.");
			bfd_reset_tx_stats(bfd);
		}
	}

	/* Update the Detection Time as described in section 6.7.4. */
	old_detect_time = bfd->detect_time;
	bfd->detect_time = cpkt->detect_mult *
	    (bfd->act_rx_intv > ntohl(cpkt->des_min_tx_intv) ?
	     bfd->act_rx_intv : ntohl(cpkt->des_min_tx_intv));
	if (bfd->detect_time != old_detect_time) {
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD resetting rx stats.");
		bfd_reset_rx_stats(bfd);
	}

	bfd->peer_tx_intv = ntohl(cpkt->des_min_tx_intv);
	bfd->peer_rx_intv = ntohl(cpkt->req_min_rx_intv);
	bfd->peer_mult = cpkt->detect_mult;

	/* Update the transmit interval as described in section 6.7.2. */
	if (poll_seq_end) {
		bfd_reset_tx_timer_defer(bfd);
	}
	bfd->last_rcv_req_rx = cpkt->req_min_rx_intv;

	/* If bfd.SessionState is AdminDown */
	if (bfd->cpkt.state == BSM_AdminDown) {
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD State is AdminDown. Discarded");
		bfd_session_release(bfd, SESSION_FIND);
                reset_rx_tx_defer(bfd);
		return -1;
	}

	/* If received state is AdminDown
	   If bfd.SessionState is not Down
	   Set bfd.LocalDiag to 3 (Neighbor signaled session down)
	   Set bfd.SessionState to Down */
	if (cpkt->state == BSM_AdminDown) {
		if (bfd->cpkt.state != BSM_Down) {
			bfd->cpkt.diag = BFD_DIAG_NBR_SESSION_DOWN;
		}
	}


        check_packet_work_defer(bfd);
	if (cpkt->state == BSM_Down) {
		bfd_bsm_event(bfd, BSM_Recived_Down);
	} else if (cpkt->state == BSM_Init) {
		bfd_bsm_event(bfd, BSM_Recived_Init);
	} else if (cpkt->state == BSM_Up) {
		bfd_bsm_event(bfd, BSM_Recived_Up);
	}

	/* If the Demand (D) bit is set and bfd.DemandModeDesired is 1,
	   and bfd.SessionState is Up, Demand mode is active. */
	if (cpkt->demand && bfd->cpkt.demand && bfd->cpkt.state == BSM_Up) {
		bfd->demand = 1;
	}
	/* If the Demand (D) bit is clear or bfd.DemandModeDesired is 0,
	   or bfd.SessionState is not Up, Demand mode is not
	   active. */
	else {
		bfd->demand = 0;
	}

	/* If the Poll (P) bit is set, send a BFD Control packet to the
	   remote system with the Poll (P) bit clear, and the Final (F) bit
	   set. */
	if (cpkt->poll) {
		/* Store old p-bit */
		u_char old_poll_bit = bfd->cpkt.poll;

		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD: Poll Sequence inprogress");

		bfd->cpkt.poll = 0;
		bfd->cpkt.final = 1;
                bfd_reset_tx_timer_defer(bfd);
		bfd_send_ctrl_packet(bfd);
		bfd->cpkt.poll = old_poll_bit;
	}

	/* If the packet was not discarded, it has been received for purposes
	   of the Detection Time expiration rules in section 6.7.4. */
	if (IS_DEBUG_CTRL_PACKET)
		blog_info("BFD: Detect Time is %d(usec)", bfd->detect_time);

	if (bfd->cpkt.state == BSM_Up || bfd->cpkt.state == BSM_Init) {
           bfd_reset_expire_timer(bfd);
	}

        reset_rx_tx_defer(bfd);
	bfd_session_release(bfd, SESSION_FIND);

	return 0;
}
