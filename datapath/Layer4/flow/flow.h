#ifndef __FLOW_H__
#define __FLOW_H__

#include <stdint.h>
#include "../../../libs/common/cmn_prefix.h"

#pragma pack(push, 8)

typedef struct flow_key_ {

    uint16_t src_port;
    uint16_t dst_port;
    cmn_prefix_t src_addr;
    cmn_prefix_t dst_addr;
    uint8_t ip_protocol;

} flow_key_t;

/*
 * TCP states for a stateful firewall sitting between two hosts.
 *
 * RFC 793 states are defined per endpoint; after the first FIN, one side may
 * be FIN_WAIT_* while the other is CLOSE_WAIT at the same time. A single field
 * cannot represent both accurately—track per-direction FIN/ACK (or initiator vs
 * responder state) if you need strict RFC behavior.
 *
 * Handshake seen at the midpoint (I = initiator of first SYN, R = peer):
 *   - SYN from I only                          -> SYN_SENT
 *   - SYN-ACK from R (Ack == isn_I + 1)        -> SYN_RECV
 *   - ACK from I (Ack == isn_R + 1), 3rd leg   -> ESTABLISHED
 *
 * Teardown: drive FIN_WAIT_* from the side that sent FIN first; CLOSE_WAIT /
 * LAST_ACK from the peer. CLOSING covers simultaneous close. TIME_WAIT (or a
 * long post-close timeout) avoids dropping late ACKs/FIN retransmits.
 *
 * RST: typically treat as immediate CLOSED (or INVALID). LISTEN is a host
 * stack state; per 5-tuple flows usually start at SYN_SENT, not LISTEN.
 */
typedef enum tcp_state_ {

    TCP_STATE_CLOSED,       /* No session or torn down (timeout, RST, both sides done) */
    TCP_STATE_SYN_SENT,     /* Saw SYN from initiator; SYN-ACK not yet validated */
    TCP_STATE_SYN_ACK_SENT, /* Saw SYN-ACK from responder; 3rd-leg ACK not yet seen */
    TCP_STATE_ESTABLISHED,  /* Handshake complete; data may flow */
    TCP_STATE_FIN_WAIT_1,   /* Local side sent FIN, waiting ACK of that FIN */
    TCP_STATE_FIN_ACK_SENT, /* FIN ACKed by peer; waiting peer's FIN */
    TCP_STATE_CLOSE_WAIT,   /* Peer sent FIN; application close not yet sent */
    TCP_STATE_LAST_ACK_SENT,     /* Local FIN sent after CLOSE_WAIT; waiting final ACK */
    TCP_STATE_CLOSING_SENT,      /* Both FINs seen; waiting final ACK (simultaneous close) */
    TCP_STATE_TIME_WAIT_SENT,    /* 2MSL wait after active close; allow straggler segments */

} flow_tcp_state_t;

typedef enum tcp_event_ {

    TCP_EVENT_SYN_SEEN,     /* SYN pkt seen from initiator */
    TCP_EVENT_SYN_ACK_SEEN, /* SYN-ACK pkt seen from responder */
    TCP_EVENT_3_ACK_SEEN,   /* ACK pkt seen from initiator */
    TCP_EVENT_FIN_WAIT_1_SEEN,
    TCP_EVENT_FIN_WAIT_2_SEEN,
    TCP_EVENT_LAST_ACK_SEEN,

} flow_tcp_event_t;


typedef struct flow_ {

    flow_key_t key;
    uint64_t pkt_src_to_dst;
    uint64_t pkt_dst_to_src;

    union {

        flow_tcp_state_t state;

    } tcp_state;

} flow_t; 

#pragma pack(pop)


#endif 