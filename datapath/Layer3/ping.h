#ifndef __PING__
#define __PING__

#include <stdint.h>
#include <semaphore.h>
#include "../../libs/common/cmn_prefix.h"

#define PING_MAX_SEQ        256     /* max simultaneously outstanding echo requests */
#define PING_DEF_TIMEOUT_S  2       /* per-probe reply timeout in seconds */

/* ICMP message types */
#define ICMP_ECHO_REP       0
#define ICMP_DEST_UNREACH   3
#define ICMP_ECHO_REQ       8
#define ICMP_TIME_EXCEEDED  11
#define ICMP_PARAM_PROBLEM  12

/* ICMP Destination Unreachable codes (type 3) */
#define ICMP_NET_UNREACH    0   /* Network Unreachable                        */
#define ICMP_HOST_UNREACH   1   /* Host Unreachable                           */
#define ICMP_PROTO_UNREACH  2   /* Protocol Unreachable                       */
#define ICMP_PORT_UNREACH   3   /* Port Unreachable                           */
#define ICMP_FRAG_NEEDED    4   /* Fragmentation Needed and DF Bit Set        */
#define ICMP_SR_FAILED      5   /* Source Route Failed                        */
#define ICMP_NET_UNKNOWN    6   /* Destination Network Unknown                */
#define ICMP_HOST_UNKNOWN   7   /* Destination Host Unknown                   */
#define ICMP_HOST_ISOLATED  8   /* Source Host Isolated                       */
#define ICMP_NET_ANO        9   /* Network Administratively Prohibited        */
#define ICMP_HOST_ANO       10  /* Host Administratively Prohibited           */
#define ICMP_NET_UNR_TOS    11  /* Network Unreachable for TOS                */
#define ICMP_HOST_UNR_TOS   12  /* Host Unreachable for TOS                   */
#define ICMP_PKT_FILTERED   13  /* Communication Administratively Prohibited  */
#define ICMP_PREC_VIOLATION 14  /* Host Precedence Violation                  */
#define ICMP_PREC_CUTOFF    15  /* Precedence Cutoff in Effect                */

/* ICMP Time Exceeded codes (type 11) */
#define ICMP_EXC_TTL        0   /* TTL Exceeded in Transit                    */
#define ICMP_EXC_FRAGTIME   1   /* Fragment Reassembly Time Exceeded          */

#pragma pack(push, 1)
typedef struct icmp_hdr_ {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq_no;
} icmp_hdr_t;
#pragma pack(pop)

/* Forward declarations */
struct pkt_block_;

/* This ping context is used to track the icmp echo request sent
    and their icmp echo reply recvd. It must track all info that 
    is required to compute ping stats such as RTT which is min, 
    max and avg. */

typedef struct ping_ctx_ {

    /* Sender context */
    dp_ctx_t        *dp_ctx;                  /* DP CTX initiating the ping */
    uint16_t         vrf_id;                  /* VRF to route pings through */

    /* Ping endpoints */
    cmn_prefix_t    dst;                      /* destination address (v4 or v6) */
    cmn_prefix_t    src;                      /* source address */

    /* ICMP echo header fields */
    uint16_t        identifier;               /* ICMP identifier (e.g. PID) */
    uint16_t        seq_no;                   /* next sequence number to send */

    /* Probe control */
    uint32_t        count;                    /* total probes requested */
    uint32_t        sent;                     /* echo requests sent so far */
    uint32_t        received;                 /* echo replies received */

    /* RTT statistics - all in microseconds */
    uint32_t        rtt_min;
    uint32_t        rtt_max;
    uint64_t        rtt_sum;                  /* accumulated sum for avg computation */

    /* Per-probe send timestamps (us since epoch), indexed by seq_no % PING_MAX_SEQ */
    uint64_t        send_time[PING_MAX_SEQ];

    /* Synchronisation: ping_send4 blocks here; ping_echo_reply_recvd posts */
    sem_t           reply_sem;
    sem_t           cli_unblock_sem;
    pthread_t       *ping_thread;

} ping_ctx_t;


void 
ping_send4 (ping_ctx_t *pctx);

void 
ping_echo_reply_recvd (ping_ctx_t *pctx, struct pkt_block_ *pkt_block);


#endif 
