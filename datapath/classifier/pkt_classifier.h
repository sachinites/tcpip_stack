#ifndef __PKT_CLASSIFIER__
#define __PKT_CLASSIFIER__

#include <stdint.h>
#include "../../libs/common/cmn_prefix.h"
#include "../../libs/common/protoIds.h"

typedef struct event_dispatcher_ event_dispatcher_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct pkt_q_ pkt_q_t;
struct rte_mbuf;

#pragma pack(push, 8)

typedef struct pkt_class_ {

    cmn_prefix_t src_ip;
    cmn_prefix_t dst_ip;
    uint32_t ifindex;

    uint16_t sub_proto;
    uint16_t vlan_id;
    uint16_t eth_proto;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t ip_proto;
    uint8_t ipv6_proto;
    
} pkt_class_t;

typedef struct trap_rule_ {

    uint16_t  id;

    uint16_t proto; /* L2 or L3 Proto*/

    bool (*trap_fn)(struct rte_mbuf *);

    void (*trap_app_cbk)(void *cp_ctx, struct rte_mbuf *mbuf);

    event_dispatcher_t *ev_dis;
    pkt_q_t *pkt_q;

    bool consume;

    uint32_t trap_count;

    struct trap_rule_ *next;

} trap_rule_t;

#pragma pack(pop)

pkt_class_t
dp_pkt_classify (struct rte_mbuf *mbuf);

void
dp_pkt_trap_l2(dp_ctx_t *dp_ctx, 
               trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
               struct rte_mbuf *mbuf);

void
dp_pkt_trap_l3(dp_ctx_t *dp_ctx, 
               trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
               struct rte_mbuf *mbuf);

void
dp_trap_rule_install (trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
                      trap_rule_t *trap_rule);

void
dp_trap_rule_uninstall (trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
                        trap_rule_t *trap_rule);

#endif 