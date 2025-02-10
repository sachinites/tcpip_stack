#ifndef __NP_RT_TABLE__
#define __NP_RT_TABLE__

typedef struct dp_msg_ dp_msg_t;
typedef struct node_ node_t;
typedef struct rt_table_ rt_table_t;

class Interface;

#include "../../Layer3/SegmentRouting/SRv6/dp/srv6-endpoint.h"
#include "../../Layer3/ipv6/ipv6_hdrs.h"

#include <stdint.h>

void 
np_rt_table_process_msg(node_t *node, dp_msg_t *dp_msg);

void
np_rt6_table_process_msg(node_t *node, dp_msg_t *dp_msg) ;

 bool
 dp_ipv6_route_install (node_t *node,
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                uint8_t rt_flags,
                                ipv6_addr_t *gw,
                                Interface* oif,   // can be NULL
                                uint32_t spf_metric,
                                Srv6_endpcode_t endfn,
                                uint16_t proto ) ;

 bool
 dp_ipv6_route_uninstall (node_t *node,
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                ipv6_addr_t *gw,
                                Interface* oif,
                                uint16_t proto_id);

void
dp_ipv6_clear_rt_table_sync (rt_table_t *rt_table, uint16_t proto_id, bool del_static);

void
dp_ipv6_clear_rt_table_async (node_t *node, uint16_t proto_id);

#endif 
