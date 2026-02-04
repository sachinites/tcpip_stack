#ifndef __SRV6_RTM__
#define __SRV6_RTM__

#include <stdint.h>
#include "../../../ipv6/ipv6_hdrs.h"
#include "../dp/srv6-endpoint.h"
#include "../../../../RTM/rtm_enums.h"

typedef struct node_ node_t;
class Interface;

/*
 * SRv6 RTM Integration Wrapper Functions
 * 
 * These functions provide a bridge between SRv6 module and the new RTM (Routing Table Manager).
 * They translate SRv6 route installation requests into RTM-compatible format.
 */

/**
 * @brief Install/Uninstall SRv6 route using new RTM
 * 
 * @param node Target node
 * @param prefix IPv6 prefix
 * @param prefix_len Prefix length
 * @param rt_flags Route flags (IPV6_LOCAL_RT or IPV6_REMOTE_RT)
 * @param gw Gateway IPv6 address (can be NULL)
 * @param oif Output interface (can be NULL)
 * @param segment_lst Segment list for SRv6 (can be NULL)
 * @param cost Metric/cost value
 * @param endfn SRv6 endpoint function
 * @param proto Protocol ID (RTM_PROTO_T)
 * @param install true to install, false to uninstall
 */
void
srv6_rtm_route_install (node_t *node,
                        ipv6_addr_t *prefix,
                        uint8_t prefix_len,
                        uint32_t rt_flags,
                        ipv6_addr_t *gw,
                        Interface* oif,
                        ipv6_addr_t (*segment_lst)[16],
                        uint32_t cost,
                        Srv6_endpcode_t endfn,
                        RTM_PROTO_T proto,
                        bool install);

#endif /* __SRV6_RTM__ */
