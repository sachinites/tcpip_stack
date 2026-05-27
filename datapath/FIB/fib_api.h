#ifndef __FIB_API__
#define __FIB_API__

#include "../../libs/BitOp/bitmap.h"
#include "fib_error.h"
#include "../../libs/mtrie/mtrie.h"
#include "../../libs/common/cmn_prefix.h"

typedef struct dp_vrf_ dp_vrf_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct fib_route_ fib_route_t;
typedef struct dp_ctx_ dp_ctx_t;

/**
 * =====================================================================================
 * 
 * FIB API Functions
 * 
 * This module provides key FIB (Forwarding Information Base) API functions including:
 * - Stride length retrieval based on AFI
 * - Packet destination extraction
 * - Nexthop forwarding operations
 * - Active nexthop selection for ECMP routes
 * =====================================================================================
 */


/* Get stride length based on AFI */
uint16_t afi_stride_len(AFI_T afi);

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(struct rte_mbuf *pkt, cmn_prefix_t *dest);

/* Perform actual forwarding based on next hop */
fib_error_t
fib_forward_pkt_to_nh(dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf, fib_nh_t *nh);

fib_nh_t* fib_get_active_nexthop(fib_route_t *route);

#endif

