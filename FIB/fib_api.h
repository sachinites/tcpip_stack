#ifndef __FIB_API__
#define __FIB_API__

#include "../BitOp/bitmap.h"
#include "fib_error.h"
#include "../mtrie/mtrie.h"
#include "../common/cmn_prefix.h"

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct fib_route_ fib_route_t;

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
uint16_t fib_get_stride_len_from_afi(AFI_T afi);

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(pkt_block_t *pkt, cmn_prefix_t *dest);

/* Perform actual forwarding based on next hop */
fib_error_t
fib_forward_pkt_to_nh(node_t *node, pkt_block_t *pkt_block, fib_nh_t *nh);

fib_nh_t* fib_get_active_nexthop(fib_route_t *route);

#endif

