#ifndef __FIB_API__
#define __FIB_API__

#include "fib.h"
#include "fib_common.h"
#include "fib_nh.h"
#include "../BitOp/bitmap.h"
#include "../mtrie/mtrie.h"

/* Convert FIB prefix to bitmap format for mtrie operations */
void fib_prefix_to_bitmap(fib_prefix_t *prefix, bitmap_t *bm_prefix, bitmap_t *bm_mask);

/* Convert bitmap back to FIB prefix format */
void bitmap_to_fib_prefix(bitmap_t *bm_prefix, bitmap_t *bm_mask, uint16_t prefix_len, fib_prefix_t *prefix);

/* Get stride length based on AFI */
uint16_t fib_get_stride_len_from_afi(FIB_AFI_T afi);

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(pkt_block_t *pkt, fib_prefix_t *dest);

/* Perform actual forwarding based on next hop */
fib_error_t fib_forward_pkt_to_nh(fib_t *fib, pkt_block_t *pkt, fib_nh_t *nh);

/* Free route data callback for mtrie */
void fib_route_free_callback(mtrie_node_t *node);

/* Convert prefix to string for display */
void fib_prefix_to_str(fib_prefix_t *prefix, char *buffer, int buf_size);

/* Get AFI name as string */
const char *fib_afi_to_str(FIB_AFI_T afi);

/* Get MPLS operation name as string */
const char *fib_mpls_op_to_str(fib_mpls_op_t op);

#endif

