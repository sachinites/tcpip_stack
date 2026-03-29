/*
 * =============================================================================
 * File: fib_nh.h
 * Description: FIB nexthop (fib_nh_t) and forwarding info (oif, prefix, MPLS/SRv6).
 * =============================================================================
 *
 * Design:
 *   - fib_nh_fwd_info_t: oif, nexthop prefix, fwd_flags; union for MPLS label stack
 *     or SRv6 segment list.
 *   - fib_nh_t: reference-counted nexthop with fwd_info and AVL glue for FIB.
 *   - fib_get_forwarding_nh: LPM lookup returns nexthop for a prefix.
 *   - fib_nh_reference / fib_nh_dereference, fib_nh_create, fib_register_nh, fib_nh_lookup.
 * =============================================================================
 */

#ifndef __FIB_NH__
#define __FIB_NH__

#include <stdint.h>
#include "../../libs/Tree/libtree.h"
#include "../../RTM/rtm_fib_common.h"
#include "../../libs/common/mpls_lstack.h"

typedef struct fib_ fib_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct dp_intf_ dp_intf_t;

#pragma pack(push, 8)

typedef struct fib_nh_fwd_info_ {

    dp_intf_t  *oif;                 /* offset 0, size 16, naturally 8-byte aligned */
    cmn_prefix_t nh_addr;           /* offset 16, size 24 */
    uint32_t fwd_flags;             /* offset 40, size 4 */
    uint32_t _pad1;                 /* padding to align union to 8 bytes */

    union {
        
        /*MPLS  Label Stack*/
        struct {
            mpls_lstack_t label_stack;
        } mpls_fwd;

        /*SRv6 Stack*/
        struct {    
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            uint8_t v6segment_lst[MAX_LBL_DEPTH][16];
        } v6_fwd;

    }u;                             /* offset 48, now 8-byte aligned */

}  fib_nh_fwd_info_t;

typedef struct fib_nh_ {

    fib_nh_fwd_info_t *fwd_info;
    avltree_node_t idx_glue;
    uint32_t hit_count;
    uint32_t ref_count;

} fib_nh_t;

#pragma pack(pop)

void fib_nh_reference (fib_nh_t *nh);
void fib_nh_dereference (fib_t *fib, fib_nh_t *nh);
fib_nh_t* fib_nh_create (fib_t *fib, fib_nh_t *nh_template);
void fib_register_nh(fib_t *fib, fib_nh_t *nh);
fib_nh_t* fib_nh_lookup (fib_t *fib, fib_nh_t *nh_template);
fib_nh_t *fib_get_forwarding_nh(fib_t *fib, cmn_prefix_t *route);

#endif /* __FIB_NH__ */