/*
 * =============================================================================
 * File: fib.h
 * Description: Forwarding Information Base (FIB) - LPM/label lookup and nexthops.
 * =============================================================================
 *
 * Design:
 *   - fib_t: per-VRF, per-AFI (IPv4/IPv6/MPLS); holds either an LPM mtrie or
 *     a label hashtable, plus a global AVL tree of nexthops.
 *   - fib_init, fib_destroy, fib_get, fib_get_by_name: lifecycle and lookup.
 *   - fib_show: display FIB for CLI/debugging.
 * =============================================================================
 */

#ifndef __FIB__
#define __FIB__

#include <stdint.h>
#include "../../libs/Tree/libtree.h"
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"

#include "fib_error.h"
#include "../../RTM/rtm_fib_common.h"

typedef struct atomic_mtrie_ atomic_mtrie_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct node_ node_t;
typedef struct dp_vrf_ dp_vrf_t;


#pragma pack(push, 8)

typedef struct fib_ {

    /* Key type of this FIB*/
    AFI_T afi;
    uint8_t vrf_id;
    char name[96];

    union {
        /* IF the key of the FIB is v4 or V6*/
        struct {
           atomic_mtrie_t *lpm;
           Fglthread_t rt_lst_head;
        }rts;

        /* IF the key of the Fib is MPLS Label*/
        hashtable_t *label_ht;
    }u;

    /* Global Tree of all Nexthops in this FIB,
        keyed by all fields */
    avltree_t nhs;

} fib_t;

#pragma pack(pop)

fib_t* fib_init (dp_vrf_t *vrf, AFI_T afi, uint8_t vrf_id);
void fib_show(fib_t *fib);
fib_t *fib_get (dp_ctx_t *dp_ctx, AFI_T afi, uint8_t vrf_id);
void fib_destroy (fib_t*fib);
fib_t* fib_get_by_name (dp_ctx_t *dp_ctx, char *fib_name);

#endif /* __FIB__ */
