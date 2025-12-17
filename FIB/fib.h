#ifndef __FIB__
#define __FIB__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

#include "fib_error.h"
#include "../RTM/rtm_fib_common.h"

typedef struct mtrie_ mtrie_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct node_ node_t;

#pragma pack(push, 8)

typedef struct fib_ {

    /* Key type of this FIB*/
    AFI_T afi;
    uint8_t vrf_id;

    union {
        /* IF the key of the FIB is v4 or V6*/
        mtrie_t *lpm;

        /* IF the key of the Fib is MPLS Label*/
        hashtable_t *label_ht;
    }u;

    /* Global Tree of all Nexthops in this FIB,
        keyed by all fields */
    avltree_t nhs;

} fib_t;
#pragma pack(pop)

fib_t* fib_init (AFI_T afi, uint8_t vrf_id);
fib_error_t fib_forward (node_t *node, pkt_block_t *pkt, uint8_t vrf_id);
void fib_show(fib_t *fib);

#endif 
