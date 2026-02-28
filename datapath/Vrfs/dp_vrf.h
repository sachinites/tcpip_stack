#ifndef __DP_VRF__
#define __DP_VRF__

#include <stdint.h>
#include "../../common/cmn_prefix.h"

typedef struct fib_ fib_t;
typedef struct hashtable hashtable_t;
typedef struct arp_table_ arp_table_t;
typedef struct dp_ctx_ dp_ctx_t;

#pragma pack(push, 8)

typedef struct dp_vrf_ {

    /* VRF id*/
    uint8_t vrf_id;
    /* VRF name, for logging purpose*/
    char vrf_name[32];
    /* inet6.0 FIB*/
    fib_t *fib_inet0;
    /* inet6.0 FIB*/
    fib_t *fib_inet6;  
    /* Mpls fib */
    fib_t *fib_mpls0;
    /* ARP table */
    arp_table_t *arp_table;

} dp_vrf_t;


typedef struct dp_vrf_create_msg_ {

    uint8_t vrf_id;
    char vrf_name[32];
    
} dp_vrf_create_msg_t;

#define DP_VRF_INTF_OP_ADD 1
#define DP_VRF_INTF_OP_DEL 2
typedef struct dp_vrf_intf_update_msg_ {

    uint32_t op_code;
    uint8_t vrf_id;
    uint32_t ifindex;
    
} dp_vrf_intf_update_msg_t;

#pragma pack(pop)

void 
dp_init_vrf_hashtable (hashtable_t **ht);

dp_vrf_t *
dp_look_up_vrf (hashtable_t *ht, uint8_t vrf_id);

void
dp_insert_vrf (hashtable_t *ht, dp_vrf_t *vrf);

void
dp_delete_vrf (dp_ctx_t *dp_ctx, hashtable_t *ht, uint8_t vrf_id) ;

dp_vrf_t *
dp_create_vrf (
               hashtable_t *ht, 
               char *vrf_name, uint8_t vrf_id) ;

fib_t *
dp_look_up_fib_by_name (dp_ctx_t *dp_ctx, char *vrf_name, char *fib_name);

static inline fib_t *
dp_vrf_fib_get(dp_vrf_t *vrf, AFI_T afi) {

    switch(afi) {
        case AF_IPV4:
            return vrf->fib_inet0;
        case AF_IPV6:
            return vrf->fib_inet6;
        case AF_LABEL:
            return vrf->fib_mpls0;
    }

    return NULL;
}

#endif 
