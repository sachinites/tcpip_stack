#ifndef __DP_VRF__
#define __DP_VRF__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct fib_ fib_t;
typedef struct hashtable hashtable_t;

#pragma pack(push, 8)

typedef struct dp_vrf_ {

    uint8_t vrf_id;

    char vrf_name[32];
    /* inet6.0 FIB*/
    fib_t *fib_inet0;
    /* inet6.0 FIB*/
    fib_t *fib_inet6;  
    /* Mpls fib */
    fib_t *mpls_fib;

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
dp_delete_vrf (node_t *node, hashtable_t *ht, uint8_t vrf_id) ;

dp_vrf_t *
dp_create_vrf (node_t *node, 
               hashtable_t *ht, 
               char *vrf_name, uint8_t vrf_id) ;

#endif 