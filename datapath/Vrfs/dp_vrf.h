/*
 * =============================================================================
 * File: dp_vrf.h
 * Description: Datapath VRF (dp_vrf_t) and VRF table APIs.
 * =============================================================================
 *
 * Design:
 *   - Each VRF has vrf_id, name, and FIBs (IPv4, IPv6, MPLS) plus ARP table.
 *   - VRF table: fixed array indexed by vrf_id (see DP_MAX_VRF).
 *   - dp_vrf_fib_get: return the appropriate FIB for an AFI (IPv4/IPv6/label).
 *   - Message structs for VRF create and interface add/delete to VRF.
 * =============================================================================
 */

#ifndef __DP_VRF__
#define __DP_VRF__

#include <stdint.h>
#include <cstddef>
#include "../../libs/common/cmn_prefix.h"
#include "../Interface/intf_cons.h"

typedef struct fib_ fib_t;
typedef struct arp_table_ arp_table_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;

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

#pragma pack(pop)

void
dp_init_vrf_table (dp_ctx_t *dp_ctx);

dp_vrf_t *
dp_look_up_vrf (dp_ctx_t *dp_ctx, int16_t vrf_id);

void
dp_insert_vrf (dp_ctx_t *dp_ctx, dp_vrf_t *vrf);

void
dp_delete_vrf (dp_ctx_t *dp_ctx, uint8_t vrf_id);

dp_vrf_t *
dp_create_vrf (dp_ctx_t *dp_ctx,
               const char *ctx_name,
               char *vrf_name, uint8_t vrf_id);

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

arp_table_t *
dp_vrf_get_arp_cache (dp_ctx_t *dp_ctx, char *vrf);

#endif /* __DP_VRF__ */
