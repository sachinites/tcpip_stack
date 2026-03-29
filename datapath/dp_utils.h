/*
 * =============================================================================
 * File: dp_utils.h
 * Description: Datapath utility APIs (e.g. subnet / interface lookup).
 * =============================================================================
 *
 * Design:
 *   - Provides helpers used across DP and CP for interface selection and
 *     address handling.
 *   - dp_intf_get_matching_subnet_interface: returns the local interface
 *     whose configured subnet contains the given IPv4 address (used e.g. for
 *     ARP and next-hop resolution).
 * =============================================================================
 */

#ifndef __DP_UTILS__
#define __DP_UTILS__

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;

#include <stdint.h>
#include <cstddef>

#include "../tcpconst.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

/**
 * dp_intf_get_matching_subnet_interface - Find interface whose subnet contains ip_addr
 * @dp_ctx:   Datapath context
 * @vrf:     VRF to search
 * @ip_addr: IPv4 address (host byte order)
 *
 * Uses FIB to resolve a connected/local route for ip_addr; if found, returns
 * the outgoing interface for that route. Returns NULL if no matching subnet.
 */
dp_intf_t *
dp_intf_get_matching_subnet_interface(dp_ctx_t *dp_ctx,
                                      dp_vrf_t *vrf,
                                      uint32_t ip_addr);

#endif /* __DP_UTILS__ */
