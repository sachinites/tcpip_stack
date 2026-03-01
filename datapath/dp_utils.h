#ifndef __DP_UTILS__
#define __DP_UTILS__


typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;

#include <stdint.h>
#include <cstddef>

#include "../tcpconst.h"
#include "../LinuxMemoryManager/uapi_mm.h"

dp_intf_t *
dp_intf_get_matching_subnet_interface(dp_ctx_t *dp_ctx,
                                      dp_vrf_t *vrf,
                                      uint32_t ip_addr);

                                      
#endif