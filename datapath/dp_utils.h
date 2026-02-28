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


static inline unsigned char *
dp_get_new_pkt_buffer(uint32_t pkt_size){

    if (pkt_size > (MAX_PACKET_BUFFER_SIZE - PKT_BUFFER_RIGHT_ROOM)) return NULL;
    unsigned char *pkt = (unsigned char *)XCALLOC_BUFF(0, MAX_PACKET_BUFFER_SIZE);
    return pkt + MAX_PACKET_BUFFER_SIZE - (pkt_size + PKT_BUFFER_RIGHT_ROOM);
}

static inline void
dp_free_pkt_buffer(unsigned char *pkt, uint32_t pkt_size){

    XFREE(pkt - (MAX_PACKET_BUFFER_SIZE - pkt_size - PKT_BUFFER_RIGHT_ROOM));
}

#endif