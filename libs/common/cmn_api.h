#ifndef __CMN_API__
#define __CMN_API__

#include <stdint.h>
#include "../LinuxMemoryManager/uapi_mm.h"
#include "protoIds.h"
#include "../pkt-block/pkt_block.h"

static inline unsigned char *
tcp_ip_get_new_pkt_buffer(uint32_t pkt_size){

    if (pkt_size > (MAX_PACKET_BUFFER_SIZE - PKT_BUFFER_RIGHT_ROOM)) return NULL;
    unsigned char *pkt = (unsigned char *)XCALLOC_BUFF(0, MAX_PACKET_BUFFER_SIZE);
    return pkt + MAX_PACKET_BUFFER_SIZE - (pkt_size + PKT_BUFFER_RIGHT_ROOM);
}

static inline void
tcp_ip_free_pkt_buffer(unsigned char *pkt, uint32_t pkt_size){

    XFREE(pkt - (MAX_PACKET_BUFFER_SIZE - pkt_size - PKT_BUFFER_RIGHT_ROOM));
}


#endif 