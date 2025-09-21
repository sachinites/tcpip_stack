#ifndef __L4_LDRS__
#define __L4_LDRS__

#include <stdint.h>

#pragma pack (push,1)

typedef struct udp_hdr_ {

    uint16_t src_port_no;
    uint16_t dst_port_no;
    uint16_t udp_length;
    uint16_t udp_checksum;

} udp_hdr_t;

#pragma pack(pop)

#endif
