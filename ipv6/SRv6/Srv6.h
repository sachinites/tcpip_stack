#ifndef __SRv6_H
#define __SRv6_H

#include <stdint.h>

#pragma pack (push,1)
typedef struct srh_hdr_ {

    uint8_t nexthdr;
    uint8_t hdrlen;
    uint8_t type;
    uint8_t segments_left;
    uint8_t first_segment;
    uint8_t flags;
    uint16_t tag;
    uint8_t segments[16][16];
    
} srh_hdr_t;
#pragma pack(pop)

#endif // __SRv6_H