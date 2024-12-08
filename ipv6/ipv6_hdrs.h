#ifndef __INET_IPV6_HDRS_H
#define __INET_IPV6_HDRS_H

#include <stdint.h>

typedef struct ipv6_addr_ {
    uint8_t addr[16];
} ipv6_addr_t;


#pragma pack (push,1)
typedef struct ipv6_hdr_ {


    uint32_t version:4;
    uint32_t traffic_class:8;
    uint32_t flow_label:20;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];

} ipv6_hdr_t;
#pragma pack(pop)




#endif // __INET_IPV6_HDRS_H
