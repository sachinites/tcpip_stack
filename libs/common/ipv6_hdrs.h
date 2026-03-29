#ifndef __INET_IPV6_HDRS_H
#define __INET_IPV6_HDRS_H

#include <stdint.h>
#include <memory.h>

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

static inline bool 
is_ipv6_addr_unspecified (uint8_t (*addr)[16]) {

    for (int i = 0; i < 16; i++) {
        if ((*addr)[i] != 0)
            return false;
    }
    return true;
}

static inline void 
 initialize_ipv6_hdr (ipv6_hdr_t *ipv6_hdr) {

    ipv6_hdr->version = 6;
    ipv6_hdr->traffic_class = 0;
    ipv6_hdr->flow_label = 0;
    ipv6_hdr->payload_length = 0;
    ipv6_hdr->next_header = 0;
    ipv6_hdr->hop_limit = 64;
    memset (ipv6_hdr->src_addr, 0, 16);
    memset (ipv6_hdr->dst_addr, 0, 16);
 }

#endif // __INET_IPV6_HDRS_H
