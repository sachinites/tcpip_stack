#ifndef IPV6_UTILS_H
#define IPV6_UTILS_H

#include "ipv6_hdrs.h"

typedef struct bitmap_ bitmap_t;

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer);

void 
inet_pton6 (char *addr_str, ipv6_addr_t *addr);

void 
ipv6_auto_generate_link_local_address(
        unsigned char(*mac)[6], uint8_t (*link_local_addr)[16]);

bool ipv6_address_is_subnet(uint8_t (*prefix)[16], uint8_t prefix_len, 
                                                uint8_t (*prefix_to_be_checked)[16]) ;

void
ipv6_copy_bitmap (uint8_t (*v6_addr)[16], bitmap_t *bm);

#endif 