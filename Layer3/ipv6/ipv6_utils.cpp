
#include <stdio.h>
#include <arpa/inet.h>
#include "ipv6_utils.h"
#include "../../tcpconst.h"

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer) {

    inet_ntop(AF_INET6, &addr->addr, buffer, INET6_ADDRSTRLEN);
    return buffer;
}

void 
inet_pton6  (char *addr_str, ipv6_addr_t *addr) {

    inet_pton(AF_INET6, addr_str, &addr->addr);
}

/* Given MAC Address as an Input, generate link local address */
void 
ipv6_auto_generate_link_local_address(
        unsigned char (*mac)[6], uint8_t (*link_local_addr)[16]) {

    (*link_local_addr)[0] = 0xFE;
    (*link_local_addr)[1] = 0x80;
    (*link_local_addr)[2] = 0x00;
    (*link_local_addr)[3] = 0x00;
    (*link_local_addr)[4] = 0x00;
    (*link_local_addr)[5] = 0x00;
    (*link_local_addr)[6] = 0x00;
    (*link_local_addr)[7] = 0x00;
    (*link_local_addr)[8] = (*mac)[0] ^ 0x02;
    (*link_local_addr)[9] = (*mac)[1];
    (*link_local_addr)[10] = (*mac)[2];
    (*link_local_addr)[11] = 0xFF;
    (*link_local_addr)[12] = 0xFE;
    (*link_local_addr)[13] = (*mac)[3];
    (*link_local_addr)[14] = (*mac)[4];
    (*link_local_addr)[15] = (*mac)[5];
}

/* Returns true if the ipv6 address 'prefix' lies in subnet of 'locator'/prefix_len */
bool ipv6_address_is_subnet(uint8_t (*prefix)[16], uint8_t prefix_len, 
                                                uint8_t (*prefix_to_be_checked)[16]) {
    // The number of full bytes we need to consider based on prefix_len
    uint8_t full_bytes = prefix_len / 8;
    uint8_t remaining_bits = prefix_len % 8;

    // Compare the full bytes first
    if (memcmp(*prefix_to_be_checked, *prefix, full_bytes) != 0) {
        return false; // The full byte parts do not match
    }

    // If there are remaining bits, mask them and compare
    if (remaining_bits > 0) {
        uint8_t mask = 0xFF << (8 - remaining_bits);
        if (( (*prefix_to_be_checked)[full_bytes] & mask) != ((*prefix)[full_bytes] & mask)) {
            return false; // The remaining bits do not match
        }
    }

    // If all the checks passed, the locator is within the subnet
    return true;
}