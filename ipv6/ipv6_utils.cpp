
#include <stdio.h>
#include <arpa/inet.h>
#include "ipv6_utils.h"
#include "../tcpconst.h"
#include "SRv6/Srv6.h"

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
