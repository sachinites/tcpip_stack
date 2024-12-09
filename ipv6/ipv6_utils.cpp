
#include <stdio.h>
#include <arpa/inet.h>
#include "ipv6_utils.h"

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer) {

    sprintf(buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
            ntohs(addr->addr[0]),
            ntohs(addr->addr[1]),
            ntohs(addr->addr[2]),
            ntohs(addr->addr[3]),
            ntohs(addr->addr[4]),
            ntohs(addr->addr[5]),
            ntohs(addr->addr[6]),
            ntohs(addr->addr[7]));

    return buffer;
}

void 
inet_pton6  (char *addr_str, ipv6_addr_t *addr) {

    inet_pton(AF_INET6, addr_str, &addr->addr);
}