#ifndef IPV6_UTILS_H
#define IPV6_UTILS_H

#include "ipv6_hdrs.h"

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer);

void 
inet_pton6 (char *addr_str, ipv6_addr_t *addr);

#endif 