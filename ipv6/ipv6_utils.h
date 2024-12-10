#ifndef IPV6_UTILS_H
#define IPV6_UTILS_H

#include "ipv6_hdrs.h"
#include "SRv6/SRv6-EndPoint.h"

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer);

void 
inet_pton6 (char *addr_str, ipv6_addr_t *addr);

const char *
end_fn_str(Srv6_endpcode_t end_fn);

const char *
flavor_str(uint8_t flavors);

#endif 