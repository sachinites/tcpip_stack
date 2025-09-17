#ifndef __CMN_STRUCT__
#define __CMN_STRUCT__

#include <stdint.h>

#define MAC_ADDR_SIZE   6
#define IPV4_ADDR_LEN_STR   16


#pragma pack (push,1)


typedef struct ip_add_ {
    unsigned char ip_addr[IPV4_ADDR_LEN_STR];
} ip_add_t;

typedef struct mac_addr_ {
    unsigned char mac[MAC_ADDR_SIZE];
} mac_addr_t;


#pragma pack(pop)


#endif 
