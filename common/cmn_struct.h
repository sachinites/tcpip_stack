#ifndef __CMN_STRUCT__
#define __CMN_STRUCT__

#include <stdint.h>

#pragma pack (push,1)


typedef struct ip_add_ {
    unsigned char ip_addr[16];
} ip_add_t;

typedef struct mac_addr_ {
    unsigned char mac[6];
} mac_addr_t;


#pragma pack(pop)


#endif 
