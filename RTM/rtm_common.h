#ifndef __RTM_CMN__
#define __RTM_CMN__

#include <stdint.h>
#include "rtm_enums.h"

typedef struct rtm_prefix_ {

    union {
        uint32_t v4_addr;
        uint8_t v6_addr[16];
    } u;

    uint8_t prefix_len;
    RTM_AFI_T afi;
    
    char pad[6];

} rtm_prefix_t;

#endif 