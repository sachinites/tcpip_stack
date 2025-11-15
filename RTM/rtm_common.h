#ifndef __RTM_CMN__
#define __RTM_CMN__

#include <stdint.h>
#include "rtm_enums.h"
#pragma pack(push, 8)

typedef struct rtm_prefix_ {

    union {
        uint32_t v4_addr;
        uint16_t v6_addr[8];
        uint32_t mpls_label;
        uint8_t mac_addr[6];
    } u;

    uint8_t prefix_len;
    RTM_AFI_T afi;

} rtm_prefix_t;


typedef struct label_ {

    uint32_t label_val;
    mpls_op_t op;

} label_t; 

#define MAX_LBL_DEPTH 8

typedef struct lstack_ {

    uint8_t curr_index;
    label_t labels[MAX_LBL_DEPTH];

} lstack_t;

#pragma pack(pop)

bool rtm_prefix_is_null (rtm_prefix_t *prefix);

#endif 