#ifndef  __ISIS_IPS_STRUCT__ 
#define __ISIS_IPS_STRUCT__ 

/* IPS for Advertisising FRR information */
#include <stdint.h>
#include <stdbool.h>
#include "isis_struct.h"

#define ISIS_PVT_IPS_CODE_FRR_ENABLE 1
#define ISIS_PVT_IPS_CODE_FRR_LINK_PROTECTION 2
#define ISIS_PVT_IPS_CODE_FRR_NODE_PROTECTION 3
#define ISIS_PVT_IPS_CODE_FRR_NODE_LINK_DEGRADATION 4
#define ISIS_PVT_IPS_CODE_FRR_ENABLE_RLFA 5
#define ISIS_PVT_IPS_CODE_FRR_USE_SPRING    6
#define ISIS_PVT_IPS_CODE_FRR_TILFA 7

typedef struct isis_ips_frr_config_ {

    uint8_t code;
    bool enable;
    char padding[6];

    isis_system_id_t system_id;

    union {

        /* Node Protection */
        uint32_t rtr_id;
        uint8_t pn_no;
        char padding1[3];

        /* Link Protection */
        uint32_t ifindex;

        /* Global ISIS FRR enable / disable */
        bool frr_enable;

        /* Node link degradation*/
        bool node_link_degradation;

        /* Enable RLFA*/
        bool rlfa;

        /* Enable SPRING */
        bool use_spring;

        /* Enable TILFA */
        bool tilfa;

        char padding2[7];
        
    } u;

} isis_ips_frr_config_t;


#endif 