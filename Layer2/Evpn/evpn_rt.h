#ifndef __EVPN_RT__
#define __EVPN_RT__

#include <stdint.h>
#include "../../libs/Tree/libtree.h"
#include "../../vrf/vrf.h"
#include "evpn_enums.h"
#include "../../libs/common/cmn_struct.h"
#include "../../libs/common/cmn_prefix.h"

#pragma pack(push, 8)

#define EVPN_RT_F_LOCAL  1
#define EVPN_RT_F_REMOTE 2

typedef struct evpn_rt_ {

    /* What is route type */
    evpn_rt_type_t type;

    /* Advertising VTEP */
    uint32_t vtep_ip;

    uint8_t flags;

    union {

        struct {

            /* Mac Addr of the host */
            mac_addr_t mac;
            uint16_t _pad;
            uint32_t ip_addr;
            uint32_t label;

        } mac_only; /* Type 2 */

        struct {

            uint32_t pe_addr;
            uint32_t evpn_label;

        } imet;  /* Type 3 */

        /* Route type 5 will go in RTM */
    } u;

} evpn_rt_t;


#pragma pack(pop)


typedef struct node_ node_t;

void
evpn_route_export_to_bgp(node_t *node,
                         rd_t *rd,
                         rt_t *export_rt,
                         evpn_rt_t *evpn_rt,
                         bool is_delete);

#endif