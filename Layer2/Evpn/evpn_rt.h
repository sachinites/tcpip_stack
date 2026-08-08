#ifndef __EVPN_RT__
#define __EVPN_RT__

#include <stdint.h>
#include "../../../libs/Tree/libtree.h"
#include "../../vrf/vrf.h"
#include "evpn_enums.h"
#include "../../../libs/common/cmn_struct.h"
#include "../../../libs/common/cmn_prefix.h"

#pragma pack(push, 8)

typedef struct evpn_rt_ {

    /* What is route type */
    evpn_rt_type_t type;

    /* Which protocol learned this route : 
        1. via EVPN_CP ( BGP )
        2. via Flood and Learn (Data Plane)
        3. via Static Configuration */
    evpn_proto_t proto;

    /* Advertising VTEP */
    cmn_prefix_t vtep_ip;

    /* Import route targets for this route */
    rt_t route_targets[8];

    /* Flags to track RT status */
    uint16_t flags;  

    union {

        struct {

            /* Mac Addr of the host */
            mac_addr_t mac;

            /* Associated L2 VNI and BD ID */
            uint32_t l2vni;
            uint16_t bd_id;

        } mac_only; /* Type 2 */

        struct {

            /* Mac Addr of the host */
            mac_addr_t mac;

            /* Associated L2 VNI and BD ID */
            uint32_t l2vni;
            uint16_t bd_id;
            uint32_t l3vni;

            /* IP Address of the host */
            cmn_prefix_t ip;

            /* VTEPs RTR MAC */
            mac_addr_t vtep_rmac;

        } mac_ip; /* Type 2 */

        struct {

            /* Associated L2 VNI and BD ID */
            uint32_t l2vni;
            uint16_t bd_id;

        } imet;  /* Type 3 */

        struct {

            /* Later */

        } l3_prefix; /* Type 5 */

    } u;

    avltree_node_t avl_glue_mac_vrf_rib; /* Glue to MAC VRF RIB*/
    avltree_node_t avl_glue_ip_vrf_rib; /* Glue to IP VRF RIB*/
    avltree_node_t avl_glue_imet_rib; /* Glue to VTEP RIB*/
    avltree_node_t avl_glue_imported_routes; /* Glue to imported routes tree*/
    avltree_node_t avl_glue_exported_routes; /* Glue to exported routes tree */

    } evpn_rt_t;


#pragma pack(pop)

#endif