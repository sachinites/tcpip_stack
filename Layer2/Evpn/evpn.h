#ifndef __EVPN__
#define __EVPN__

#include <stdint.h>
#include "../../../libs/common/cmn_prefix.h"
#include "../../../libs/Tree/libtree.h"
#include "../../vrf/vrf.h"

typedef struct rtm_ rtm_t;

#if 0
/* CLI to install static EVPN routes directly in Datapath */
config node <node-name> protocol evpn mac-route <MAC> nexthop <nexthop-ip> evi <evi-id>  
config node <node-name> protocol evpn imet-route <ip> evi <evi-id>
config node <node-name> protocol evpn ip-prefix <ip/mask> nexthop <nexthop-ip> evi <evi-id>

#endif 


/*

bgpd
    │
    │  (best EVPN route)
    ▼

  EVPN Import Manager
    │
    │ 
    ▼
EVPN L2RIBs

    │

    ├── MAC VRFs
    │       ├── MAC-only
    │       ├── MAC-IP
    │       └── IMET
    │
    └── IP VRFs
            ├── MAC-IP
            └── Type-5
*/

/* This structure is populated using below configuration 

evpn
  vni 5010 l2
    rd auto
    route-target import 65501:10
    route-target export 65501:10
  vni 5020 l2
    rd auto
    route-target import 65501:20
    route-target export 65501:20
*/
typedef struct mac_vrf_ {

    uint32_t l2vni;  /* Key */

    rd_t rd;  /* Route Distinguisher */
    rt_t import_rt;  /* Import Route Target */
    rt_t export_rt;  /* Export Route Target */

    /* MAC VRF RIB ( All MAC-only/MAC-IP routes will go here ) */
    avltree_t mac_vrf_rib;

    /* All Type 3 routes will do here to build BUM 
        replication list, route will be dtored using 
        evpn_rt_t->avl_glue_imet_rib */
    avltree_t imet_rib;
    
} mac_vrf_t;

typedef struct ip_vrf_ {

    uint32_t l3vni;  /* Key */  
    uint8_t vrf_id;  /* VRF ID */

    rd_t rd;  /* Route Distinguisher */
    rt_t import_rt;  /* Import Route Target */
    rt_t export_rt;  /* Export Route Target */

    /* MAC VRF RIB (All Type 5 and MAC_IP routes will go here ) */
    avltree_t ip_vrf_rib;
    
} ip_vrf_t;


typedef struct evpn_ {

    /* All EVPN Routes, imported from BGP/LOCAL Learned or static */
    avltree_t imported_routes;    /* Keyed by VTEP IP, Route_type, NLRI */

    /* All EVPN routes to be advertised to BGP */
    avltree_t exported_routes;    /* Keyed by VTEP IP, Route_type, NLRI */
    
    avltree_node_t mac_vrf_tree;  /* Keyed by l2vni */
    avltree_node_t ip_vrf_tree;   /* Keyed by l3vni */

} evpn_t;




#endif 
