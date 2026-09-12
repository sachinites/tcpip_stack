#ifndef __EVPN__
#define __EVPN__

#include <stdint.h>
#include "../../vrf/vrf.h"

typedef struct rtm_ rtm_t;
typedef struct node_ node_t;
class BDInterface ;


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

#pragma pack(push, 8)

typedef struct evpn_inst_ {

    /* Owning Rtr*/
    node_t *node;

    /* EVPN is a control plane wrapper over BD Mgmt */
    BDInterfaceP bd_intf;    

    rd_t rd;
    rt_t import_rt;    
    rt_t export_rt;    


    /*EVPN Instance identifier */
    uint8_t evi;

} evpn_inst_t;

#pragma pack(pop)

evpn_inst_t *
evpn_instance_init (node_t *node, uint8_t evpn_id) ;

void
evpn_instance_deinit (evpn_inst_t **evpn_inst);

bool 
evpn_config_rd (evpn_inst_t *evpn_inst, rd_t rd);

bool 
evpn_unconfig_rd (evpn_inst_t *evpn_inst, rd_t rd);

bool 
evpn_config_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import);

bool 
evpn_unconfig_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import);

void
evpn_connect_bd (evpn_inst_t *evpn_inst, BDInterface *bd_intf);

bool 
evpn_disconnect_bd (evpn_inst_t *evpn_inst, BDInterface *bd_intf);

#endif 
