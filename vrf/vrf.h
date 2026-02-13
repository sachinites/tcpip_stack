#ifndef __RTR_VRF__
#define __RTR_VRF__

#include <stdint.h>
#include <stdbool.h>
#include <unordered_map>
#include <string>
#include <vector>

#include "../gluethread/glthread.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../common/mpls_lstack.h"
#include "../Interface/InterfaceFwd.h"

typedef struct rtm_ rtm_t;
typedef struct fib_ fib_t;
typedef struct node_ node_t;
typedef struct node_info_ isis_node_info_t;

#define MAX_VRF_PER_NODE    8

#pragma pack(push, 8)

typedef struct rd_
{
    uint16_t asn;
    uint32_t number;
} rd_t;

typedef struct rt_
{
    uint16_t asn;
    uint32_t number;
} rt_t;

typedef struct vrf_ {

    /* VRF ID*/
    uint8_t vrf_id;
    /* vrf name */
    char vrf_name[32];
    /* Owning Router*/
    node_t *node;
    
    /* RIBs */
    rtm_t *inet0;   // ipv4 RIB
    rtm_t *inet3;   // ipv4-> MPLS Service RIB
    rtm_t *inet63;  // ipv6 -> MPLS service RIB
    rtm_t *inet6;   // ipv6 Rib

    /* inet6.0 FIB*/
    fib_t *fib_inet0;
    /* inet6.0 FIB*/
    fib_t *fib_inet6;    
    /* Interfaces in this VRF - hashmap keyed by interface name*/
    std::unordered_map<std::string, InterfaceP> *intf_by_name;
    /* Interfaces in this VRF - hashmap keyed by interface index*/
    std::unordered_map<uint32_t, InterfaceP> *intf_by_ifindex;
    /* L3 VPN service label */
    mpls_label_val_t l3_vpn_label;
    /* Route Distinguisher Type 0 */
    rd_t rd;
    /* Route target */
    rt_t import_rt;
    rt_t export_rt;

    SRv6EndPointEND_DX4Interface *DX4_vrf_steering_intfp;
    glthread_t dx4_sid_lst;

    isis_node_info_t *isis_node_info;

} vrf_t;

typedef struct def_vrf_ {

    vrf_t vrf;
    rtm_t *mpls0;
    fib_t *mpls_fib;
    rtm_t *l3vpnv4;
    rtm_t *l3vpnv6;

} def_vrf_t;

#pragma pack(pop)

/* Default VRF functions */
def_vrf_t* vrf_def_init (node_t *node);

/* VRF functions */
vrf_t* vrf_init (node_t *node, uint8_t vrf_id, char *vrf_name, vrf_t *vrf_out);
void vrf_delete_by_id (node_t *node, uint8_t vrf_id );
void vrf_delete (vrf_t* vrf_id , bool _free);
bool vrf_add_interface (vrf_t *vrf, Interface *intf);
bool vrf_del_interface (vrf_t *vrf, Interface *intf);
vrf_t* vrf_get_by_id (node_t *node, uint8_t vrf_id);
vrf_t* vrf_get_by_name (node_t *node, char *name);
char* vrf_name (node_t *node, uint8_t vrf_id);
bool node_register_vrf(node_t *node, vrf_t *vrf);
void show_vrfs(node_t *node);

void vrf_rtm_program_dx4_sid (vrf_t *vrf, ipv6_addr_t *dx4_sid);
void vrf_rtm_unprogram_dx4_sid (vrf_t *vrf, ipv6_addr_t *dx4_sid);

vrf_t *NODE_DEF_VRF(node_t *node);

#define NODE_DEF_VRF_VRF_MEMBER(node_ptr, member)  \
    (((def_vrf_t *)(NODE_DEF_VRF(node_ptr)))->vrf.member)

#define NODE_DEF_VRF_MEMBER(node_ptr, member)  \
    (((def_vrf_t *)(NODE_DEF_VRF(node_ptr)))->member)

#endif