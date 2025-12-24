#ifndef __RTR_VRF__
#define __RTR_VRF__

#include <stdint.h>
#include <stdbool.h>
#include "../common/mpls_lstack.h"
#include "../Interface/InterfaceFwd.h"

typedef struct rtm_ rtm_t;
typedef struct fib_ fib_t;
typedef struct node_ node_t;

#define VRF_MAX_INTF 6
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
    /* inet0 RIB */
    rtm_t *inet0;
    /* inet6.0 FIB*/
    fib_t *fib_inet0;
    /* inet.6 RIB*/
    rtm_t *inet6;
    /* inet6.0 FIB*/
    fib_t *fib_inet6;    
    /* Interfaces in this VRF*/
    InterfaceP intf[VRF_MAX_INTF];
    /* L3 VPN service label */
    mpls_label_val_t l3_vpn_label;
    /* Route Distinguisher Type 0 */
    rd_t rd;
    /* Route target */
    rt_t import_rt;
    rt_t export_rt;

} vrf_t;

#pragma pack(pop)

vrf_t* vrf_init (node_t *node, uint8_t vrf_id, char *vrf_name);
void vrf_delete_by_id (node_t *node, uint8_t vrf_id );
void vrf_delete (vrf_t* vrf_id );
bool vrf_add_interface (vrf_t *vrf, InterfaceP intf);
bool vrf_del_interface (vrf_t *vrf, InterfaceP intf);
vrf_t* vrf_get_by_id (node_t *node, uint8_t vrf_id);
vrf_t* vrf_get_by_name (node_t *node, char *name);
char* vrf_name (node_t *node, uint8_t vrf_id);
bool node_register_vrf(node_t *node, vrf_t *vrf);
void show_vrfs(node_t *node);

#endif 