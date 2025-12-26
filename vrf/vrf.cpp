#include "vrf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../router_init.h"
#include "../RTM/rtm.h"
#include "../FIB/fib.h"
#include "../Interface/InterfaceUApi.h"

/* Initialize a VRF instance */
vrf_t* vrf_init(node_t *node, uint8_t vrf_id, char *vrf_name) {

    /* Allocate memory for new VRF */
    vrf_t *vrf = (vrf_t *)XCALLOC2(0, 1, vrf_t);

    /* Initialize VRF fields */
    vrf->vrf_id = vrf_id;
    strncpy(vrf->vrf_name, vrf_name, sizeof(vrf->vrf_name) - 1);
    vrf->vrf_name[sizeof(vrf->vrf_name) - 1] = '\0';

    /* Initialize interface array */
    for (int i = 0; i < VRF_MAX_INTF; i++) {
        vrf->intf[i] = nullptr;
    }

    /* Initialize L3 VPN label to 0 */
    vrf->l3_vpn_label = node_get_sequence_no(node);

    /* Initialize Route Distinguisher */
    vrf->rd.asn = 0;
    vrf->rd.number = 0;

    /* Initialize Route Target */
    vrf->import_rt.asn = 0;
    vrf->import_rt.number = 0;
    vrf->export_rt.asn = 0;
    vrf->export_rt.number = 0;    

    return vrf;
}

/* Delete VRF by ID */
void vrf_delete_by_id(node_t *node, uint8_t vrf_id) {
    
    /* Look up VRF */
    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    vrf_delete(vrf);
}

/* Delete VRF instance */
void vrf_delete(vrf_t* vrf) {

    /* Remove interfaces from VRF */
    for (int i = 0; i < VRF_MAX_INTF; i++) {

        if (vrf->intf[i]) {
            vrf->intf[i]->vrf = NULL;
            vrf->intf[i] = nullptr;
        }
    }

    rtm_stop(vrf->inet0);
    rtm_check_and_delete (vrf->inet0);
    vrf->inet0 = NULL;
    fib_destroy(vrf->fib_inet0);
    vrf->fib_inet0 = NULL;

    rtm_stop(vrf->inet6);
    rtm_check_and_delete (vrf->inet6);
    vrf->inet6 = NULL;
    fib_destroy(vrf->fib_inet6);
    vrf->fib_inet6 = NULL;

    //mpls_label_release (vrf->l3_vpn_label);
    vrf->l3_vpn_label = 0;
    vrf->node = NULL;

    XFREE(vrf);
}

/* Add interface to VRF */
bool vrf_add_interface(vrf_t *vrf, InterfaceP intf) {
    
    if (intf->vrf) return false;

    if (intf->HasL3Config()) {
        cprintf ("Error : Interface already has L3 Config, Not Eligible for vrf Config\n");
        return false;
    }

    for (int i = 0; i < VRF_MAX_INTF; i++) {
        if (vrf->intf[i] == nullptr) {
            vrf->intf[i] = intf;
            intf->vrf = vrf;
            return true;
        }
    }

    /* No available slot */
    return false;
}

/* Remove interface from VRF */
bool vrf_del_interface(vrf_t *vrf, InterfaceP intf) {
    
    if (!intf->vrf) return false;

    if (intf->HasL3Config()) {
        cprintf ("Error : Interface not eligible for vrf deletion, Remove L3 config first\n");
        return false;
    }

    /* Find and remove the interface */
    for (int i = 0; i < VRF_MAX_INTF; i++) {
        if (vrf->intf[i] == intf) {
            vrf->intf[i] = nullptr;
            intf->vrf = NULL;
            return true;
        }
    }

    /* Interface not found */
    return false;
}

/* Get VRF by ID from global registry */
vrf_t* vrf_get_by_id (node_t *node, uint8_t vrf_id) {
    
    int i;

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i] && node->vrf[i]->vrf_id == vrf_id) {
            return node->vrf[i];
        }
    }

    return NULL;
}

bool
node_register_vrf(node_t *node, vrf_t *vrf) {

    int i;
    
    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i]) continue;
        node->vrf[i] = vrf;
        vrf->node = node;
        break;
    }

    /* initialize all RTMs and FIBs now*/
    if (i != MAX_VRF_PER_NODE) {

        /* Initialize pointers to NULL */
        vrf->node       = node;
        vrf->inet0      = rtm_initialize (node, vrf->vrf_id, AF_IPV4, 0);
        vrf->fib_inet0  = fib_init(node, AF_IPV4, vrf->vrf_id);
        vrf->inet6      = rtm_initialize (node, vrf->vrf_id, AF_IPV6, 0);
        vrf->fib_inet6  = fib_init(node, AF_IPV6, vrf->vrf_id);
        return true;
    }

    return false;
}

char* vrf_name (node_t *node, uint8_t vrf_id) {

    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    if (vrf ) return vrf->vrf_name;
    return NULL;
}

vrf_t* 
vrf_get_by_name (node_t *node, char *name) {

    int i;
    
    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i] && 
            0 == strncmp(node->vrf[i]->vrf_name, name, sizeof (node->vrf[i]->vrf_name))) {
            return node->vrf[i];
        }
    }

    return NULL;    
}

void 
show_vrfs(node_t *node) {

}
