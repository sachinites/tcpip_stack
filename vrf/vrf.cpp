#include "vrf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../lmm_enums.h"
#include "../router_init.h"
#include "../RTM/rtm.h"
#include "../FIB/fib.h"
#include "../Interface/InterfaceUApi.h"
#include "../net.h"
#include "../common/cp2dp.h"

/* Initialize Default VRF */
def_vrf_t* vrf_def_init(node_t *node) {
    
    /* Allocate memory for default VRF */
    def_vrf_t *def_vrf = (def_vrf_t *)XCALLOC2(0, 1, def_vrf_t);
    
    vrf_init (node, RTM_DEFAULT_VRF, DEF_VRF_NAME, &def_vrf->vrf);
    
    def_vrf->mpls0       = rtm_initialize(node, RTM_DEFAULT_VRF, AF_LABEL, 0);   // mpls.0
    def_vrf->l3vpnv4     = rtm_initialize(node, RTM_DEFAULT_VRF, AF_IPV4, 128);  // bgp.l3vpn.0 (v4)
    def_vrf->l3vpnv6     = rtm_initialize(node, RTM_DEFAULT_VRF, AF_IPV6, 128);  // bgp.l3vpn.0 (v6)
    
    return def_vrf;
}

/* Initialize a VRF instance */
vrf_t* vrf_init(node_t *node, uint8_t vrf_id, char *vrf_name, vrf_t *vrf) {

    /* Initialize VRF fields */
    vrf->vrf_id = vrf_id;
    strncpy(vrf->vrf_name, vrf_name, sizeof(vrf->vrf_name) - 1);
    vrf->vrf_name[sizeof(vrf->vrf_name) - 1] = '\0';

    vrf->node = node;

    /* Initializw RIBs*/
    vrf->inet0   = rtm_initialize(node, vrf_id, AF_IPV4, 0); 
    vrf->inet3   = rtm_initialize(node, vrf_id, AF_IPV4, 3); 
    vrf->inet63 = rtm_initialize(node, vrf_id, AF_IPV6, 3); 
    vrf->inet6   = rtm_initialize(node, vrf_id, AF_IPV6, 0); 

    /* Initialize interface hashmaps */
    vrf->intf_by_name = new std::unordered_map<std::string, InterfaceP>();
    vrf->intf_by_ifindex = new std::unordered_map<uint32_t, InterfaceP>();

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

    /* Initialize dx4_sid db*/
    init_glthread(&vrf->dx4_sid_lst);

    return vrf;
}

/* Delete VRF by ID */
void vrf_delete_by_id(node_t *node, uint8_t vrf_id) {
    
    /* Look up VRF */
    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    vrf_delete(vrf, true);
}

/* Delete VRF instance */
void vrf_delete(vrf_t* vrf, bool _free) {

    glthread_t *curr;

    assert (vrf->vrf_id != RTM_DEFAULT_VRF);

    rtm_stop(vrf->inet0);
    rtm_check_and_delete (vrf->inet0, true);
    vrf->inet0 = NULL;

    rtm_stop(vrf->inet3);
    rtm_check_and_delete (vrf->inet3, true);
    vrf->inet3 = NULL;

    rtm_stop(vrf->inet63);
    rtm_check_and_delete (vrf->inet63, true);
    vrf->inet63 = NULL;

    rtm_stop(vrf->inet6);
    rtm_check_and_delete (vrf->inet6, true);
    vrf->inet6 = NULL;

    /* Remove interfaces from VRF */
    if (vrf->intf_by_name) {
        delete vrf->intf_by_name;
        vrf->intf_by_name = nullptr;
    }
    
    if (vrf->intf_by_ifindex) {
        delete vrf->intf_by_ifindex;
        vrf->intf_by_ifindex = nullptr;
    }
    
    //mpls_label_release (vrf->l3_vpn_label);
    vrf->l3_vpn_label = 0;
    vrf->node = NULL;

    while ((curr = dequeue_glthread_first(&vrf->dx4_sid_lst))) {

        glthread_data_node_t *data_node = glue_to_glthread_data_node(curr);
        ipv6_addr_t *dx4_sid = (ipv6_addr_t *)data_node->data;
        vrf_rtm_unprogram_dx4_sid (vrf, dx4_sid);
        XFREE(data_node);
    } 

    if (vrf->DX4_vrf_steering_intfp) {
        delete vrf->DX4_vrf_steering_intfp;
        vrf->DX4_vrf_steering_intfp = NULL;
    }

    if (_free) XFREE(vrf);
}

/* Add interface to VRF */
bool vrf_add_interface(vrf_t *vrf, Interface* intf) {
    
    assert(!intf->vrf);

    if (intf->HasL3Config(true)) {
        cprintf ("Error : Interface already has L3 Config, Not Eligible for vrf Config\n");
        return false;
    }

    if (vrf_interface_insert(vrf, intf)) {
        intf->vrf = vrf;
        cp2dp_vrf_add_interface(vrf->node, vrf->vrf_id, intf->ifindex);
        return true;
    }

    return false;
}

/* Remove interface from VRF */
bool vrf_del_interface(vrf_t *vrf, Interface *intf) {
    
    if (!intf->vrf) return false;

    if (intf->HasL3Config(false)) {

        cprintf ("Error : Interface not eligible for vrf deletion, Remove L3 config first\n");
        return false;
    }

    const char *ifname = intf->if_name.c_str();
    uint32_t ifindex = intf->ifindex;

    if (vrf_interface_delete_by_name(vrf, ifname)) {
        intf->vrf = NULL;
        cp2dp_vrf_delete_interface(vrf->node, vrf->vrf_id, ifindex);
        return true;
    }

    /* Interface not found */
    return false;
}

/* Get VRF by ID from global registry */
vrf_t* vrf_get_by_id (node_t *node, uint8_t vrf_id) {
    
    int i;

    if (vrf_id == 0) return (vrf_t *)node->node_nw_prop.def_vrf;

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

    return true;
}

char* vrf_name (node_t *node, uint8_t vrf_id) {

    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    if (vrf ) return vrf->vrf_name;
    return NULL;
}

vrf_t* 
vrf_get_by_name (node_t *node, char *name) {

    int i;
    
    if (strcmp (name, DEF_VRF_NAME) == 0) 
        return (vrf_t *)node->node_nw_prop.def_vrf;

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

    int i;
    bool has_vrf = false;

    cprintf("%-10s %-20s %-15s %-15s %-15s %-20s %-20s\n", 
            "VRF ID", "VRF Name", "RD", "Import RT", "Export RT", "IPv4 RIB", "IPv6 RIB");
    cprintf("%-10s %-20s %-15s %-15s %-15s %-20s %-20s\n",
            "------", "--------", "--", "---------", "---------", "---------", "---------");

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        
        if (!node->vrf[i]) continue;
        
        vrf_t *vrf = node->vrf[i];
        has_vrf = true;

        char rd_str[32];
        char import_rt_str[32];
        char export_rt_str[32];

        /* Format Route Distinguisher */
        if (vrf->rd.asn == 0 && vrf->rd.number == 0) {
            snprintf(rd_str, sizeof(rd_str), "Not Set");
        } else {
            snprintf(rd_str, sizeof(rd_str), "%u:%u", vrf->rd.asn, vrf->rd.number);
        }

        /* Format Import RT */
        if (vrf->import_rt.asn == 0 && vrf->import_rt.number == 0) {
            snprintf(import_rt_str, sizeof(import_rt_str), "Not Set");
        } else {
            snprintf(import_rt_str, sizeof(import_rt_str), "%u:%u", 
                    vrf->import_rt.asn, vrf->import_rt.number);
        }

        /* Format Export RT */
        if (vrf->export_rt.asn == 0 && vrf->export_rt.number == 0) {
            snprintf(export_rt_str, sizeof(export_rt_str), "Not Set");
        } else {
            snprintf(export_rt_str, sizeof(export_rt_str), "%u:%u", 
                    vrf->export_rt.asn, vrf->export_rt.number);
        }

        /* Display VRF information */
        cprintf("%-10u %-20s %-15s %-15s %-15s %-20s %-20s\n",
                vrf->vrf_id,
                vrf->vrf_name,
                rd_str,
                import_rt_str,
                export_rt_str,
                vrf->inet0 ? vrf->inet0->name : "N/A",
                vrf->inet6 ? vrf->inet6->name : "N/A");
    }

    if (!has_vrf) {
        cprintf("No VRFs configured.\n");
    }

    printw("\n");
}

vrf_t * 
NODE_DEF_VRF(node_t *node) {
    return (vrf_t *)node->node_nw_prop.def_vrf;
}

void 
vrf_rtm_program_dx4_sid (vrf_t *vrf, ipv6_addr_t *dx4_sid) {

}

void 
vrf_rtm_unprogram_dx4_sid (vrf_t *vrf, ipv6_addr_t *dx4_sid) {

}
