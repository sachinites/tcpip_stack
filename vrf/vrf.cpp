#include "vrf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../lmm_enums.h"
#include "../router_init.h"
#include "../RTM/rtm.h"
#include "../datapath/FIB/fib.h"
#include "../Interface/InterfaceUApi.h"
#include "../Interface/Interface.h"
#include "../Interface/InterfacEnums.h"
#include "../net.h"
#include "../dpal/cp2dp.h"
#include "../LabelMgr/label_mgr.h"

/* Initialize Default VRF */
def_vrf_t* vrf_def_init(node_t *node) {
    
    /* Allocate memory for default VRF */
    def_vrf_t *def_vrf = (def_vrf_t *)XCALLOC2(0, 1, def_vrf_t);
    
    vrf_init (node, RTM_DEFAULT_VRF, DEF_VRF_NAME, &def_vrf->vrf);
    
    def_vrf->mpls0       = rtm_initialize(node, RTM_DEFAULT_VRF, DEF_VRF_NAME, AF_LABEL, 0);   // mpls.0
    def_vrf->l3vpnv4     = rtm_initialize(node, RTM_DEFAULT_VRF, DEF_VRF_NAME, AF_IPV4, 128);  // bgp.l3vpn.0 (v4)
    def_vrf->l3vpnv6     = rtm_initialize(node, RTM_DEFAULT_VRF, DEF_VRF_NAME, AF_IPV6, 128);  // bgp.l3vpn.0 (v6)
    
    return def_vrf;
}

/* Initialize a VRF instance */
vrf_t* vrf_init(node_t *node, uint8_t vrf_id, char *vrf_name, vrf_t *vrf) {

    if (vrf_id >= MAX_VRF_PER_NODE)
        return NULL;

    /* Initialize VRF fields */
    vrf->vrf_id = vrf_id;
    strncpy(vrf->vrf_name, vrf_name, sizeof(vrf->vrf_name) - 1);
    vrf->vrf_name[sizeof(vrf->vrf_name) - 1] = '\0';

    vrf->node = node;

    /* Initializw RIBs*/
    vrf->inet0   = rtm_initialize(node, vrf_id, vrf_name, AF_IPV4, 0);
    vrf->inet3   = rtm_initialize(node, vrf_id, vrf_name, AF_IPV4, 3);
    vrf->inet63  = rtm_initialize(node, vrf_id, vrf_name, AF_IPV6, 3);
    vrf->inet6   = rtm_initialize(node, vrf_id, vrf_name, AF_IPV6, 0);

    /* Initialize interface hashmaps */
    vrf->intf_by_name = new std::unordered_map<std::string, InterfaceP>();
    vrf->intf_by_ifindex = new std::unordered_map<uint32_t, InterfaceP>();

    /* Initialize L3 VPN label to 0 */
    if (vrf_id == 0) 
        vrf->l3_vpn_label = 0;
    else  {
        assert (label_mgr_block_alloc_label(
            node->l3vpn_lbl_block, &vrf->l3_vpn_label) == LABEL_MGR_OK);
    }

    /* Initialize Route Distinguisher */
    vrf->rd.asn = 0;
    vrf->rd.number = 0;

    /* Initialize Route Target */
    vrf->import_rt.asn = 0;
    vrf->import_rt.number = 0;
    vrf->export_rt.asn = 0;
    vrf->export_rt.number = 0;    

    vrf->isis_node_info = NULL;
    vrf->srv6_node_info = NULL;

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

    /* Release L3 VPN label */
    label_mgr_block_release_label(vrf->node->l3vpn_lbl_block, vrf->l3_vpn_label);
    vrf->l3_vpn_label = 0;

    vrf->node->vrf[vrf->vrf_id] = NULL;
    vrf->node = NULL;

    if (_free) {
        XFREE(vrf);
    }
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
        if (intf->iftype == INTF_TYPE_GRE_TUNNEL) {
            GRETunnelInterface *gre_intf =
                dynamic_cast<GRETunnelInterface *>(intf);
            gre_intf->gre_tunnel_check_and_activate_tunnel();
        }
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

    if (intf->iftype == INTF_TYPE_GRE_TUNNEL) {
        GRETunnelInterface *gre_intf =
            dynamic_cast<GRETunnelInterface *>(intf);
        gre_intf->gre_deactivate_tunnel();
    }

    if (vrf_interface_delete_by_name(vrf, ifname)) {
        intf->vrf = NULL;
        cp2dp_vrf_delete_interface(vrf->node, vrf->vrf_id, ifindex);
        return true;
    }

    /* Interface not found */
    return false;
}

vrf_t* vrf_get_by_id (node_t *node, uint8_t vrf_id) {

    return node->vrf[vrf_id];
}

bool
node_register_vrf(node_t *node, vrf_t *vrf) {

    if (!node || !vrf || vrf->vrf_id >= MAX_VRF_PER_NODE)
        return false;

    assert (!node->vrf[vrf->vrf_id]);
    node->vrf[vrf->vrf_id] = vrf;
    vrf->node = node;
    return true;
}

char* vrf_name (node_t *node, uint8_t vrf_id) {

    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    if (vrf ) return vrf->vrf_name;
    return NULL;
}

char *
cp_get_vrf_name_from_vrf_id (void *ctx, uint8_t vrf_id) {

    return vrf_name((node_t *)ctx, vrf_id);
}

vrf_t* 
vrf_get_by_name (node_t *node, char *name) {

    int i;
    
    if (!name || strcmp (name, DEF_VRF_NAME) == 0) 
        return (vrf_t *)node->node_nw_prop.def_vrf;

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i] && 
            0 == strncmp(node->vrf[i]->vrf_name, name, sizeof (node->vrf[i]->vrf_name))) {
            return node->vrf[i];
        }
    }

    return NULL;    
}

int
vrf_alloc_new_vrf_id (node_t *node) {

    int i;

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {

        if (!node->vrf[i]) return i;
    }

    return -1;
}

void 
show_vrfs(node_t *node) {

    int i;
    bool has_vrf = false;

    cprintf("%-10s %-20s %-15s %-15s %-15s %-12s\n",
            "VRF ID", "VRF Name", "RD", "Import RT", "Export RT", "L3VPN Label");
    cprintf("%-10s %-20s %-15s %-15s %-15s %-12s\n",
            "------", "--------", "--", "---------", "---------", "-----------");

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
        cprintf("%-10u %-20s %-15s %-15s %-15s %-12u\n",
                vrf->vrf_id,
                vrf->vrf_name,
                rd_str,
                import_rt_str,
                export_rt_str,
                vrf->l3_vpn_label);
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
