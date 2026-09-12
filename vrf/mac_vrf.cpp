#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/c-hashtable/hashtable.h"
#include "../libs/Tracer/tracer.h"

#include "../Interface/InterfaceUApi.h"

#include "../router_init.h"
#include "../net.h"
#include "../RTM/rtm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../Interface/InterfacEnums.h"
#include "../libs/common/cmn_prefix.h"

#include "mac_vrf.h"
#include "../Layer2/Evpn/evpn_rt.h"
#include "../Layer2/Evpn/evpn.h"

extern int cprintf(const char *format, ...);

#define MAC_VRF_TYPE2_HT_SIZE  128

static unsigned int
mac_vrf_type2_hash (void *key)
{
    mac_addr_t *mac = (mac_addr_t *)key;
    unsigned int hash = 5381;
    int i;

    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        hash = ((hash << 5) + hash) + mac->mac[i];
    }

    return hash;
}

static int
mac_vrf_type2_key_equal (void *key1, void *key2)
{
    return (memcmp(key1, key2, MAC_ADDR_SIZE) == 0);
}

mac_vrf_t *
mac_vrf_create (vrf_t *vrf, uint16_t mac_vrf_id, evpn_inst_t *evpn_inst) {

    assert (vrf->mac_vrf[mac_vrf_id] == NULL);
    assert (evpn_inst);

    mac_vrf_t *mac_vrf = (mac_vrf_t *)XCALLOC2(0, 1, mac_vrf_t);
    mac_vrf->mac_vrf_id = mac_vrf_id;
    mac_vrf->evpn_inst = evpn_inst;

    /* Association between VRF and Mac VRF */
    mac_vrf->vrf = vrf;
    vrf->mac_vrf[mac_vrf_id] = mac_vrf;

    /* Type-2 RIB: hashtable keyed by MAC address */
    mac_vrf->type2_rib = create_hashtable(MAC_VRF_TYPE2_HT_SIZE,
                                          mac_vrf_type2_hash,
                                          mac_vrf_type2_key_equal);
    assert(mac_vrf->type2_rib);

    /* mac vrf name for BD10 under L3 VRF red will be : red.mac.10 */
    mac_vrf->mac_rtm = rtm_initialize (vrf->node, 
                                        vrf->vrf_id, 
                                        vrf->vrf_name, 
                                        AF_MAC, mac_vrf_id);
                        
    return mac_vrf;
}

static void 
mac_vrf_check_and_delete(mac_vrf_t *mac_vrf) {

    assert (!mac_vrf->type2_rib);
    assert (!mac_vrf->vrf);
    assert (!mac_vrf->mac_rtm);
    XFREE(mac_vrf);
}


void
mac_vrf_destroy (vrf_t *vrf, uint16_t mac_vrf_id) {

    mac_vrf_t *mac_vrf = vrf->mac_vrf[mac_vrf_id];

    /* De-associate with parent L3 VRF */
    vrf->mac_vrf[mac_vrf_id] = NULL;
    mac_vrf->vrf = NULL;

    /* Flush Type-2 RIB (frees keys and evpn_rt_t values) */
    if (mac_vrf->type2_rib) {
        hashtable_destroy(mac_vrf->type2_rib, 1);
        mac_vrf->type2_rib = NULL;
    }

    rtm_stop(mac_vrf->mac_rtm);
    rtm_check_and_delete(mac_vrf->mac_rtm, true);
    mac_vrf->mac_rtm = NULL;

    mac_vrf_check_and_delete(mac_vrf);
}

void 
mac_vrf_evpn_route_type2_local_import(
                mac_vrf_t *mac_vrf, 
                mac_addr_t *mac_addr) {

    mac_addr_t *key;
    evpn_rt_t *evpn_rt;

    /* Idempotent: already present for this MAC */
    if (hashtable_search(mac_vrf->type2_rib, mac_addr)) {
        return;
    }

    /* Hashtable owns the key and frees it on remove/destroy */
    key = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);

    memcpy(key->mac, mac_addr->mac, MAC_ADDR_SIZE);

    /* Hashtable frees the value when destroy(..., free_values=1) */
    evpn_rt = (evpn_rt_t *)XCALLOC2(0, 1, evpn_rt_t);

    evpn_rt->type = EVPN_RT_TYPE_MAC_ONLY;
    evpn_rt->flags = EVPN_RT_F_LOCAL;
    evpn_rt->vtep_ip = NODE_RTR_ID_INT(mac_vrf->vrf->node);
    memcpy(evpn_rt->u.mac_only.mac.mac, mac_addr->mac, MAC_ADDR_SIZE);
    evpn_rt->u.mac_only.ip_addr = 0;
    evpn_rt->u.mac_only.label = mac_vrf->evpn_inst->bd_intf->vpn_svc_label;

    if (!hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
        XFREE(key);
        XFREE(evpn_rt);
    }

    evpn_route_export_to_bgp(mac_vrf->vrf->node,
                             &mac_vrf->evpn_inst->rd,
                             &mac_vrf->evpn_inst->export_rt,
                             evpn_rt,
                             false);
}

void
mac_vrf_evpn_route_type2_delete (
                mac_vrf_t *mac_vrf,
                mac_addr_t *mac_addr) {

    evpn_rt_t *evpn_rt;

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    /* hashtable_remove frees the key; caller frees the value */
    evpn_rt = (evpn_rt_t *)hashtable_remove(mac_vrf->type2_rib, mac_addr);
    if (evpn_rt) {
        if (mac_vrf->evpn_inst) {
            evpn_route_export_to_bgp(mac_vrf->vrf->node,
                                     &mac_vrf->evpn_inst->rd,
                                     &mac_vrf->evpn_inst->export_rt,
                                     evpn_rt,
                                     true);
        }
        XFREE(evpn_rt);
    }
}

void
mac_vrf_evpn_route_type2_remote_import(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t vtep_ip,
        uint32_t label)
{
    mac_addr_t *key;
    evpn_rt_t *evpn_rt;
    evpn_rt_t *existing;

    node_t *node = mac_vrf->vrf->node;

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    existing = (evpn_rt_t *)hashtable_search(mac_vrf->type2_rib, mac_addr);
    if (existing) {
        if (existing->flags & EVPN_RT_F_LOCAL) {
            return;
        }

        existing->vtep_ip = vtep_ip;
        existing->u.mac_only.label = label;
        return;
    }

    key = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);
    memcpy(key->mac, mac_addr->mac, MAC_ADDR_SIZE);

    evpn_rt = (evpn_rt_t *)XCALLOC2(0, 1, evpn_rt_t);
    evpn_rt->type = EVPN_RT_TYPE_MAC_ONLY;
    evpn_rt->flags = EVPN_RT_F_REMOTE;
    evpn_rt->vtep_ip = vtep_ip;
    memcpy(evpn_rt->u.mac_only.mac.mac, mac_addr->mac, MAC_ADDR_SIZE);
    evpn_rt->u.mac_only.ip_addr = 0;
    evpn_rt->u.mac_only.label = label;

    if (!hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
        XFREE(key);
        XFREE(evpn_rt);
        return;
    }

    {
        cmn_prefix_t prefix;
        cmn_prefix_t gateway;
        rtm_error_t rc;

        memset(&prefix, 0, sizeof(prefix));
        prefix.afi = AF_MAC;
        prefix.prefix_len = 48;
        memcpy(prefix.u.mac_addr, mac_addr->mac, MAC_ADDR_SIZE);

        cmn_prefix_initialize_v4(&gateway, vtep_ip, 32);

        rc = cp_rtm_install_route_advanced(
                mac_vrf->mac_rtm,
                &prefix,
                RTM_PROTO_BGP,
                RTM_PROTO_L2VPN_EVPN,
                0, 0,
                RTM_NH_ACTION_TUNNEL,
                1,
                &gateway,
                0,
                INTF_TYPE_UNKNOWN,
                NULL,
                0,
                (mpls_label_val_t)label,
                MPLS_OP_STACK_OPS_UNKNOWN,
                mac_vrf->evpn_inst->bd_intf->ifindex);

        if (rc != RTM_SUCCESS) {
            tracer(node->cptr, DRTM | DERR, "Error : Failed to install route into MAC VRF RTM %s "
                    "for MAC %02x:%02x:%02x:%02x:%02x:%02x — %s\n",
                    mac_vrf->mac_rtm->name,
                    mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2],
                    mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5],
                    rtm_error_to_string(rc));
            return;
        }

        tracer(node->cptr, DRTM_DET, "Installed route into MAC VRF RTM %s "
                "for MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac_vrf->mac_rtm->name,
                mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2],
                mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5]);
    }
}

void
mac_vrf_evpn_route_type2_remote_delete(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr)
{
    evpn_rt_t *evpn_rt;

    node_t *node = mac_vrf->vrf->node;

    evpn_rt = (evpn_rt_t *)hashtable_remove(mac_vrf->type2_rib, mac_addr);

    if (!evpn_rt) {
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {
        mac_addr_t *key = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);

        memcpy(key->mac, mac_addr->mac, MAC_ADDR_SIZE);
        if (!hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
            XFREE(key);
            XFREE(evpn_rt);
        }
        return;
    }

    {
        cmn_prefix_t prefix;
        cmn_prefix_t gateway;
        rtm_error_t rc;

        memset(&prefix, 0, sizeof(prefix));
        prefix.afi = AF_MAC;
        prefix.prefix_len = 48;
        memcpy(prefix.u.mac_addr, mac_addr->mac, MAC_ADDR_SIZE);

        cmn_prefix_initialize_v4(&gateway, evpn_rt->vtep_ip, 32);

        rc = cp_rtm_uninstall_route_advanced(
                mac_vrf->mac_rtm,
                &prefix,
                RTM_PROTO_BGP,
                RTM_PROTO_L2VPN_EVPN,
                0,
                RTM_NH_ACTION_TUNNEL,
                1,
                &gateway,
                0,
                INTF_TYPE_UNKNOWN,
                NULL,
                0,
                (mpls_label_val_t)evpn_rt->u.mac_only.label,
                MPLS_OP_STACK_OPS_UNKNOWN,
                mac_vrf->evpn_inst->bd_intf->ifindex);

        if (rc != RTM_SUCCESS) {
            tracer(node->cptr, DRTM | DERR, "Error : Failed to uninstall route from MAC VRF RTM %s "
                    "for MAC %02x:%02x:%02x:%02x:%02x:%02x — %s\n",
                    mac_vrf->mac_rtm->name,
                    mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2],
                    mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5],
                    rtm_error_to_string(rc));
        }   
        else {
            tracer(node->cptr, DRTM_DET, "Uninstalled route from MAC VRF RTM %s "
                    "for MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    mac_vrf->mac_rtm->name,
                    mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2],
                    mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5]);
        }
    }

    XFREE(evpn_rt);
}
