#include <assert.h>
#include <stdio.h>
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
#define MAC_VRF_MAC_STR_LEN    18

static const char *
mac_vrf_format_mac(const mac_addr_t *mac, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->mac[0], mac->mac[1], mac->mac[2],
             mac->mac[3], mac->mac[4], mac->mac[5]);
    return buf;
}

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
mac_vrf_create (vrf_t *vrf, uint16_t mac_vrf_id) {

    mac_vrf_t *mac_vrf = (mac_vrf_t *)XCALLOC2(0, 1, mac_vrf_t);
    mac_vrf->mac_vrf_id = mac_vrf_id;

    /* Association between VRF and Mac VRF */
    mac_vrf->vrf = vrf;

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
    assert (!mac_vrf->evpn_inst);
    XFREE(mac_vrf);
}


void
mac_vrf_destroy (mac_vrf_t *mac_vrf) {

    /* De-associate with parent L3 VRF */
    mac_vrf->vrf = NULL;

    /* Flush Type-2 RIB (frees keys and evpn_rt_t values) */
    if (mac_vrf->type2_rib) {
        hashtable_destroy(mac_vrf->type2_rib, 1);
        mac_vrf->type2_rib = NULL;
    }

    rtm_stop(mac_vrf->mac_rtm);
    rtm_check_and_delete(mac_vrf->mac_rtm, true);
    mac_vrf->mac_rtm = NULL;

    mac_vrf->evpn_inst = NULL;
    mac_vrf_check_and_delete(mac_vrf);
}

void 
mac_vrf_evpn_route_type2_local_import(
                node_t *node,
                mac_vrf_t *mac_vrf, 
                mac_addr_t *mac_addr) {

    mac_addr_t *key;
    evpn_rt_t *evpn_rt;
    char mac_str[MAC_VRF_MAC_STR_LEN];

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s mac-vrf %u\n",
           mac_str, mac_vrf->mac_vrf_id);

    /* Idempotent: already present for this MAC */
    if (hashtable_search(mac_vrf->type2_rib, mac_addr)) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 local import route %s skipped — already in RIB\n",
               mac_str);
        return;
    }

    /* Hashtable owns the key and frees it on remove/destroy */
    key = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);

    memcpy(key->mac, mac_addr->mac, MAC_ADDR_SIZE);

    /* Hashtable frees the value when destroy(..., free_values=1) */
    evpn_rt = (evpn_rt_t *)XCALLOC2(0, 1, evpn_rt_t);

    evpn_rt->type = EVPN_RT_TYPE_MAC_ONLY;
    evpn_rt->flags = EVPN_RT_F_LOCAL;
    evpn_rt->vtep_ip = NODE_RTR_ID_INT(node);
    memcpy(evpn_rt->u.mac_only.mac.mac, mac_addr->mac, MAC_ADDR_SIZE);
    evpn_rt->u.mac_only.ip_addr = 0;
    evpn_rt->u.mac_only.label = mac_vrf->evpn_inst->bd_intf->vpn_svc_label;

    if (!hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
        tracer(node->cptr, DEVPN | DERR,
               "EVPN Type-2 local import route %s failed — hashtable insert\n",
               mac_str);
        XFREE(key);
        XFREE(evpn_rt);
        return;
    }

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s installed label %u, exporting to BGP\n",
           mac_str, evpn_rt->u.mac_only.label);

    evpn_route_export_to_bgp(node,
                             &mac_vrf->evpn_inst->rd,
                             &mac_vrf->evpn_inst->export_rt,
                             evpn_rt,
                             false);
}

void
mac_vrf_evpn_route_type2_delete (
                node_t *node,
                mac_vrf_t *mac_vrf,
                mac_addr_t *mac_addr) {

    evpn_rt_t *evpn_rt;
    char mac_str[MAC_VRF_MAC_STR_LEN];

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 delete route %s mac-vrf %u\n",
           mac_str, mac_vrf->mac_vrf_id);

    /* hashtable_remove frees the key; caller frees the value */
    evpn_rt = (evpn_rt_t *)hashtable_search(mac_vrf->type2_rib, mac_addr);

    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 delete route %s skipped — not in RIB\n",
               mac_str);
        return;
    }

    if (evpn_rt && evpn_rt->type == EVPN_RT_F_LOCAL) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 delete route %s — withdraw local from BGP\n",
               mac_str);

        evpn_route_export_to_bgp(node,
                                     &mac_vrf->evpn_inst->rd,
                                     &mac_vrf->evpn_inst->export_rt,
                                     evpn_rt,
                                     true);
        
    }
    else if (evpn_rt && evpn_rt->type == EVPN_RT_F_REMOTE) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 delete route %s — remote (RTM uninstall)\n",
               mac_str);
        
        /* 1. Send Delete to RTM --> Mac (Redundant )*/
        mac_vrf_evpn_route_type2_remote_delete (mac_vrf, mac_addr);

        /* ToDo : If the Delete was triggered by CLI command ( instead of BGP 
            withdrawing the route), then ask BGP to replay back remotely learnt 
            routes (through Job)*/
    }

    hashtable_remove(mac_vrf->type2_rib, mac_addr);
    XFREE(evpn_rt);
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
    char ip_addr_str[16];
    char mac_str[MAC_VRF_MAC_STR_LEN];

    node_t *node = mac_vrf->vrf->node;

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote import route %s VTEP %s label %u mac-vrf %u\n",
           mac_str, ip_ntop(vtep_ip, (c_string)ip_addr_str),
           label, mac_vrf->mac_vrf_id);

    existing = (evpn_rt_t *)hashtable_search(mac_vrf->type2_rib, mac_addr);

    if (existing) {

        if (existing->flags & EVPN_RT_F_LOCAL) {

         tracer(node->cptr, DRTM | DERR,
            "EVPN Type-2 remote import route %s skipped — "
            "local already exists in MAC VRF %d\n",
                mac_str, mac_vrf->mac_vrf_id);
         }
        else {
            tracer(node->cptr, DEVPN_DET,
                   "EVPN Type-2 remote import route %s skipped — already in RIB\n",
                   mac_str);
        }
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
        tracer(node->cptr, DEVPN | DERR,
               "EVPN Type-2 remote import route %s failed — hashtable insert\n",
               mac_str);
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
            tracer(node->cptr, DRTM | DEVPN | DERR,
                   "EVPN Type-2 remote import route %s failed RTM install "
                   "into %s — %s\n",
                    mac_str, mac_vrf->mac_rtm->name,
                    rtm_error_to_string(rc));
            return;
        }

        tracer(node->cptr, DRTM_DET | DEVPN_DET,
               "EVPN Type-2 remote import route %s installed into MAC VRF RTM %s\n",
                mac_str, mac_vrf->mac_rtm->name);
    }
}

void
mac_vrf_evpn_route_type2_remote_delete(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr)
{
    evpn_rt_t *evpn_rt;
    char mac_str[MAC_VRF_MAC_STR_LEN];

    node_t *node = mac_vrf->vrf->node;

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote delete route %s mac-vrf %u\n",
           mac_str, mac_vrf->mac_vrf_id);

    evpn_rt = (evpn_rt_t *)hashtable_remove(mac_vrf->type2_rib, mac_addr);

    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 remote delete route %s skipped — not in RIB\n",
               mac_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {
        mac_addr_t *key = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);

        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 remote delete route %s skipped — "
               "local route preferred\n",
               mac_str);

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
            tracer(node->cptr, DRTM | DERR,
                   "EVPN Type-2 remote delete route %s failed RTM uninstall "
                   "from %s — %s\n",
                    mac_str, mac_vrf->mac_rtm->name,
                    rtm_error_to_string(rc));
        }
        else {
            tracer(node->cptr, DRTM_DET,
                   "EVPN Type-2 remote delete route %s uninstalled from "
                   "MAC VRF RTM %s\n",
                    mac_str, mac_vrf->mac_rtm->name);
        }
    }

    XFREE(evpn_rt);
}

rtm_t *
mac_vrf_get_rtm (node_t *node, uint16_t mac_vrf_id) {

    uint16_t i ;
    evpn_inst_t *evpn_inst;

    for (i = 0; i < MAX_EVPN_INDEX; i++) {

        evpn_inst = node->evpn[i];
        if (!evpn_inst || !evpn_inst->mac_vrf) continue;
        if (evpn_inst->mac_vrf->mac_vrf_id != mac_vrf_id) continue;
        return evpn_inst->mac_vrf->mac_rtm;
    }

    return NULL;
}
