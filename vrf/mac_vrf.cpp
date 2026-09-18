#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/c-hashtable/hashtable.h"
#include "../libs/c-hashtable/hashtable_itr.h"
#include "../libs/Tracer/tracer.h"

#include "../Interface/InterfaceUApi.h"

#include "../router_init.h"
#include "../net.h"
#include "../utils.h"
#include "../RTM/rtm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../Interface/InterfacEnums.h"
#include "../libs/common/cmn_prefix.h"

#include "../dpal/cp2dp.h"

#include "mac_vrf.h"
#include "../Layer2/Evpn/evpn_rt.h"
#include "../Layer2/Evpn/evpn_bgp.h"
#include "../Layer2/Evpn/evpn.h"

extern int cprintf(const char *format, ...);

#define MAC_VRF_TYPE2_HT_SIZE  128
#define MAC_VRF_TYPE3_HT_SIZE  32
#define MAC_VRF_MAC_IP_HT_SIZE 128
#define MAC_VRF_MAC_STR_LEN    18

static const char *
mac_vrf_format_mac(const mac_addr_t *mac, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->mac[0], mac->mac[1], mac->mac[2],
             mac->mac[3], mac->mac[4], mac->mac[5]);
    return buf;
}

static void
mac_vrf_type2_key_init(mac_vrf_type2_key_t *key,
                       const mac_addr_t *mac,
                       uint32_t ip_addr)
{
    memset(key, 0, sizeof(*key));
    memcpy(key->mac.mac, mac->mac, MAC_ADDR_SIZE);
    key->ip_addr = ip_addr;
}

static mac_vrf_type2_key_t *
mac_vrf_type2_key_alloc(const mac_addr_t *mac, uint32_t ip_addr)
{
    mac_vrf_type2_key_t *key =
        (mac_vrf_type2_key_t *)XCALLOC_BUFF(0, sizeof(mac_vrf_type2_key_t));
    if (key)
        mac_vrf_type2_key_init(key, mac, ip_addr);
    return key;
}

static unsigned int
mac_vrf_type2_hash (void *key)
{
    mac_vrf_type2_key_t *k = (mac_vrf_type2_key_t *)key;
    unsigned int hash = 5381;
    int i;

    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        hash = ((hash << 5) + hash) + k->mac.mac[i];
    }
    hash = ((hash << 5) + hash) + (unsigned int)(k->ip_addr & 0xff);
    hash = ((hash << 5) + hash) + (unsigned int)((k->ip_addr >> 8) & 0xff);
    hash = ((hash << 5) + hash) + (unsigned int)((k->ip_addr >> 16) & 0xff);
    hash = ((hash << 5) + hash) + (unsigned int)((k->ip_addr >> 24) & 0xff);

    return hash;
}

static int
mac_vrf_type2_key_equal (void *key1, void *key2)
{
    mac_vrf_type2_key_t *a = (mac_vrf_type2_key_t *)key1;
    mac_vrf_type2_key_t *b = (mac_vrf_type2_key_t *)key2;

    return (memcmp(a->mac.mac, b->mac.mac, MAC_ADDR_SIZE) == 0) &&
           (a->ip_addr == b->ip_addr);
}

static unsigned int
mac_vrf_type3_hash (void *key)
{
    uint32_t *pe_addr = (uint32_t *)key;
    return (unsigned int)(*pe_addr);
}

static int
mac_vrf_type3_key_equal (void *key1, void *key2)
{
    uint32_t *a = (uint32_t *)key1;
    uint32_t *b = (uint32_t *)key2;
    return (*a == *b);
}

/* IP→MAC binding table uses the same uint32 key hash/equal as Type-3. */
static void
mac_vrf_mac_ip_binding_add(mac_vrf_t *mac_vrf,
                           uint32_t ip_addr,
                           const mac_addr_t *mac)
{
    uint32_t *key;
    mac_addr_t *val;
    mac_addr_t *old;

    if (!mac_vrf || !mac_vrf->mac_ip_binding || !mac || ip_addr == 0)
        return;

    old = (mac_addr_t *)hashtable_remove(mac_vrf->mac_ip_binding, &ip_addr);
    if (old)
        XFREE(old);

    key = (uint32_t *)XCALLOC2(0, 1, uint32_t);
    *key = ip_addr;
    val = (mac_addr_t *)XCALLOC2(0, 1, mac_addr_t);
    memcpy(val->mac, mac->mac, MAC_ADDR_SIZE);

    if (!hashtable_insert(mac_vrf->mac_ip_binding, key, val)) {
        XFREE(key);
        XFREE(val);
    }

    cp2dp_arp_sup_cache_entry_add(mac_vrf->vrf->node, 
                                  mac_vrf->evpn_inst->bd_intf->ifindex,
                                  ip_addr, (uint8_t *)mac->mac, true);
}

static void
mac_vrf_mac_ip_binding_del(mac_vrf_t *mac_vrf, uint32_t ip_addr)
{
    mac_addr_t *val;

    if (!mac_vrf || !mac_vrf->mac_ip_binding || ip_addr == 0)
        return;

    val = (mac_addr_t *)hashtable_remove(mac_vrf->mac_ip_binding, &ip_addr);

    if (val) {
        cp2dp_arp_sup_cache_entry_del(
                mac_vrf->vrf->node, 
                mac_vrf->evpn_inst->bd_intf->ifindex, 
                ip_addr,
                true);

        XFREE(val);
    }
}

static void
mac_vrf_fill_broadcast_mac(mac_addr_t *mac)
{
    layer2_fill_with_broadcast_mac(mac->mac);
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

    mac_vrf->type3_rib = create_hashtable(MAC_VRF_TYPE3_HT_SIZE,
                                          mac_vrf_type3_hash,
                                          mac_vrf_type3_key_equal);
    assert(mac_vrf->type3_rib);

    mac_vrf->mac_ip_binding = create_hashtable(MAC_VRF_MAC_IP_HT_SIZE,
                                               mac_vrf_type3_hash,
                                               mac_vrf_type3_key_equal);
    assert(mac_vrf->mac_ip_binding);

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
    assert (!mac_vrf->type3_rib);
    assert (!mac_vrf->mac_ip_binding);
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

    if (mac_vrf->type3_rib) {
        hashtable_destroy(mac_vrf->type3_rib, 1);
        mac_vrf->type3_rib = NULL;
    }

    if (mac_vrf->mac_ip_binding) {
        hashtable_destroy(mac_vrf->mac_ip_binding, 1);
        mac_vrf->mac_ip_binding = NULL;
    }

    rtm_stop(mac_vrf->mac_rtm);
    rtm_check_and_delete(mac_vrf->mac_rtm, true);
    mac_vrf->mac_rtm = NULL;

    mac_vrf->evpn_inst = NULL;
    mac_vrf_check_and_delete(mac_vrf);
}

static rtm_error_t
mac_vrf_type2_rtm_install(
        mac_vrf_t *mac_vrf,
        node_t *node,
        mac_addr_t *mac_addr,
        uint32_t vtep_ip,
        uint32_t label,
        const char *mac_str)
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
            RTM_SUB_PROTO_BGP_EVPN,
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
               "EVPN Type-2 route %s failed RTM install into %s — %s\n",
               mac_str, mac_vrf->mac_rtm->name, rtm_error_to_string(rc));
        return rc;
    }

    tracer(node->cptr, DRTM_DET | DEVPN_DET,
           "EVPN Type-2 route %s installed into MAC VRF RTM %s\n",
           mac_str, mac_vrf->mac_rtm->name);
    return RTM_SUCCESS;
}

static rtm_error_t
mac_vrf_type2_rtm_uninstall(
        mac_vrf_t *mac_vrf,
        node_t *node,
        mac_addr_t *mac_addr,
        uint32_t vtep_ip,
        uint32_t label,
        const char *mac_str)
{
    cmn_prefix_t prefix;
    cmn_prefix_t gateway;
    rtm_error_t rc;

    memset(&prefix, 0, sizeof(prefix));
    prefix.afi = AF_MAC;
    prefix.prefix_len = 48;
    memcpy(prefix.u.mac_addr, mac_addr->mac, MAC_ADDR_SIZE);

    cmn_prefix_initialize_v4(&gateway, vtep_ip, 32);

    rc = cp_rtm_uninstall_route_advanced(
            mac_vrf->mac_rtm,
            &prefix,
            RTM_PROTO_BGP,
            RTM_SUB_PROTO_BGP_EVPN,
            0,
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
        tracer(node->cptr, DRTM | DERR,
               "EVPN Type-2 route %s failed RTM uninstall from %s — %s\n",
               mac_str, mac_vrf->mac_rtm->name, rtm_error_to_string(rc));
        return rc;
    }

    tracer(node->cptr, DRTM_DET | DEVPN_DET,
           "EVPN Type-2 route %s uninstalled from MAC VRF RTM %s\n",
           mac_str, mac_vrf->mac_rtm->name);
    return RTM_SUCCESS;
}

static void
mac_vrf_type2_remote_update_in_place(
        mac_vrf_t *mac_vrf,
        node_t *node,
        mac_addr_t *mac_addr,
        evpn_exp_rt_t *existing,
        uint32_t vtep_ip,
        uint32_t label,
        uint32_t seq_no,
        const char *mac_str,
        const char *host_ip_str)
{
    char vtep_str[16];
    uint32_t old_vtep = existing->vtep_ip;
    uint32_t old_label = existing->u.mac_only.label;

    if (existing->flags & EVPN_RT_F_REMOTE) {
        mac_vrf_type2_rtm_uninstall(mac_vrf, node, mac_addr,
                                    old_vtep, old_label, mac_str);
    }

    existing->flags = EVPN_RT_F_REMOTE;
    existing->vtep_ip = vtep_ip;
    existing->u.mac_only.label = label;
    existing->u.mac_only.seq_no = seq_no;

    mac_vrf_type2_rtm_install(mac_vrf, node, mac_addr, vtep_ip, label,
                              mac_str);

    ip_ntop(vtep_ip, (c_string)vtep_str);
    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote import route %s ip %s — updated in place "
           "seq %u VTEP %s label %u\n",
           mac_str, host_ip_str, seq_no, vtep_str, label);
}

static evpn_exp_rt_t *
mac_vrf_type2_alloc_route(
        node_t *node,
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t ip_addr,
        uint32_t vtep_ip,
        uint32_t label,
        uint8_t flags,
        uint32_t seq_no)
{
    evpn_exp_rt_t *evpn_rt;

    evpn_rt = (evpn_exp_rt_t *)XCALLOC2(0, 1, evpn_exp_rt_t);
    if (!evpn_rt)
        return NULL;

    evpn_rt->type = EVPN_RT_TYPE_MAC_ONLY;
    evpn_rt->flags = flags;
    evpn_rt->vtep_ip = vtep_ip;
    memcpy(evpn_rt->u.mac_only.mac.mac, mac_addr->mac, MAC_ADDR_SIZE);
    evpn_rt->u.mac_only.ip_addr = ip_addr;
    evpn_rt->u.mac_only.label = label;
    evpn_rt->u.mac_only.seq_no = seq_no;

    if (flags & EVPN_RT_F_LOCAL) {
        evpn_rt->vtep_ip = NODE_RTR_ID_INT(node);
        evpn_rt->u.mac_only.label = mac_vrf->evpn_inst->bd_intf->vpn_svc_label;
    }

    return evpn_rt;
}

static bool
mac_vrf_type2_rib_insert(
        node_t *node,
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t ip_addr,
        evpn_exp_rt_t *evpn_rt,
        const char *mac_str,
        const char *ip_str)
{
    mac_vrf_type2_key_t *key;

    key = mac_vrf_type2_key_alloc(mac_addr, ip_addr);
    if (!key) {
        XFREE(evpn_rt);
        return false;
    }

    if (!hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
        tracer(node->cptr, DEVPN | DERR,
               "EVPN Type-2 route %s ip %s failed — hashtable insert\n",
               mac_str, ip_str);
        XFREE(key);
        XFREE(evpn_rt);
        return false;
    }

    return true;
}

static evpn_exp_rt_t *
mac_vrf_type2_rib_remove(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t ip_addr)
{
    mac_vrf_type2_key_t lookup_key;
    evpn_exp_rt_t *evpn_rt;

    mac_vrf_type2_key_init(&lookup_key, mac_addr, ip_addr);
    evpn_rt = (evpn_exp_rt_t *)hashtable_remove(mac_vrf->type2_rib, &lookup_key);
    return evpn_rt;
}

void 
mac_vrf_evpn_route_type2_local_import(
                node_t *node,
                mac_vrf_t *mac_vrf, 
                mac_addr_t *mac_addr,
                uint32_t ip_addr) {

    mac_vrf_type2_key_t lookup_key;
    evpn_exp_rt_t *evpn_rt;
    evpn_exp_rt_t *existing;
    char mac_str[MAC_VRF_MAC_STR_LEN];
    char ip_str[16];
    uint32_t new_seq;

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));
    ip_ntop(ip_addr, (c_string)ip_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s ip %s mac-vrf %u\n",
           mac_str, ip_str, mac_vrf->mac_vrf_id);

    mac_vrf_type2_key_init(&lookup_key, mac_addr, ip_addr);
    existing = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type2_rib, &lookup_key);

    if (!existing) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 local import route %s ip %s — absent, "
               "install local seq 0\n",
               mac_str, ip_str);

        evpn_rt = mac_vrf_type2_alloc_route(
                node, mac_vrf, mac_addr, ip_addr, 0, 0,
                EVPN_RT_F_LOCAL, 0);
        if (!evpn_rt)
            return;

        if (!mac_vrf_type2_rib_insert(node, mac_vrf, mac_addr, ip_addr,
                                      evpn_rt, mac_str, ip_str)) {
            return;
        }

        mac_vrf_mac_ip_binding_add(mac_vrf, ip_addr, mac_addr);

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 local import route %s ip %s installed label %u "
               "seq 0, exporting to BGP\n",
               mac_str, ip_str, evpn_rt->u.mac_only.label);

        evpn_route_export_to_bgp(node,
                                 &mac_vrf->evpn_inst->rd,
                                 &mac_vrf->evpn_inst->export_rt,
                                 evpn_rt,
                                 false);
        return;
    }

    if (existing->flags & EVPN_RT_F_LOCAL) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 local import route %s ip %s — existing local "
               "seq %u, no-op\n",
               mac_str, ip_str, existing->u.mac_only.seq_no);
        return;
    }

    new_seq = existing->u.mac_only.seq_no + 1;

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s ip %s — existing remote "
           "seq %u, mobility takeover with local seq %u\n",
           mac_str, ip_str, existing->u.mac_only.seq_no, new_seq);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s ip %s — uninstall remote "
           "from RTM\n",
           mac_str, ip_str);

    mac_vrf_type2_rtm_uninstall(mac_vrf, node, mac_addr,
                                existing->vtep_ip,
                                existing->u.mac_only.label,
                                mac_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s ip %s — delete remote "
           "MAC-VRF entry\n",
           mac_str, ip_str);

    mac_vrf_type2_rib_remove(mac_vrf, mac_addr, ip_addr);
    XFREE(existing);

    evpn_rt = mac_vrf_type2_alloc_route(
            node, mac_vrf, 
            mac_addr, 
            ip_addr, 
            NODE_RTR_ID_INT(node), 
            mac_vrf->evpn_inst->bd_intf->vpn_svc_label,
            EVPN_RT_F_LOCAL, new_seq);
    if (!evpn_rt)
        return;

    if (!mac_vrf_type2_rib_insert(node, mac_vrf, mac_addr, ip_addr,
                                  evpn_rt, mac_str, ip_str)) {
        return;
    }

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 local import route %s ip %s installed label %u "
           "seq %u, exporting to BGP\n",
           mac_str, ip_str, evpn_rt->u.mac_only.label, new_seq);

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
                mac_addr_t *mac_addr,
                uint32_t ip_addr) {

    mac_vrf_type2_key_t lookup_key;
    evpn_exp_rt_t *evpn_rt;
    char mac_str[MAC_VRF_MAC_STR_LEN];
    char ip_str[16];

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));
    ip_ntop(ip_addr, (c_string)ip_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 delete route %s ip %s mac-vrf %u\n",
           mac_str, ip_str, mac_vrf->mac_vrf_id);

    mac_vrf_type2_key_init(&lookup_key, mac_addr, ip_addr);
    evpn_rt = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type2_rib, &lookup_key);

    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 delete route %s ip %s skipped — not in RIB\n",
               mac_str, ip_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 delete route %s ip %s — withdraw local from BGP\n",
               mac_str, ip_str);

        evpn_route_export_to_bgp(node,
                                     &mac_vrf->evpn_inst->rd,
                                     &mac_vrf->evpn_inst->export_rt,
                                     evpn_rt,
                                     true);
        
    }
    else if (evpn_rt->flags & EVPN_RT_F_REMOTE) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 delete route %s ip %s — remote (RTM uninstall)\n",
               mac_str, ip_str);
        
        /* 1. Send Delete to RTM --> Mac (Redundant )*/
        mac_vrf_evpn_route_type2_remote_delete(
                mac_vrf, mac_addr, ip_addr,
                MAC_VRF_TYPE2_WITHDRAW_SEQ_FORCE, true);

        /* ToDo : If the Delete was triggered by CLI command ( instead of BGP 
            withdrawing the route), then ask BGP to replay back remotely learnt 
            routes (through Job)*/
        return;
    }

    hashtable_remove(mac_vrf->type2_rib, &lookup_key);
    mac_vrf_mac_ip_binding_del(mac_vrf, evpn_rt->u.mac_only.ip_addr);
    XFREE(evpn_rt);
}

void
mac_vrf_evpn_route_type2_delete_by_mac (
                node_t *node,
                mac_vrf_t *mac_vrf,
                mac_addr_t *mac_addr)
{
    struct hashtable_itr *itr;
    mac_vrf_type2_key_t *keys = NULL;
    unsigned int count;
    unsigned int n = 0;
    unsigned int i;

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr)
        return;

    count = hashtable_count(mac_vrf->type2_rib);
    if (count == 0)
        return;

    keys = (mac_vrf_type2_key_t *)XCALLOC_BUFF(
                0, count * sizeof(mac_vrf_type2_key_t));
    if (!keys)
        return;

    itr = hashtable_iterator(mac_vrf->type2_rib);
    if (!itr) {
        XFREE(keys);
        return;
    }

    do {
        mac_vrf_type2_key_t *key =
            (mac_vrf_type2_key_t *)hashtable_iterator_key(itr);
        if (!key)
            break;
        if (memcmp(key->mac.mac, mac_addr->mac, MAC_ADDR_SIZE) != 0)
            continue;
        if (n < count)
            keys[n++] = *key;
    } while (hashtable_iterator_advance(itr));

    free(itr);

    for (i = 0; i < n; i++)
        mac_vrf_evpn_route_type2_delete(node, mac_vrf, &keys[i].mac,
                                        keys[i].ip_addr);

    XFREE(keys);
}

void
mac_vrf_evpn_route_type2_remote_import(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t ip_addr,
        uint32_t vtep_ip,
        uint32_t label,
        uint32_t seq_no)
{
    mac_vrf_type2_key_t lookup_key;
    evpn_exp_rt_t *evpn_rt;
    evpn_exp_rt_t *existing;
    char ip_addr_str[16];
    char host_ip_str[16];
    char mac_str[MAC_VRF_MAC_STR_LEN];

    node_t *node = mac_vrf->vrf->node;

    if (!mac_vrf || !mac_vrf->type2_rib || !mac_addr) {
        return;
    }

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));
    ip_ntop(ip_addr, (c_string)host_ip_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote import route %s ip %s VTEP %s label %u "
           "seq %u mac-vrf %u\n",
           mac_str, host_ip_str,
           ip_ntop(vtep_ip, (c_string)ip_addr_str),
           label, seq_no, mac_vrf->mac_vrf_id);

    mac_vrf_type2_key_init(&lookup_key, mac_addr, ip_addr);
    existing = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type2_rib, &lookup_key);

    if (!existing) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 remote import route %s ip %s — absent, "
               "install remote seq %u\n",
               mac_str, host_ip_str, seq_no);

        evpn_rt = mac_vrf_type2_alloc_route(
                node, mac_vrf, mac_addr, ip_addr, vtep_ip, label,
                EVPN_RT_F_REMOTE, seq_no);
        if (!evpn_rt)
            return;

        if (!mac_vrf_type2_rib_insert(node, mac_vrf, mac_addr, ip_addr,
                                      evpn_rt, mac_str, host_ip_str)) {
            return;
        }

        mac_vrf_mac_ip_binding_add(mac_vrf, ip_addr, mac_addr);

        mac_vrf_type2_rtm_install(mac_vrf, node, mac_addr, vtep_ip, label,
                                  mac_str);
        return;
    }

    if (existing->flags & EVPN_RT_F_LOCAL) {

        if (seq_no <= existing->u.mac_only.seq_no) {

            tracer(node->cptr, DEVPN,
                   "EVPN Type-2 remote import route %s ip %s — incoming "
                   "seq %u <= local seq %u, ignore\n",
                   mac_str, host_ip_str, seq_no,
                   existing->u.mac_only.seq_no);
            return;
        }

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 remote import route %s ip %s — incoming "
               "seq %u > local seq %u, remote wins\n",
               mac_str, host_ip_str, seq_no, existing->u.mac_only.seq_no);

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 remote import route %s ip %s — withdraw "
               "local from BGP\n",
               mac_str, host_ip_str);

        evpn_route_export_to_bgp(node,
                                 &mac_vrf->evpn_inst->rd,
                                 &mac_vrf->evpn_inst->export_rt,
                                 existing,
                                 true);

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 remote import route %s ip %s — remote wins, "
               "update local entry in place\n",
               mac_str, host_ip_str);

        mac_vrf_type2_remote_update_in_place(
                mac_vrf, node, mac_addr, existing,
                vtep_ip, label, seq_no, mac_str, host_ip_str);
        return;
    }

    if (seq_no <= existing->u.mac_only.seq_no) {

        tracer(node->cptr, DEVPN,
               "EVPN Type-2 remote import route %s ip %s — incoming "
               "seq %u <= remote seq %u, ignore\n",
               mac_str, host_ip_str, seq_no, existing->u.mac_only.seq_no);
        return;
    }

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote import route %s ip %s — incoming "
           "seq %u > remote seq %u, replace remote in place\n",
           mac_str, host_ip_str, seq_no, existing->u.mac_only.seq_no);

    mac_vrf_type2_remote_update_in_place(
            mac_vrf, node, mac_addr, existing,
            vtep_ip, label, seq_no, mac_str, host_ip_str);
}

void
mac_vrf_evpn_route_type2_remote_delete(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t ip_addr,
        uint32_t withdraw_seq,
        bool withdraw_seq_present)
{
    mac_vrf_type2_key_t lookup_key;
    evpn_exp_rt_t *evpn_rt;
    char mac_str[MAC_VRF_MAC_STR_LEN];
    char ip_str[16];

    node_t *node = mac_vrf->vrf->node;

    mac_vrf_format_mac(mac_addr, mac_str, sizeof(mac_str));
    ip_ntop(ip_addr, (c_string)ip_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-2 remote delete route %s ip %s mac-vrf %u "
           "withdraw-seq %u%s\n",
           mac_str, ip_str, mac_vrf->mac_vrf_id,
           withdraw_seq, withdraw_seq_present ? "" : " (absent)");

    mac_vrf_type2_key_init(&lookup_key, mac_addr, ip_addr);
    evpn_rt = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type2_rib, &lookup_key);

    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 remote delete route %s ip %s skipped — not in RIB\n",
               mac_str, ip_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_REMOTE) {
        uint32_t existing_seq = evpn_rt->u.mac_only.seq_no;

        if (withdraw_seq_present) {
            if (existing_seq > withdraw_seq) {
                tracer(node->cptr, DEVPN,
                       "EVPN Type-2 remote delete route %s ip %s skipped — "
                       "stale withdraw seq %u < existing seq %u\n",
                       mac_str, ip_str, withdraw_seq, existing_seq);
                return;
            }
        } else if (existing_seq > 0) {
            tracer(node->cptr, DEVPN,
                   "EVPN Type-2 remote delete route %s ip %s skipped — "
                   "withdraw without mobility seq, existing seq %u\n",
                   mac_str, ip_str, existing_seq);
            return;
        }
    }

    evpn_rt = (evpn_exp_rt_t *)hashtable_remove(mac_vrf->type2_rib, &lookup_key);

    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 remote delete route %s ip %s skipped — not in RIB\n",
               mac_str, ip_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {
        mac_vrf_type2_key_t *key =
            mac_vrf_type2_key_alloc(mac_addr, evpn_rt->u.mac_only.ip_addr);

        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-2 remote delete route %s ip %s skipped — "
               "local route preferred\n",
               mac_str, ip_str);

        if (!key || !hashtable_insert(mac_vrf->type2_rib, key, evpn_rt)) {
            mac_vrf_mac_ip_binding_del(mac_vrf, evpn_rt->u.mac_only.ip_addr);
            if (key)
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
                RTM_SUB_PROTO_BGP_EVPN,
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

    mac_vrf_mac_ip_binding_del(mac_vrf, evpn_rt->u.mac_only.ip_addr);
    XFREE(evpn_rt);
}

void
mac_vrf_evpn_route_type3_local_import(
        node_t *node,
        mac_vrf_t *mac_vrf)
{
    uint32_t *key;
    uint32_t pe_addr;
    evpn_exp_rt_t *evpn_rt;
    char ip_addr_str[16];

    if (!mac_vrf || !mac_vrf->type3_rib || !mac_vrf->evpn_inst ||
        !mac_vrf->evpn_inst->bd_intf) {
        return;
    }

    pe_addr = NODE_RTR_ID_INT(node);
    ip_ntop(pe_addr, (c_string)ip_addr_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-3 local import route PE %s mac-vrf %u\n",
           ip_addr_str, mac_vrf->mac_vrf_id);

    if (hashtable_search(mac_vrf->type3_rib, &pe_addr)) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-3 local import route PE %s skipped — already in RIB\n",
               ip_addr_str);
        return;
    }

    key = (uint32_t *)XCALLOC2(0, 1, uint32_t);
    *key = pe_addr;

    evpn_rt = (evpn_exp_rt_t *)XCALLOC2(0, 1, evpn_exp_rt_t);
    evpn_rt->type = EVPN_RT_TYPE_IMET;
    evpn_rt->flags = EVPN_RT_F_LOCAL;
    evpn_rt->vtep_ip = pe_addr;
    evpn_rt->u.imet.pe_addr = pe_addr;
    evpn_rt->u.imet.evpn_label =
        mac_vrf->evpn_inst->bd_intf->vpn_bum_label;

    if (!hashtable_insert(mac_vrf->type3_rib, key, evpn_rt)) {
        tracer(node->cptr, DEVPN | DERR,
               "EVPN Type-3 local import route PE %s failed — hashtable insert\n",
               ip_addr_str);
        XFREE(key);
        XFREE(evpn_rt);
        return;
    }

    tracer(node->cptr, DEVPN,
           "EVPN Type-3 local import route PE %s installed BUM label %u, "
           "exporting to BGP\n",
           ip_addr_str, evpn_rt->u.imet.evpn_label);

    evpn_route_export_to_bgp(node,
                             &mac_vrf->evpn_inst->rd,
                             &mac_vrf->evpn_inst->export_rt,
                             evpn_rt,
                             false);
}

void
mac_vrf_evpn_route_type3_delete(
        node_t *node,
        mac_vrf_t *mac_vrf)
{
    uint32_t pe_addr;
    evpn_exp_rt_t *evpn_rt;
    char ip_addr_str[16];

    if (!mac_vrf || !mac_vrf->type3_rib || !mac_vrf->evpn_inst) {
        return;
    }

    pe_addr = NODE_RTR_ID_INT(node);
    ip_ntop(pe_addr, (c_string)ip_addr_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-3 delete route PE %s mac-vrf %u\n",
           ip_addr_str, mac_vrf->mac_vrf_id);

    evpn_rt = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type3_rib, &pe_addr);
    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-3 delete route PE %s skipped — not in RIB\n",
               ip_addr_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {
        tracer(node->cptr, DEVPN,
               "EVPN Type-3 delete route PE %s — withdraw local from BGP\n",
               ip_addr_str);

        evpn_route_export_to_bgp(node,
                                 &mac_vrf->evpn_inst->rd,
                                 &mac_vrf->evpn_inst->export_rt,
                                 evpn_rt,
                                 true);
    }
    else if (evpn_rt->flags & EVPN_RT_F_REMOTE) {
        mac_vrf_evpn_route_type3_remote_delete(mac_vrf, pe_addr);
    }

    hashtable_remove(mac_vrf->type3_rib, &pe_addr);
    XFREE(evpn_rt);
}

void
mac_vrf_evpn_route_type3_remote_import(
        mac_vrf_t *mac_vrf,
        uint32_t pe_addr,
        uint32_t vtep_ip,
        uint32_t label)
{
    uint32_t *key;
    evpn_exp_rt_t *evpn_rt;
    evpn_exp_rt_t *existing;
    mac_addr_t bcast_mac;
    char pe_str[16];
    char nh_str[16];
    node_t *node;

    if (!mac_vrf || !mac_vrf->type3_rib) {
        return;
    }

    node = mac_vrf->vrf->node;
    ip_ntop(pe_addr, (c_string)pe_str);
    ip_ntop(vtep_ip, (c_string)nh_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-3 remote import route PE %s VTEP %s label %u mac-vrf %u\n",
           pe_str, nh_str, label, mac_vrf->mac_vrf_id);

    existing = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type3_rib, &pe_addr);
    if (existing) {
        if (existing->flags & EVPN_RT_F_LOCAL) {
            tracer(node->cptr, DEVPN | DERR,
                   "EVPN Type-3 remote import route PE %s skipped — "
                   "local already exists in MAC VRF %d\n",
                   pe_str, mac_vrf->mac_vrf_id);
        }
        else {
            tracer(node->cptr, DEVPN_DET,
                   "EVPN Type-3 remote import route PE %s skipped — "
                   "already in RIB\n",
                   pe_str);
        }
        return;
    }

    key = (uint32_t *)XCALLOC2(0, 1, uint32_t);
    *key = pe_addr;

    evpn_rt = (evpn_exp_rt_t *)XCALLOC2(0, 1, evpn_exp_rt_t);
    evpn_rt->type = EVPN_RT_TYPE_IMET;
    evpn_rt->flags = EVPN_RT_F_REMOTE;
    evpn_rt->vtep_ip = vtep_ip;
    evpn_rt->u.imet.pe_addr = pe_addr;
    evpn_rt->u.imet.evpn_label = label;

    if (!hashtable_insert(mac_vrf->type3_rib, key, evpn_rt)) {
        tracer(node->cptr, DEVPN | DERR,
               "EVPN Type-3 remote import route PE %s failed — "
               "hashtable insert\n",
               pe_str);
        XFREE(key);
        XFREE(evpn_rt);
        return;
    }

    mac_vrf_fill_broadcast_mac(&bcast_mac);

    {
        cmn_prefix_t prefix;
        cmn_prefix_t gateway;
        rtm_error_t rc;

        memset(&prefix, 0, sizeof(prefix));
        prefix.afi = AF_MAC;
        prefix.prefix_len = 48;
        memcpy(prefix.u.mac_addr, bcast_mac.mac, MAC_ADDR_SIZE);

        cmn_prefix_initialize_v4(&gateway, vtep_ip, 32);

        rc = cp_rtm_install_route_advanced(
                mac_vrf->mac_rtm,
                &prefix,
                RTM_PROTO_BGP,
                RTM_SUB_PROTO_BGP_EVPN,
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
                   "EVPN Type-3 remote import route PE %s failed RTM install "
                   "into %s — %s\n",
                   pe_str, mac_vrf->mac_rtm->name,
                   rtm_error_to_string(rc));
            return;
        }

        tracer(node->cptr, DRTM_DET | DEVPN_DET,
               "EVPN Type-3 remote import route PE %s installed broadcast "
               "MAC into MAC VRF RTM %s\n",
               pe_str, mac_vrf->mac_rtm->name);
    }
}

void
mac_vrf_evpn_route_type3_remote_delete(
        mac_vrf_t *mac_vrf,
        uint32_t pe_addr)
{
    evpn_exp_rt_t *evpn_rt;
    mac_addr_t bcast_mac;
    char pe_str[16];
    node_t *node;

    node = mac_vrf->vrf->node;
    ip_ntop(pe_addr, (c_string)pe_str);

    tracer(node->cptr, DEVPN,
           "EVPN Type-3 remote delete route PE %s mac-vrf %u\n",
           pe_str, mac_vrf->mac_vrf_id);

    evpn_rt = (evpn_exp_rt_t *)hashtable_remove(mac_vrf->type3_rib, &pe_addr);
    if (!evpn_rt) {
        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-3 remote delete route PE %s skipped — not in RIB\n",
               pe_str);
        return;
    }

    if (evpn_rt->flags & EVPN_RT_F_LOCAL) {
        uint32_t *key = (uint32_t *)XCALLOC2(0, 1, uint32_t);

        tracer(node->cptr, DEVPN_DET,
               "EVPN Type-3 remote delete route PE %s skipped — "
               "local route preferred\n",
               pe_str);

        *key = pe_addr;
        if (!hashtable_insert(mac_vrf->type3_rib, key, evpn_rt)) {
            XFREE(key);
            XFREE(evpn_rt);
        }
        return;
    }

    mac_vrf_fill_broadcast_mac(&bcast_mac);

    {
        cmn_prefix_t prefix;
        cmn_prefix_t gateway;
        rtm_error_t rc;

        memset(&prefix, 0, sizeof(prefix));
        prefix.afi = AF_MAC;
        prefix.prefix_len = 48;
        memcpy(prefix.u.mac_addr, bcast_mac.mac, MAC_ADDR_SIZE);

        cmn_prefix_initialize_v4(&gateway, evpn_rt->vtep_ip, 32);

        rc = cp_rtm_uninstall_route_advanced(
                mac_vrf->mac_rtm,
                &prefix,
                RTM_PROTO_BGP,
                RTM_SUB_PROTO_BGP_EVPN,
                0,
                RTM_NH_ACTION_TUNNEL,
                1,
                &gateway,
                0,
                INTF_TYPE_UNKNOWN,
                NULL,
                0,
                (mpls_label_val_t)evpn_rt->u.imet.evpn_label,
                MPLS_OP_STACK_OPS_UNKNOWN,
                mac_vrf->evpn_inst->bd_intf->ifindex);

        if (rc != RTM_SUCCESS) {
            tracer(node->cptr, DRTM | DERR,
                   "EVPN Type-3 remote delete route PE %s failed RTM uninstall "
                   "from %s — %s\n",
                   pe_str, mac_vrf->mac_rtm->name,
                   rtm_error_to_string(rc));
        }
        else {
            tracer(node->cptr, DRTM_DET,
                   "EVPN Type-3 remote delete route PE %s uninstalled from "
                   "MAC VRF RTM %s\n",
                   pe_str, mac_vrf->mac_rtm->name);
        }
    }

    XFREE(evpn_rt);
}

void 
mac_vrf_delete_all_remote_evpn_routes(mac_vrf_t *mac_vrf)
{
    struct hashtable_itr *itr;
    mac_vrf_type2_key_t *keys = NULL;
    unsigned int count;
    unsigned int n = 0;
    unsigned int i;

    if (!mac_vrf || !mac_vrf->type2_rib)
    {
        return;
    }

    if (mac_vrf->mac_rtm)
    {
        cp_rtm_uninstall_routes_by_proto(mac_vrf->mac_rtm,
                                         RTM_PROTO_BGP,
                                         RTM_SUB_PROTO_BGP_EVPN,
                                         0);
    }

    do
    {
        count = hashtable_count(mac_vrf->type2_rib);
        if (count == 0)
        {
            break;
        }

        keys = (mac_vrf_type2_key_t *)XCALLOC_BUFF(
                    0, count * sizeof(mac_vrf_type2_key_t));
        if (!keys)
        {
            break;
        }

        itr = hashtable_iterator(mac_vrf->type2_rib);
        if (!itr)
        {
            XFREE(keys);
            break;
        }

        do
        {
            mac_vrf_type2_key_t *key =
                (mac_vrf_type2_key_t *)hashtable_iterator_key(itr);
            evpn_exp_rt_t *evpn_rt =
                (evpn_exp_rt_t *)hashtable_iterator_value(itr);

            if (!key || !evpn_rt)
            {
                break;
            }

            if (evpn_rt->flags & EVPN_RT_F_LOCAL)
            {
                continue;
            }

            if (n < count)
            {
                keys[n] = *key;
                n++;
            }
        } while (hashtable_iterator_advance(itr));

        free(itr);

        for (i = 0; i < n; i++)
        {
            evpn_exp_rt_t *evpn_rt =
                (evpn_exp_rt_t *)hashtable_remove(mac_vrf->type2_rib, &keys[i]);
            if (evpn_rt)
            {
                mac_vrf_mac_ip_binding_del(mac_vrf, evpn_rt->u.mac_only.ip_addr);
                XFREE(evpn_rt);
            }
        }

        XFREE(keys);

    } while (0);

    if (!mac_vrf->type3_rib || hashtable_count(mac_vrf->type3_rib) == 0)
    {
        return;
    }

    {
        uint32_t *pe_keys = NULL;
        unsigned int pe_count;
        unsigned int pe_n = 0;

        pe_count = hashtable_count(mac_vrf->type3_rib);
        pe_keys = (uint32_t *)XCALLOC_BUFF(0, pe_count * sizeof(uint32_t));
        if (!pe_keys)
        {
            return;
        }

        itr = hashtable_iterator(mac_vrf->type3_rib);
        if (!itr)
        {
            XFREE(pe_keys);
            return;
        }

        do
        {
            uint32_t *key = (uint32_t *)hashtable_iterator_key(itr);
            evpn_exp_rt_t *evpn_rt =
                (evpn_exp_rt_t *)hashtable_iterator_value(itr);

            if (!key || !evpn_rt)
            {
                break;
            }

            if (evpn_rt->flags & EVPN_RT_F_LOCAL)
            {
                continue;
            }

            if (pe_n < pe_count)
            {
                pe_keys[pe_n++] = *key;
            }
        } while (hashtable_iterator_advance(itr));

        free(itr);

        for (i = 0; i < pe_n; i++)
        {
            evpn_exp_rt_t *evpn_rt =
                (evpn_exp_rt_t *)hashtable_remove(mac_vrf->type3_rib,
                                                  &pe_keys[i]);
            if (evpn_rt)
            {
                XFREE(evpn_rt);
            }
        }

        XFREE(pe_keys);
    }
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

/* Called when BGP L2VPN/EVPN afi/safi is configured by user. Export all
    locally learnt Type 2 and Type 3 routes to bgp. This is required
    only for  L2VPN/EVPN afi/safi since exporting vpnv4 and unicast afi/safi
    are taken care of by dist-mgr */
void 
mac_vrf_export_evpn_local_evpn_routes_to_bgp(node_t *node, evpn_inst_t *evpn) {

    hashtable_t *ht;
    hashtable_itr *itr;
    mac_vrf_t *mac_vrf;
    evpn_exp_rt_t *evpn_rt;

    do {

        if (!evpn) return;
        mac_vrf = evpn->mac_vrf;
        if (!mac_vrf) return;

        /* Export Type 2 Routes */
        ht = mac_vrf->type2_rib;
        if (!ht) break;

        if (!hashtable_count(ht)) break;

        itr = hashtable_iterator(ht);

        do {

            evpn_rt = (evpn_exp_rt_t *)hashtable_iterator_value(itr);

            if (evpn_rt->flags & EVPN_RT_F_LOCAL) { 

                evpn_route_export_to_bgp(node,
                             &mac_vrf->evpn_inst->rd,
                             &mac_vrf->evpn_inst->export_rt,
                             evpn_rt,
                             false);
            }
        } while (hashtable_iterator_advance(itr));

        free(itr);

    } while (0);

    /* Export Type 3 Routes */
    ht = mac_vrf->type3_rib;
    if (!ht)
        return;
    if (!hashtable_count(ht))
        return;

    itr = hashtable_iterator(ht);

    do
    {

        evpn_rt = (evpn_exp_rt_t *)hashtable_iterator_value(itr);

        if (evpn_rt->flags & EVPN_RT_F_LOCAL) { 

            evpn_route_export_to_bgp(node,
                                 &mac_vrf->evpn_inst->rd,
                                 &mac_vrf->evpn_inst->export_rt,
                                 evpn_rt,
                                 false);
        }
    } while (hashtable_iterator_advance(itr));

    free(itr);
}

void 
mac_vrf_export_all_local_evpn_routes_to_bgp(node_t *node) {

    int i;
    evpn_inst_t *evpn;

    for (i = 0; i < MAX_EVPN_INDEX; i++) {

        evpn = node->evpn[i];
        if (!evpn) continue;
        mac_vrf_export_evpn_local_evpn_routes_to_bgp (node, evpn);
    }
}