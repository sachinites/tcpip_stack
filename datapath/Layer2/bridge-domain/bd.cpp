#include <stddef.h>
#include <assert.h>
#include "bd.h"

#include "../../../libs/common/l2_hdrs.h"
#include "../../../libs/common/cmn_struct.h"
#include "../../../libs/common/mpls_lstack.h"
#include "../../../libs/Tracer/tracer.h"

#include "../switching/mac_table.h"
#include "../arp/arp.h"
#include "arp_sup_cache.h"

#include "../../dp_ctx.h"
#include "../../dp_uapi.h"
#include "../../dp_utils.h"
#include "../../Interface/dp_intf.h"
#include "../../Interface/dp_intf_store.h"
#include "../../Interface/intf_cons.h"
#include "../../dp-program/dp-prog-api.h"
#include "../../dp-program/dp-prog-struct.h"
#include "../../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../../dp_const.h"
#include "../../../libs/libtimer/WheelTimer.h"

extern bool
mpls_apply_nh_label_stack(dp_ctx_t *dp_ctx,
                          struct rte_mbuf *mbuf,
                          mpls_lstack_t *lstack);

int 
AC_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *ac, 
        struct rte_mbuf *mbuf, uint32_t ctx) {

    (void)ctx;

    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));
    
    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD,
        "Pkt:%s Intf:%s\n", pkt_mbuf_str(mbuf), ac->if_name); 

    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    if (vlan_8021q_hdr) {

        pkt_tracer(mbuf, dp_ctx->dptr, DL2SW | DERR,
            "Error : Egress AC %s recvd vlan tagged pkt %s, pkt dropped\n", 
            ac->if_name, pkt_mbuf_str(mbuf));
        ac->xmit_pkt_dropped++;
        return -1;
    }

    /* Add 802.1q tag to the pkt */
    uint16_t vlan_id = ac->encap_8021q_tag;

    /* Tag packet with vlan id */
    tag_pkt_with_vlan_id(mbuf, vlan_id);

    /* Send the pkt out of underlying physical interface */
    dp_send_pkt_out(dp_ctx, ac->underlying_intf, mbuf, 0);

    return 0;
}

/* This interface is responsible to flood the packet out of vlan interface 
    This function assumes that outter most header of the packet is untagged 
    ethernet hdr.
*/
int 
BD_FloodPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *bd_vfif, 
        struct rte_mbuf *mbuf,
        uint32_t ctx) {

    dp_intf_t *ac ;
    dp_intf_t *bd_intf;

    /* Can be NULL, Or ingress Attachment Ckt Or Overlay Tunnel*/
    dp_intf_t *exempt_ac = pkt_mbuf_get_ingress_intf(dp_ctx, mbuf);
    if (exempt_ac && exempt_ac->ac_intf) exempt_ac = exempt_ac->ac_intf;

    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD,
        "Pkt:%s Intf:%s\n", pkt_mbuf_str(mbuf), bd_vfif->if_name); 

    bd_intf = dp_ctx->intf_table[ctx];

    if (!bd_intf) {
        pkt_tracer(mbuf, dp_ctx->dptr, DL2SW | DERR,
            "Error : BD flood: Pkt:%s : BD intf not found, pkt is dropped\n", 
            pkt_mbuf_str(mbuf));
        return -1;
    }

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW,
        "Flooding the Pkt:%s in BD %s, exempt intf %s\n", 
        pkt_mbuf_str(mbuf), 
        bd_intf->if_name, exempt_ac ? exempt_ac->if_name: "Nil");

    /* Iterate over all ACs of BD */
    struct rte_mbuf *dup_mbuf;
    int count = 0;

    for (int i = 0; i < MAX_BD_MEMBER_PORTS; i++)
    {
        ac = bd_intf->mports[i];

        if (!ac || ac == exempt_ac) continue;

        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD_DET | DFLOW_DET,
            "BD:%s Flooding the pkt on AC:%s\n", bd_intf->if_name, ac->if_name);
            
        dup_mbuf = PKT_MBUF_DUP(mbuf);
        dp_send_pkt_out(dp_ctx, ac, dup_mbuf, 0);
        pkt_mbuf_dereference(dup_mbuf);
        count++;
    }

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW,
        "pkt %s flooded in BD %s in %u ACs\n", pkt_mbuf_str(mbuf), bd_intf->if_name, count);

    bd_intf->pkt_sent++;
    return 0;
}

static void 
bd_ac_set_name (dp_intf_t *ac, const char *name) {
    
    snprintf (ac->if_name, sizeof(ac->if_name) - 1, "ac-%s", name);
    ac->if_name[sizeof(ac->if_name) - 1] = '\0';
}


dp_intf_t *
bd_ac_create (dp_ctx_t *dp_ctx, uint32_t ifindex ) {

    uint8_t mac_addr[6] = {0};

    /* Create AC interface */
    dp_intf_t *ac = dp_create_interface(ifindex, DP_INTF_TYPE_AC, &mac_addr, 0);

    /* Set default members */
    ac->switchport = true;
    ac->l2_mode = DP_LAN_ACCESS_MODE;
    ac->is_up = true;

    bd_ac_set_name (ac, dp_ctx->intf_table[ifindex]->if_name);

    /* Look up the underlying physical interface */
    ac->underlying_intf = dp_ctx->intf_table[ifindex];
    assert (ac->underlying_intf);
    ac->underlying_intf->ac_intf = ac;
    ac->dp_ctx = dp_ctx;
    return ac;
}


void 
bd_add_ac (dp_intf_t *bd_intf, dp_intf_t *ac) {

    int i;
    assert(ac->bd_intf == NULL);
    for (i = 0; i < MAX_BD_MEMBER_PORTS; i++) {
        if (bd_intf->mports[i] == NULL) {
            bd_intf->mports[i] = ac;
            break;
        }
    }
    assert (i < MAX_BD_MEMBER_PORTS);
    ac->bd_intf = bd_intf;
}

bool 
bd_has_ac_member (dp_intf_t *bd_intf, uint32_t ifindex) {

    int i;
    for (i = 0; i < MAX_BD_MEMBER_PORTS; i++) {
        if (bd_intf->mports[i] && 
            bd_intf->mports[i]->port_id == ifindex) {
            return true;
        }
    }
    return false;
}

static void
bd_ac_delete_timer_cbk (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    (void)ev_dis;
    (void)arg_size;

    dp_intf_t *ac = (dp_intf_t *)arg;

    dp_check_and_free_interface(ac);
}

static void
bd_schedule_ac_delete (dp_ctx_t *dp_ctx, dp_intf_t *ac)
{
    assert(ac);
    assert(ac->bd_intf == NULL);
    assert(ac->underlying_intf == NULL);
    assert(ac->dp_ctx == dp_ctx);

    timer_register_app_event(DP_TIMER(dp_ctx),
                             bd_ac_delete_timer_cbk,
                             ac,
                             sizeof(*ac),
                             DP_INTF_DELETE_GRACE_MS,
                             0);
}

void 
bd_del_ac (dp_intf_t *bd_intf, uint32_t ac_ifindex) {

    int i;

    for (i = 0; i < MAX_BD_MEMBER_PORTS; i++) {
        if (!bd_intf->mports[i] || 
             bd_intf->mports[i]->port_id != ac_ifindex) {
            continue;
        }
        break;
    }

    assert (i < MAX_BD_MEMBER_PORTS);

    dp_intf_t *ac = bd_intf->mports[i];

    /* Break the link between BD and AC*/
    bd_intf->mports[i] = NULL;
    ac->bd_intf = NULL;

    /* Break the link between AC and underlying physical interface */
    ac->underlying_intf->ac_intf = NULL;
    ac->underlying_intf = NULL;

    bd_schedule_ac_delete(bd_intf->dp_ctx, ac);
}

void 
bd_ac_configure_8021q_tag (dp_intf_t *ac, uint16_t tag) {
    
    ac->encap_8021q_tag = tag;
}

void
bd_perform_mac_learning (dp_ctx_t *dp_ctx,
                         dp_intf_t *bd, 
                         mac_addr_t *src_mac, 
                         dp_intf_t *ac,
                         uint32_t ip_addr){

    /* Post MAC learn job to dp_ev_dis (single-writer thread). */
    dp_post_bd_mac_learn_job(dp_ctx, 
                         bd->port_id,
                         (uint8_t *)src_mac,
                         ac->port_id,
                         ip_addr);
}

extern bool
l2_switch_forward_frame(
                        dp_ctx_t *dp_ctx,
                        mac_table_t *mac_table,
                        dp_intf_t *vlan_bd_intf,
                        dp_intf_t *recv_intf, 
                        struct rte_mbuf *mbuf);

bool
bd_switch_forward_frame (dp_ctx_t *dp_ctx,
                         mac_table_t *mac_table,
                         dp_intf_t *vlan_bd_intf,
                         dp_intf_t *recv_ac, 
                         struct rte_mbuf *mbuf) {

    return l2_switch_forward_frame(dp_ctx, mac_table, vlan_bd_intf, recv_ac, mbuf);
}

int 
BD_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *bd_intf, 
        struct rte_mbuf *mbuf, uint32_t ctx) {

    dp_intf_t *recv_intf = pkt_mbuf_get_ingress_intf(dp_ctx, mbuf);

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW,
        "pkt %s Recvd on intf %s in BD %s\n", 
        pkt_mbuf_str(mbuf), recv_intf->if_name, bd_intf->if_name);

    bd_switch_forward_frame (
            dp_ctx, 
            bd_intf->mac_table,
            bd_intf,
            recv_intf,
            mbuf);

    return 0;
}


static bool
bd_process_arp_with_arp_supp_cache
    (dp_ctx_t *dp_ctx,
     struct rte_mbuf *mbuf,
     dp_intf_t *ac)
{
    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr;
    arp_hdr_t *arp_in;
    uint32_t target_ip;
    mac_addr_t *reply_mac;
    dp_intf_t *bd_intf;
    char ip_str[IPV4_ADDR_LEN_STR];
    struct rte_mbuf *reply_mbuf;
    ethernet_hdr_t *eth_reply;

    eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    if (!eth_hdr)
        return false;

    if (ntohs(eth_hdr->type) != ETH_TYPE_ARP)
        return false;

    arp_in = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
    if (ntohs(arp_in->op_code) != ARP_BROAD_REQ)
        return false;

    bd_intf = ac->bd_intf;
    if (!bd_intf || !bd_intf->arp_sup_cache_db)
        return false;

    /* ARP request target IP — look up suppression cache for its MAC. */
    target_ip = ntohl(arp_in->dst_ip);
    dp_arp_sup_cache_entry_t *entry =
        arp_sup_cache_entry_lookup(bd_intf->arp_sup_cache_db, target_ip);
    if (!entry)
        return false;

    reply_mac = &entry->mac_Addr;
    entry->supp_count++;

    /*
     * Impersonate the genuine owner of target_ip:
     *   reply src_ip  = ARP-B dst_ip (target being resolved)
     *   reply src_mac = cached MAC for that IP
     *   reply dst_*   = requester's src_* from the ARP-B
     * Send the reply back on the ingress AC only (do not flood).
     */
    reply_mbuf = dp_pkt_mbuf_get_new(
        dp_ctx,
        (uint16_t)(sizeof(ethernet_hdr_t) + sizeof(arp_hdr_t) + ETH_FCS_SIZE));
    pkt_mbuf_update_new_hdr_type(reply_mbuf, ETHERNET_HEADER);
    eth_reply = (ethernet_hdr_t *)pkt_mbuf_get_pkt(reply_mbuf, 0);

    l2_prepare_arp_reply_msg(eth_reply,
                             &arp_in->src_mac, ntohl(arp_in->src_ip),
                             reply_mac, target_ip);

    pkt_tracer(reply_mbuf, dp_ctx->dptr, DARP,
        "BD %s: ARP suppression reply for %s "
        "(%02x:%02x:%02x:%02x:%02x:%02x) → AC %s only\n",
        bd_intf->if_name,
        ip_ntop(target_ip, (c_string)ip_str),
        reply_mac->mac[0], reply_mac->mac[1], reply_mac->mac[2],
        reply_mac->mac[3], reply_mac->mac[4], reply_mac->mac[5],
        ac->if_name);

    AC_SendPacketOut(dp_ctx, ac, reply_mbuf, 0);
    pkt_mbuf_dereference(reply_mbuf);
    return true;
}


void
bd_ac_recv_pkt (dp_ctx_t *dp_ctx, dp_intf_t *ac, struct rte_mbuf *mbuf) {

    pkt_size_t pkt_size;
    mac_addr_t src_mac;
    mac_addr_t dst_mac;

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW,
        "Bridge-Domain : pkt %s Recvd on AC %s \n", 
        pkt_mbuf_str(mbuf), ac->if_name);

    if (pkt_mbuf_get_starting_hdr (mbuf) != ETHERNET_HEADER) {

        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW | DERR,
            "Error : Non-Ethernet pkt %s Recvd on AC %s, dropped\n", 
            pkt_mbuf_str(mbuf), ac->if_name);

        return ;
    }

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    /* Drop the untagged packet */
    if (!vlan_8021q_hdr) {

        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW | DERR,
            "Error : Untagged pkt %s Recvd on AC %s is dropped\n", 
            pkt_mbuf_str(mbuf), ac->if_name);

        ac->xmit_pkt_dropped++;
        return ;
    }

   uint16_t vlan_id = (uint16_t)TCI_VID(vlan_8021q_hdr->tci);

    /* If vlan id do not match AC's dot1q tag, drop the packet */
    if (vlan_id != ac->encap_8021q_tag) {

        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD | DFLOW | DERR,
            "Error : Vlan id %d does not match AC's dot1q tag %d\n", 
            vlan_id, ac->encap_8021q_tag);
            
        ac->xmit_pkt_dropped++;
        return ;
    }

    /* Fetch Src and Dst MAC addresses */
    vlan_ethernet_hdr_t *vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;

    src_mac = vlan_eth_hdr->src_mac;
    dst_mac = vlan_eth_hdr->dst_mac;

    /* Untag the packet but keep the ethernet hdr */
    untag_pkt_with_vlan_id(mbuf);

    /* If this is ARP, learn host IP (sender) with the source MAC. */
    uint32_t learn_ip = 0;
    eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    if (eth_hdr && ntohs(eth_hdr->type) == ETH_TYPE_ARP) {
        arp_hdr_t *arp = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
        learn_ip = ntohl(arp->src_ip);
    }

    /* If this is ARP Broadcast request, intercept it and see if we can reply to it*/
    mac_table_entry_t *existing = mac_table_lookup(
                                    ac->bd_intf->mac_table,
                                    DEFAULT_VLAN_ID,
                                    (uint8_t *)src_mac.mac);

    if (bd_process_arp_with_arp_supp_cache (dp_ctx, mbuf, ac)) {

        if (!mac_table_entry_skip_mac_learning(existing, ac->port_id))
            bd_perform_mac_learning(dp_ctx, ac->bd_intf, &src_mac, ac, learn_ip);

        return;
    }

    if (!existing || 
         !mac_table_entry_skip_mac_learning(existing, ac->port_id) ) {

        bd_perform_mac_learning(dp_ctx, ac->bd_intf, &src_mac, ac, learn_ip);
    }
    else {
        mac_table_entry_touch(existing);
    }

    /* Forward the pkt in bridge domain */
    bd_switch_forward_frame (
            dp_ctx, 
            ac->bd_intf->mac_table,
            ac->bd_intf,
            ac,
            mbuf);        
}