#include <stddef.h>
#include <assert.h>
#include "bd.h"

#include "../../../libs/common/l2_hdrs.h"
#include "../../../libs/common/cmn_struct.h"
#include "../../../libs/common/mpls_lstack.h"

#include "../switching/mac_table.h"

#include "../../dp_ctx.h"
#include "../../dp_uapi.h"
#include "../../Interface/dp_intf.h"
#include "../../Interface/dp_intf_store.h"
#include "../../Interface/intf_cons.h"
#include "../../dp-program/dp-prog-api.h"
#include "../../dp-program/dp-prog-struct.h"
#include "../../Layer2/l2fwd/ipv4-l2fwd.h"

extern bool
mpls_apply_nh_label_stack(struct rte_mbuf *mbuf, mpls_lstack_t *lstack);

int 
AC_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *ac, 
        struct rte_mbuf *mbuf) {

    assert (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER);
    
    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    if (vlan_8021q_hdr) {
        ac->xmit_pkt_dropped++;
        return;
    }

    /* Does this AC has MPLS label stack */
    if (ac->lbl_stack) {
        /* Encapsulate the pkt with MPLS label stack */
        mpls_apply_nh_label_stack (mbuf, ac->lbl_stack);
    }

    /* Add 802.1q tag to the pkt */
    uint16_t vlan_id = ac->encap_8021q_tag;

    /* Tag packet with vlan id */
    tag_pkt_with_vlan_id(mbuf, vlan_id);

    /* Send the pkt out of underlying physical interface */
    dp_send_pkt_out(dp_ctx, ac->underlying_intf, mbuf);

    return 0;
}

/* This interface is responsible to flood the packet out of vlan interface 
    This function assumes that outter most header of the packet is untagged 
    ethernet hdr.
*/
int 
BD_FloodPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf) {

    dp_intf_t *ac ;
    dp_intf_t *exempt_ac = pkt_mbuf_get_ingress_intf(mbuf);

    assert (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER);

    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);

    dp_intf_t *bd_intf = intf->bd_intf;

    /* Iterate over all ACs of BD */
    struct rte_mbuf *dup_mbuf;

    for (int i = 0; i < MAX_BD_MEMBER_PORTS; i++) { 

        ac = bd_intf->mports[i];
        if (!ac || ac == exempt_ac) continue;
        if (!ac->is_up) {
            continue;
            ac->xmit_pkt_dropped++;
        }
        dup_mbuf = PKT_MBUF_DUP(mbuf);
        dp_send_pkt_out(dp_ctx, ac, dup_mbuf);
        pkt_mbuf_dereference (dup_mbuf);
    }

    return 0;
}

static void 
bd_ac_set_name (dp_intf_t *ac, const char *name) {
    
    strncpy(ac->if_name, name, sizeof(ac->if_name) - 1);
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
        if (bd_intf->mports[i]->port_id == ifindex) {
            return true;
        }
    }
    return false;
}

void 
bd_del_ac (dp_intf_t *bd_intf, uint32_t ac_ifindex) {

    int i;

    for (i = 0; i < MAX_BD_MEMBER_PORTS; i++) {
        if (bd_intf->mports[i]->port_id != ac_ifindex) {
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

    free(ac);
}

void 
bd_ac_configure_8021q_tag (dp_intf_t *ac, uint16_t tag) {
    
    ac->encap_8021q_tag = tag;
}

void
bd_perform_mac_learning (dp_ctx_t *dp_ctx,
                         dp_intf_t *bd, 
                         mac_addr_t *src_mac, 
                         dp_intf_t *ac){

    mac_table_entry_t *existing =
        mac_table_lookup(bd->mac_table, 0, (uint8_t *)src_mac);

    if (existing) {
        if (!(existing->flags & MAC_STATIC))
            mac_table_entry_touch(existing);
        return;
    }

    /* Post MAC learn job to dp_ev_dis (single-writer thread). */
    dp_post_bd_mac_learn_job(dp_ctx, 
                         bd->port_id,
                         (uint8_t *)src_mac,
                         ac->port_id);
}

extern void
l2_switch_forward_frame(
                        dp_ctx_t *dp_ctx,
                        mac_table_t *mac_table,
                        dp_intf_t *recv_intf, 
                        struct rte_mbuf *mbuf);

static void 
bd_switch_forward_frame (dp_ctx_t *dp_ctx,
                         mac_table_t *mac_table,
                         dp_intf_t *recv_ac, 
                         struct rte_mbuf *mbuf) {

    l2_switch_forward_frame(dp_ctx, mac_table, recv_ac, mbuf);
}

int 
BD_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf) {

    bd_switch_forward_frame (
            dp_ctx, 
            intf->bd_intf->mac_table,
            intf, 
            mbuf);
}

void 
bd_ac_recv_pkt (dp_ctx_t *dp_ctx, dp_intf_t *ac, struct rte_mbuf *mbuf) {

    if (pkt_mbuf_get_starting_hdr (mbuf) == ETHERNET_HEADER) return; 

    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    /* Drop the untagged packet */
    if (!vlan_8021q_hdr) {
        ac->xmit_pkt_dropped++;
        return;
    }

    /* Fetch Src and Dst MAC addresses */
    mac_addr_t src_mac;
    mac_addr_t dst_mac;

    vlan_ethernet_hdr_t *vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;

    src_mac = vlan_eth_hdr->src_mac;
    dst_mac = vlan_eth_hdr->dst_mac;
    uint16_t eth_proto = htons(vlan_eth_hdr->type);

    /* Untag the packet but keep the ethernet hdr */
    untag_pkt_with_vlan_id(mbuf);

    /* Perform MAC learning : To be done via DP manager thread */
    bd_perform_mac_learning (dp_ctx, ac->bd_intf, &src_mac, ac);

    /* Forward the pkt in bridge domain */
    BD_SendPacketOut (dp_ctx, ac, mbuf);
}