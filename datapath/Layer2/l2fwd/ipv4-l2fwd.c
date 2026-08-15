#include <assert.h>
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../Interface/dp_intf_store.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../../../libs/common/l2_hdrs.h"
#include "ipv4-l2fwd.h"
#include "../arp/arp.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../dp_utils.h"
#include "../../dp_uapi.h"
#include "../../classifier/pkt_classifier.h"
#include "../../Layer3/layer3.h"

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      struct rte_mbuf *mbuf);

extern void
cp_punt_pkt_from_layer2_to_layer5(
					  void *node,
					  uint32_t recv_intf_ifindex,
        			  struct rte_mbuf *mbuf,
					  gen_proto_id_t hdr_code);
                  
static void
l2_forward_ip_packet(dp_ctx_t *dp_ctx, 
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *oif,
                     struct rte_mbuf *mbuf)
{

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    arp_entry_t * arp_entry = NULL;
    byte next_hop_ip_str[IPV4_ADDR_LEN_STR];

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    
    pkt_size_t ethernet_payload_size = 
        pkt_size - sizeof(ethernet_hdr_t) - ETH_FCS_SIZE;

    /* Handling L2 forwarding for any payload other than ipv4. Simply,
        encap the pkt within ethernet hdr with dst mac as broadcast mac */
    if (ethernet_hdr->type != htons(ETH_TYPE_IPv4) && 
        ethernet_hdr->type != htons(ETH_TYPE_MPLS_UC)) {

        layer2_fill_with_broadcast_mac (ethernet_hdr->dst_mac.mac);
        memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        dp_send_pkt_out(dp_ctx, oif, mbuf, 0);
        return;
    }

    tcp_ip_covert_ip_n_to_p(next_hop_ip, (c_string)next_hop_ip_str);

    if(oif) {

        /* L3 has resolved the nexthop; L2-forward out of oif. */

        arp_entry = arp_table_lookup(vrf->arp_table, next_hop_ip);

        if (!arp_entry || arp_entry_sane(arp_entry)) {

            tracer(dp_ctx->dptr, DL2FWD, 
                "VRF %s: Dest : %s : ARP not yet resolved, posting ARP_RESOLVE job\n",
                vrf->vrf_name, next_hop_ip_str);
                
            /*
             * ARP not yet resolved (or pending).  Ref the mbuf and post an
             * ARP_RESOLVE job to dp_ev_dis.  dp_ev_dis will:
             *  1. Create/update the sane entry and queue the mbuf.
             *  2. Send an ARP broadcast request.
             * The packet will be forwarded when the ARP reply arrives.
             */
            //pkt_mbuf_ref_inc(mbuf);
            dp_post_arp_resolve_job(dp_ctx, vrf, oif->port_id,
                                    next_hop_ip, NULL);
            return;
        }

        goto l2_frame_prepare;
    }
   
    /* if outgoing_intf is NULL, then two cases possible : 
       1. L2 has to forward the frame to self(destination is local interface ip address
        including loopback address)
       2. L2 has to forward the frame to machine on local connected subnet*/

    /*case 1 */
    
    oif = dp_intf_get_matching_subnet_interface(dp_ctx, vrf, next_hop_ip);
   
    /*If the destination IP address do not match any local subnet Nor
     * is it a self loopback address*/
    if(!oif && (next_hop_ip != dp_ctx->rtr_id)) {

        tracer(dp_ctx->dptr, DL2FWD | DERR,
            "Error : Local matching subnet for IP:%s could not be found\n",
                    next_hop_ip_str);
        return;
    }

    /*if the destination ip address is exact match to local interface
     * ip address*/
    if (oif && (next_hop_ip == oif->ip_addr)) {
        /*send to self*/

        memset(ethernet_hdr->src_mac.mac, 0, MAC_ADDR_SIZE);
        memcpy(ethernet_hdr->dst_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        dp_pkt_entry_point(dp_ctx,oif->vrf, oif, mbuf);
        return;
    }

    /*If the destination ip address is exact match to self loopback address, 
     * rebounce the pkt to Network Layer again*/
    if(next_hop_ip == dp_ctx->rtr_id) {

        pkt_mbuf_slide(mbuf, -1, 1, (uint16_t)sizeof(ethernet_hdr_t));
        pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
        pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
        dp_promote_pkt_to_layer3(dp_ctx, vrf, 0, mbuf);
        return;
    }

    arp_entry = arp_table_lookup(vrf->arp_table, next_hop_ip);

    if (!arp_entry || arp_entry_sane(arp_entry)) {
        /* ARP not yet resolved — post resolve job to dp_ev_dis. */
        pkt_mbuf_ref_inc(mbuf);
        dp_post_arp_resolve_job(dp_ctx, vrf,
                                oif ? oif->port_id : 0,
                                next_hop_ip, mbuf);
        return;
    }

    l2_frame_prepare:
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, MAC_ADDR_SIZE);
        memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        dp_send_pkt_out(dp_ctx, oif, mbuf, 0);
        arp_entry_touch(arp_entry);  /* cheap timestamp store; timer checks this */
    }

/* An API to be used by Layer 3 or higher to push the pkt
 * down the TCP IP Stack to L2. Note that, though most of the time
 * this API shall be used by L3, but any Higher Layer API can use
 * this API. For example, An application can run directly on L2 bypassing
 * L3 altogether.*/
void dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                          dp_vrf_t *vrf,
                          uint32_t next_hop_ip,
                          dp_intf_t *oif,
                          struct rte_mbuf *mbuf,
                          gen_proto_id_t hdr_type)
{

    gen_proto_id_t starting_hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    pkt_mbuf_tcp_ip_expand_buffer_ethernet_hdr(mbuf);

    ethernet_hdr_t *empty_ethernet_hdr =
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL);

    switch (hdr_type) {
        case IP_PROTO_IP_IN_IP:
            SET_COMMON_ETH_HDR_TYPE(empty_ethernet_hdr, ETH_TYPE_IPv4);
            break;
        case IP_PROTO_IPv6:
            SET_COMMON_ETH_HDR_TYPE(empty_ethernet_hdr, ETH_TYPE_IPv6);
            break;
        case IP_PROTO_MPLS_IN_IP:
            SET_COMMON_ETH_HDR_TYPE(empty_ethernet_hdr, ETH_TYPE_MPLS_UC);
            break;
        default:
            assert(0);
    }

    l2_forward_ip_packet(dp_ctx,
                         vrf,
                         next_hop_ip,
                         oif,
                         mbuf);
}

/*Vlan Management Routines*/

/* Return new packet size if pkt is tagged with new vlan id*/
void
tag_pkt_with_vlan_id (
                     struct rte_mbuf *mbuf,
                     int vlan_id ) {

    pkt_size_t total_pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &total_pkt_size);

    uint32_t payload_size  = 0 ;

    /*If the pkt is already tagged, replace it*/
    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    if(vlan_8021q_hdr){
        payload_size = total_pkt_size - sizeof (vlan_ethernet_hdr_t) - ETH_FCS_SIZE;
        vlan_8021q_hdr->tci = MAKE_TCI(TCI_PCP(vlan_8021q_hdr->tci),
                                        TCI_DEI(vlan_8021q_hdr->tci),
                                        vlan_id);
        SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
        return;
    }

    /*If the pkt is not already tagged, tag it*/
    ethernet_hdr_t ethernet_hdr_old;
    memcpy((char *)&ethernet_hdr_old, (char *)ethernet_hdr, sizeof (ethernet_hdr_t));
    
    payload_size = total_pkt_size - sizeof (ethernet_hdr_t) - ETH_FCS_SIZE;

    /* Create room for 802.1Q vlan hdr*/
    pkt_mbuf_slide(mbuf, -1, -1, (uint16_t)sizeof(vlan_8021q_hdr_t));

    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
            (vlan_ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &total_pkt_size);

    memset((char *)vlan_ethernet_hdr, 0, sizeof (vlan_ethernet_hdr_t));
    memcpy(vlan_ethernet_hdr->dst_mac.mac, 
        ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(vlan_ethernet_hdr->src_mac.mac, 
        ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

    /*Come to 802.1Q vlan hdr*/
    vlan_ethernet_hdr->vlan_8021q_hdr.tpid = htons(ETH_TYPE_VLAN_8021Q);
    vlan_ethernet_hdr->vlan_8021q_hdr.tci  = MAKE_TCI(0, 0, vlan_id);

    /*Type field*/
    vlan_ethernet_hdr->type = ethernet_hdr_old.type;

    /*No need to copy data*/

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS((ethernet_hdr_t *)vlan_ethernet_hdr, payload_size, 0 );
}

/* Return new packet size if pkt is untagged with the existing
 * vlan 801.1q hdr*/
void
untag_pkt_with_vlan_id(struct rte_mbuf *mbuf) {

    pkt_size_t pkt_size;
    vlan_ethernet_hdr_t vlan_ethernet_hdr_old;

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        is_pkt_vlan_tagged(ethernet_hdr);
    
    /*Not tagged already, do nothing*/    
    if(!vlan_8021q_hdr){
        return;
    }


    memcpy((char *)&vlan_ethernet_hdr_old, 
           (char *)ethernet_hdr, 
            sizeof(vlan_ethernet_hdr_t));

    pkt_mbuf_slide(mbuf, -1, 1, (uint16_t)sizeof(vlan_8021q_hdr_t));

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
   
    memcpy(ethernet_hdr->dst_mac.mac, vlan_ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(ethernet_hdr->src_mac.mac, vlan_ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

    ethernet_hdr->type = vlan_ethernet_hdr_old.type;
    
    /*No need to copy data*/
    uint32_t payload_size = pkt_size - sizeof(ethernet_hdr_t) - ETH_FCS_SIZE;

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
}

void
promote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
                    dp_intf_t *iif, 
                    struct rte_mbuf *mbuf) {

    bool is_vlan_tagged;
    uint16_t eth_type;
    pkt_size_t pkt_size;

    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    is_vlan_tagged = is_pkt_vlan_tagged(ethernet_hdr );

    dp_pkt_trap_l3(dp_ctx, &iif->trap_rule_table, mbuf);
    
     /* Unconditionally distribute pkt-copy to interested applications */
    cp_punt_pkt_from_layer2_to_layer5(
                     dp_ctx->ctx_pvt_data, 
                     iif->port_id, 
                     mbuf,
                     ETHERNET_HEADER);

    eth_type = ntohs(ethernet_hdr->type);

    switch(eth_type){

        case ETH_TYPE_ARP:
            {
                /*Can be ARP Broadcast or ARP reply*/
                arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));

                switch(htons(arp_hdr->op_code))
                {
                    case ARP_BROAD_REQ:
                        process_arp_broadcast_request(dp_ctx, vrf, iif, ethernet_hdr);
                        return;
                    case ARP_REPLY:
                        process_arp_reply_msg(dp_ctx, vrf, iif, ethernet_hdr);
                        return;
                    default:
                        assert(0);
                }
            }
            break;

        case ETH_TYPE_IPv4:

            /* Strip the ethernet header to expose the IP payload. */
            pkt_mbuf_slide(mbuf, -1, 1, 
                    is_vlan_tagged ? (uint16_t)sizeof(vlan_ethernet_hdr_t) : \
                    (uint16_t)sizeof(ethernet_hdr_t));

            pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
            pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IP_IN_IP);
            dp_promote_pkt_to_layer3(
                    dp_ctx,
                    vrf, iif, 
                    mbuf);
            break;

        case ETH_TYPE_IPv6:
            pkt_mbuf_slide(mbuf, -1, 1, 
                    is_vlan_tagged ? (uint16_t)sizeof(vlan_ethernet_hdr_t) : \
                    (uint16_t)sizeof(ethernet_hdr_t));
            pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
            pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IPv6);
            dp_promote_pkt_to_layer3(
                    dp_ctx,
                    vrf, iif, 
                    mbuf);
            break;

        case ETH_TYPE_MPLS_UC:
            pkt_mbuf_slide(mbuf, -1, 1, 
                    is_vlan_tagged ? (uint16_t)sizeof(vlan_ethernet_hdr_t) : \
                    (uint16_t)sizeof(ethernet_hdr_t));
            pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
            pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_MPLS_IN_IP);

            dp_mpls_fwd_pkt (dp_ctx, vrf, iif, mbuf);
            break;

        default: ;
    }
}

bool 
l2_frame_recv_qualify_on_interface( dp_ctx_t *dp_ctx,
                                    dp_vrf_t *vrf,
                                    dp_intf_t *interface, 
                                    struct rte_mbuf *mbuf,
                                    uint16_t *output_vlan_id){

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;

    *output_vlan_id = 0;

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
                        is_pkt_vlan_tagged(ethernet_hdr);

    /* Presence of IP address on interface makes it work in L3 mode,
     * while absence of IP-address automatically make it work in
     * L2 mode provided that it is operational either in ACCESS mode or TRUNK mode.*/

    /* case 10 : If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/

    tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
        "Pkt : %s received on interface %s being tested for "
        "RECV-Qualification test\n", pkt_mbuf_str(mbuf), interface->if_name);

    if (!interface->ip_addr &&
        !interface->switchport) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
            "failed RECV-Qualification test : Interface is neither L3 interface or L2 switchport\n",
            pkt_mbuf_str(mbuf), interface->if_name);

        return false;
    }

    if (!interface->is_up) {

        interface->recvd_pkt_dropped++;
        tracer(dp_ctx->dptr, DL2FWD | DFLOW | DERR,
            "Error : Pkt : %s dropped. Reciepient AC %s is not admin up.\n",
            pkt_mbuf_str(mbuf), interface->if_name);        
        return false;
    }

    /* Handle Reception on Attachment Circuits ACs*/
    if (interface->ac_intf) {

        dp_intf_t *ac = interface->ac_intf;

        if (!ac->bd_intf ) {

            ac->recvd_pkt_dropped++;
            tracer(dp_ctx->dptr, DL2FWD | DFLOW | DERR,
                "Error : Pkt : %s dropped. Reciepient AC %s is not BD member.\n",
                pkt_mbuf_str(mbuf), ac->if_name);            
            return false;
        }

        if (!ac->bd_intf->is_up) {

            ac->bd_intf->recvd_pkt_dropped++;
            tracer(dp_ctx->dptr, DL2FWD | DFLOW | DERR,
                "Error : Pkt : %s dropped. Reciepient BD %s is not admin up.\n",
                pkt_mbuf_str(mbuf), ac->bd_intf->if_name);
            return false;
        }

        if (!ac->encap_8021q_tag)
        {
            tracer(dp_ctx->dptr, DL2FWD | DFLOW | DERR,
                   "Error : Pkt : %s dropped. Reciepient AC %s is not dot1q enabled.\n",
                   pkt_mbuf_str(mbuf), ac->if_name);
        }

        return true;
    }


    /* If interface is working in ACCESS mode but at the
     * same time not operating within a vlan, then it must
     * accept untagged packet only*/

    if (interface->l2_mode == DP_LAN_ACCESS_MODE &&
         interface->vlan_intf->vlan_id == 0) {

        if(!vlan_8021q_hdr)
            return true;    /*case 3*/
        
        else {
            tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
                "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Tagged pkt "
                "recvd on Access interface not operating in any vlan\n",
                pkt_mbuf_str(mbuf), interface->if_name);
            return false;   /*case 4*/
        }
    }

    /* if interface is working in ACCESS mode and operating with in
     * vlan, then :
     * 1. it must accept untagged frame and tag it with a vlan-id of an interface
     * 2. Or  it must accept tagged frame but tagged with same vlan-id as interface's vlan operation*/

    uint16_t intf_vlan_id = 0,
                 pkt_vlan_id = 0;

    if (interface->l2_mode == DP_LAN_ACCESS_MODE){
        
        intf_vlan_id = interface->vlan_intf->vlan_id;

        if(!vlan_8021q_hdr && intf_vlan_id){
            *output_vlan_id = intf_vlan_id;
            return true; /*case 6*/
        }

        if(!vlan_8021q_hdr && !intf_vlan_id){
            /*case 3*/
            return true;
        }

        pkt_vlan_id = (uint16_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);

        if(pkt_vlan_id == intf_vlan_id){
            return true;    /*case 5*/
        }
        else{
            tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
                "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Vlan Mismatch, "
                "802.1Q vlan  %d != Interface vlan %d\n", 
                pkt_mbuf_str(mbuf), interface->if_name,  
                pkt_vlan_id, intf_vlan_id);
            return false;   /*case 5*/
        }
    }

    /* if interface is operating in a TRUNK mode, then it must discard all untagged
     * frames*/
    
    if(interface->l2_mode == DP_LAN_TRUNK_MODE){
       
        if(!vlan_8021q_hdr){
            /*case 7 & 8*/
            tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
                "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Untagged "
                "pkt recvd on Trunk Interface\n", 
                pkt_mbuf_str(mbuf), interface->if_name);
            return false;
        }
    }

    /* if interface is operating in a TRUNK mode, then it must accept the frame
     * which are tagged with any vlan-id in which interface is operating.*/

    if((interface->l2_mode == DP_LAN_TRUNK_MODE) && 
            vlan_8021q_hdr){
        
        pkt_vlan_id = (uint16_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);

        if (dp_is_vlan_member(interface->vlan_bitmap, pkt_vlan_id)) {
            return true;    /*case 9*/
        }
        else{
            tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
                "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Trunk Interface is "
                "not configured with Pkt vlan %d\n", 
                pkt_mbuf_str(mbuf), interface->if_name,  pkt_vlan_id);
            return false;   /*case 9*/
        }
    }

    /* Tagged Ethernet pkt is allowed on GRE interface due to Vlan
    Extension*/
    if (interface->if_type == DP_INTF_TYPE_GRE_TUNNEL &&
            vlan_8021q_hdr) {
                
        *output_vlan_id = (uint16_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        return true;
    }


    /*If the interface is operating in L3 mode, and recv vlan tagged frame, drop it*/
    if(interface->ip_addr && vlan_8021q_hdr){
        /*case 2*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s received on interface %s "
            "failed RECV-Qualification test : Vlan tagged pkt recvd on L3 interface\n", 
            pkt_mbuf_str(mbuf), interface->if_name);
        return false;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if(interface->ip_addr  && 
            memcmp(interface->mac_add.mac, 
            ethernet_hdr->dst_mac.mac, 
            MAC_ADDR_SIZE) == 0){
            /*case 1*/
            return true;
    }

    /*If interface is working in L3 mode, then accept the frame with
     * broadcast MAC*/
    if(interface->ip_addr  &&
        IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        /*case 1*/
        return true;
    }

    tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
        "Pkt : %s received on interface %s "
        "failed RECV-Qualification test : Unknown Reason\n", 
        pkt_mbuf_str(mbuf), interface->if_name);    

    interface->recvd_pkt_dropped++;
    return false;
}

bool 
is_arp_pkt_for_svi_interface (dp_ctx_t *dp_ctx,
                              struct rte_mbuf *mbuf)
{
    uint16_t proto;
    pkt_size_t pkt_size;
    arp_hdr_t *arp_hdr;
    uint32_t svi_ip_addr;
    uint16_t vlan_id = 0;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    ethernet_hdr_t *ethernet_hdr = NULL;
    vlan_ethernet_hdr_t *vlan_eth_hdr = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    if (is_pkt_vlan_tagged(ethernet_hdr)) {
        vlan_eth_hdr = (vlan_ethernet_hdr_t *)ethernet_hdr;
        proto = ntohs(vlan_eth_hdr->type);
        vlan_id = GET_802_1Q_VLAN_ID(&vlan_eth_hdr->vlan_8021q_hdr);
    }   
    else {
        proto = ntohs(ethernet_hdr->type);
    }

    if (proto != ETH_TYPE_ARP) return false;

    arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
    
    if (ntohs(arp_hdr->op_code) != ARP_BROAD_REQ && 
         ntohs(arp_hdr->op_code) != ARP_REPLY) return false;

    /* Lookup Vlan Inteface */
    dp_intf_t *svi_intf = dp_look_up_interface_by_vlan_id(dp_ctx->dp_vlan_intf_ht, vlan_id);

    if (!svi_intf) return false;

    return (svi_intf->ip_addr == ntohl(arp_hdr->dst_ip)) ;
}

bool
svi_interface_intercept_arp_pkt (dp_ctx_t *dp_ctx,
                                dp_vrf_t *vrf,
                                struct rte_mbuf *mbuf) {

    uint16_t l3_proto;
    pkt_size_t pkt_size;
    
    vlan_ethernet_hdr_t *vlan_eth_hdr;
    dp_intf_t *interface = pkt_mbuf_get_ingress_intf(mbuf);
    
    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));

    vlan_eth_hdr = ( vlan_ethernet_hdr_t  *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    uint16_t pkt_vlan_id = GET_802_1Q_VLAN_ID(&vlan_eth_hdr->vlan_8021q_hdr);
    l3_proto = ntohs(vlan_eth_hdr->type);

    /* Step 1*/
    if (!interface->switchport) return false;

    /* Step 2 */
    dp_intf_t *vlan_intf = NULL;
    
    if (interface->l2_mode == DP_LAN_ACCESS_MODE) {
        vlan_intf = interface->vlan_intf;
    }
    else if (interface->l2_mode == DP_LAN_TRUNK_MODE) {   
        vlan_intf = dp_look_up_interface_by_vlan_id(
                    dp_ctx->dp_vlan_intf_ht, pkt_vlan_id);
    }
    else {
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s recvd on switchport %s which is neither "
            "in Access nor in Trunk mode, Pkt Dropped\n",
            pkt_mbuf_str(mbuf), interface->if_name);
        return true;
    }

    if (!vlan_intf) {
        /* It means, the pkt is recvd on switchport interface but
         * the interface is not operating in any vlan*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s recvd on switchport %s which is not bound to any vlan, pkt Dropped\n",
            pkt_mbuf_str(mbuf), interface->if_name);
        return true;
    }

    uint32_t svi_ip_addr;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    assert (vrf == vlan_intf->vrf);

    /*Process ARP packets destined for SVI interface */
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr));

    if (ntohs(arp_hdr->op_code) == ARP_REPLY) {

        arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table, arp_hdr, vlan_intf);
        return true;
    }

    if (ntohs(arp_hdr->op_code) != ARP_BROAD_REQ) return true;

    svi_ip_addr = vlan_intf->ip_addr;

    tracer(dp_ctx->dptr, DL2FWD | DFLOW,
           "Pkt : %s recvd on SVI interface %s is ARP Broadcast "
           "request for SVI IP, Sending ARP reply\n",
           pkt_mbuf_str(mbuf), vlan_intf->if_name);

    /* Overhead ARP Boradcast pkt and update ARP cache */
    arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table,
                                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr),
                                    vlan_intf);

    arp_hdr_t *arp_hdr_in = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr));

    pkt_size_t arp_reply_pkt_size = sizeof(vlan_ethernet_hdr_t) + 
                                    ETH_FCS_SIZE +
                                    (pkt_size_t)sizeof(arp_hdr_t);

    struct rte_mbuf *mbuf2 = dp_pkt_mbuf_get_new(dp_ctx, arp_reply_pkt_size);

    vlan_ethernet_hdr_t *vlan_ethernet_hdr_reply =
        (vlan_ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf2, 0);

    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tpid = htons(ETH_TYPE_VLAN_8021Q);
    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tci  = MAKE_TCI(0, 0, pkt_vlan_id);

    l2_prepare_arp_reply_msg((ethernet_hdr_t *)vlan_ethernet_hdr_reply,
                             &arp_hdr_in->src_mac, ntohl(arp_hdr_in->src_ip),
                             &vlan_intf->mac_add, svi_ip_addr);

    pkt_mbuf_update_new_hdr_type(mbuf2, ETHERNET_HEADER);

    arp_hdr_t *arp_hdr_reply = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(
        (ethernet_hdr_t *)vlan_ethernet_hdr_reply));

    tracer(dp_ctx->dptr, DARP,
        "Sending ARP Reply [%s : %02x:%02x:%02x:%02x:%02x:%02x] out of interface %s\n",
           tcp_ip_covert_ip_n_to_p(arp_hdr_reply->dst_ip, (c_string)ip_addr_str),
           arp_hdr_reply->dst_mac.mac[0],
           arp_hdr_reply->dst_mac.mac[1],
           arp_hdr_reply->dst_mac.mac[2],
           arp_hdr_reply->dst_mac.mac[3],
           arp_hdr_reply->dst_mac.mac[4],
           arp_hdr_reply->dst_mac.mac[5],
           interface->if_name);

    dp_send_pkt_out(dp_ctx, interface, mbuf2, 0);
    pkt_mbuf_dereference(mbuf2);
    return true;
}

static dp_intf_t *
dp_ingress_bd_intf(struct rte_mbuf *mbuf)
{
    dp_intf_t *ingress = pkt_mbuf_get_ingress_intf(mbuf);

    if (!ingress)
        return NULL;

    if (ingress->if_type == DP_INTF_TYPE_AC && ingress->bd_intf)
        return ingress->bd_intf;

    if (ingress->if_type == DP_INTF_TYPE_BD)
        return ingress;

    return NULL;
}

bool
is_arp_pkt_for_bd_svi_interface (dp_ctx_t *dp_ctx,
                                   struct rte_mbuf *mbuf)
{
    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    arp_hdr_t *arp_hdr;
    dp_intf_t *bd_intf;

    (void)dp_ctx;

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    if (ntohs(ethernet_hdr->type) != ETH_TYPE_ARP)
        return false;

    arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));

    if (ntohs(arp_hdr->op_code) != ARP_BROAD_REQ &&
        ntohs(arp_hdr->op_code) != ARP_REPLY)
        return false;

    bd_intf = dp_ingress_bd_intf(mbuf);

    if (!bd_intf || !bd_intf->ip_addr)
        return false;

    return (bd_intf->ip_addr == ntohl(arp_hdr->dst_ip));
}

bool
bd_svi_interface_intercept_arp_pkt (dp_ctx_t *dp_ctx,
                                    struct rte_mbuf *mbuf)
{
    pkt_size_t pkt_size;
    dp_intf_t *ingress_ac;
    dp_intf_t *bd_intf;
    dp_vrf_t *vrf;
    ethernet_hdr_t *eth_hdr;
    arp_hdr_t *arp_hdr;
    uint32_t svi_ip_addr;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    ingress_ac = pkt_mbuf_get_ingress_intf(mbuf);
    bd_intf = dp_ingress_bd_intf(mbuf);

    if (!ingress_ac || ingress_ac->if_type != DP_INTF_TYPE_AC || !bd_intf)
        return false;

    vrf = bd_intf->vrf ? bd_intf->vrf : dp_ctx->default_vrf;

    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));

    eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(eth_hdr));

    if (ntohs(arp_hdr->op_code) == ARP_REPLY) {
        arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table,
                                        arp_hdr, ingress_ac);
        return true;
    }

    if (ntohs(arp_hdr->op_code) != ARP_BROAD_REQ)
        return true;

    svi_ip_addr = bd_intf->ip_addr;

    tracer(dp_ctx->dptr, DL2FWD | DFLOW,
           "Pkt : %s recvd on BD %s is ARP Broadcast request for SVI IP\n",
           pkt_mbuf_str(mbuf), bd_intf->if_name);

    arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table, arp_hdr, ingress_ac);

    pkt_size_t arp_reply_pkt_size = sizeof(ethernet_hdr_t) +
                                    ETH_FCS_SIZE +
                                    (pkt_size_t)sizeof(arp_hdr_t);

    struct rte_mbuf *mbuf2 = dp_pkt_mbuf_get_new(dp_ctx, arp_reply_pkt_size);
    ethernet_hdr_t *eth_reply =
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf2, 0);

    l2_prepare_arp_reply_msg(eth_reply,
                             &arp_hdr->src_mac, ntohl(arp_hdr->src_ip),
                             (mac_addr_t *)&dp_ctx->rmac, svi_ip_addr);

    pkt_mbuf_update_new_hdr_type(mbuf2, ETHERNET_HEADER);

    arp_hdr_t *arp_hdr_reply =
        (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(eth_reply));

    tracer(dp_ctx->dptr, DARP,
        "Sending BD ARP Reply [%s] out of AC %s\n",
        tcp_ip_covert_ip_n_to_p(arp_hdr_reply->dst_ip, (c_string)ip_addr_str),
        ingress_ac->if_name);

    dp_send_pkt_out(dp_ctx, ingress_ac, mbuf2, 0);
    pkt_mbuf_dereference(mbuf2);
    return true;
}
