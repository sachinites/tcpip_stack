#include <assert.h>
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../Interface/dp_intf_store.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../../pkt_block.h"
#include "../../../common/l2_hdrs.h"
#include "ipv4-l2fwd.h"
#include "../arp/arp.h"
#include "../../../Tracer/tracer.h"
#include "../../dp_utils.h"
#include "../../dp_uapi.h"
#include "../../../common/cmn_api.h"

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ;

extern void
cp_punt_pkt_from_layer2_to_layer5(
					  void *node,
					  uint32_t recv_intf_ifindex,
        			  pkt_block_t *pkt_block,
					  hdr_type_t hdr_code);

extern int
dp_inject_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface);
                  
static void
l2_forward_ip_packet(dp_ctx_t *dp_ctx, 
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *oif,
                     pkt_block_t *pkt_block)
{

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    arp_entry_t * arp_entry = NULL;
    byte next_hop_ip_str[IPV4_ADDR_LEN_STR];

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    
    pkt_size_t ethernet_payload_size = 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    /* Handling L2 forwarding for any payload other than ipv4. Sinply,
        encap the pkt within ethernet hdr with dst mac as broadcast mac */
    if (ethernet_hdr->type != htons(ETH_IP)) {

        layer2_fill_with_broadcast_mac (ethernet_hdr->dst_mac.mac);
        memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        dp_send_pkt_out(dp_ctx, oif, pkt_block);
        return;
    }

    tcp_ip_covert_ip_n_to_p(next_hop_ip, (c_string)next_hop_ip_str);

    if(oif) {

        /* It means, L3 has resolved the nexthop, So its time to L2 forward the pkt out of this 
        interface*/

        arp_entry = arp_table_lookup(vrf->arp_table, next_hop_ip);

        if (!arp_entry) {

            /*Time for ARP resolution*/
            create_update_arp_sane_entry(dp_ctx, vrf, vrf->arp_table,  next_hop_ip,  pkt_block);
            send_arp_broadcast_request(dp_ctx, vrf, oif, next_hop_ip);
            return;
        }

        else if (arp_entry_sane(arp_entry)) {

            create_update_arp_sane_entry(dp_ctx, vrf, vrf->arp_table,  next_hop_ip, pkt_block);
             return;
        }

        goto l2_frame_prepare ;
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
        dp_inject_packet(dp_ctx, pkt_block, oif);
        return;
    }

    /*If the destination ip address is exact match to self loopback address, 
     * rebounce the pkt to Network Layer again*/
    if(next_hop_ip == dp_ctx->rtr_id) {
        dp_promote_pkt_to_layer3(dp_ctx, vrf, 0, pkt_block, ethernet_hdr->type);
        return;
    }

    arp_entry = arp_table_lookup(vrf->arp_table, next_hop_ip);

    if (!arp_entry || (arp_entry && arp_entry_sane(arp_entry))){
        
        /*Time for ARP resolution*/
        create_update_arp_sane_entry(dp_ctx, vrf, vrf->arp_table, 
                next_hop_ip, 
                pkt_block);
        send_arp_broadcast_request(dp_ctx, vrf, oif, next_hop_ip);
        return;
    }

    l2_frame_prepare:
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, MAC_ADDR_SIZE);
        memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        dp_send_pkt_out(dp_ctx, oif, pkt_block);
		arp_entry_refresh_expiration_timer(arp_entry);
        arp_entry->hit_count++;
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
                          pkt_block_t *pkt_block,
                          hdr_type_t hdr_type)
{

    tcp_ip_expand_buffer_ethernet_hdr(pkt_block);

    ethernet_hdr_t *empty_ethernet_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, NULL);

    empty_ethernet_hdr->type = htons(tcp_ip_convert_internal_proto_to_std_proto(hdr_type));

    l2_forward_ip_packet(dp_ctx,
                         vrf,
                         next_hop_ip,
                         oif,
                         pkt_block);
}

/*Vlan Management Routines*/

/* Return new packet size if pkt is tagged with new vlan id*/
void
tag_pkt_with_vlan_id (
                     pkt_block_t *pkt_block,
                     int vlan_id ) {

    pkt_size_t total_pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &total_pkt_size);

    uint32_t payload_size  = 0 ;

    /*If the pkt is already tagged, replace it*/
    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    if(vlan_8021q_hdr){
        payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
        vlan_8021q_hdr->tci_vid = 0;
        vlan_8021q_hdr->tci_vid |= htons((uint16_t)vlan_id);
        SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
        return;
    }

    /*If the pkt is not already tagged, tag it*/
    /*Fix me : Avoid declaring local variables of type 
     ethernet_hdr_t or vlan_ethernet_hdr_t as the size of these
     variables are too large and is not healthy for program stack
     memory*/
    ethernet_hdr_t ethernet_hdr_old;
    memcpy((char *)&ethernet_hdr_old, (char *)ethernet_hdr, 
                ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    payload_size = total_pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD; 
    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
            (vlan_ethernet_hdr_t *)((char *)ethernet_hdr - sizeof(vlan_8021q_hdr_t));

    memset((char *)vlan_ethernet_hdr, 0, 
                VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);
    memcpy(vlan_ethernet_hdr->dst_mac.mac, 
        ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(vlan_ethernet_hdr->src_mac.mac, 
        ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

    /*Come to 802.1Q vlan hdr*/
    vlan_ethernet_hdr->vlan_8021q_hdr.tpid = htons(VLAN_8021Q_PROTO);
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_pcp = 0;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_dei = 0;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_vid = 0;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_vid |= htons((uint16_t)vlan_id);

    /*Type field*/
    vlan_ethernet_hdr->type = ethernet_hdr_old.type;

    /*No need to copy data*/

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS((ethernet_hdr_t *)vlan_ethernet_hdr, payload_size, 0 );

    pkt_block_set_new_pkt(
                pkt_block,
                (uint8_t *)vlan_ethernet_hdr,
                total_pkt_size  + (pkt_size_t)sizeof(vlan_8021q_hdr_t));
}

/* Return new packet size if pkt is untagged with the existing
 * vlan 801.1q hdr*/
void
untag_pkt_with_vlan_id(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        is_pkt_vlan_tagged(ethernet_hdr);
    
    /*Not tagged already, do nothing*/    
    if(!vlan_8021q_hdr){
        return;
    }

    /*Fix me : Avoid declaring local variables of type 
      ethernet_hdr_t or vlan_ethernet_hdr_t as the size of these
      variables are too large and is not healthy for program stack
      memory*/
    vlan_ethernet_hdr_t vlan_ethernet_hdr_old;
    memcpy((char *)&vlan_ethernet_hdr_old, (char *)ethernet_hdr, 
                VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    ethernet_hdr = (ethernet_hdr_t *)((char *)ethernet_hdr + sizeof(vlan_8021q_hdr_t));
   
    memcpy(ethernet_hdr->dst_mac.mac, vlan_ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(ethernet_hdr->src_mac.mac, vlan_ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

    ethernet_hdr->type = vlan_ethernet_hdr_old.type;
    
    /*No need to copy data*/
    uint32_t payload_size = pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
    
    pkt_block_set_new_pkt(pkt_block, (uint8_t *)ethernet_hdr,  
                                            pkt_size - (pkt_size_t )sizeof(vlan_8021q_hdr_t));
}

void
promote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
                    dp_intf_t *iif, 
                    pkt_block_t *pkt_block) {

    uint16_t eth_type;
    pkt_size_t pkt_size;

    assert(pkt_block_verify_pkt(pkt_block, ETH_HDR));

    /* Unconditionally distribute pkt-copy to interested applications */
    cp_punt_pkt_from_layer2_to_layer5(
                    dp_ctx->ctx_pvt_data, 
                    iif->port_id, 
                    pkt_block,
                    ETH_HDR);

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    eth_type = htons(ethernet_hdr->type);

    switch(eth_type){

        case PROTO_ARP:
            {
                /*Can be ARP Broadcast or ARP reply*/
                arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));

                switch(htons(arp_hdr->op_code)){

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

        case ETH_IP:
        case PROTO_IP_IN_IP:
        case ETH_IP6:
            dp_promote_pkt_to_layer3(
                    dp_ctx,
                    vrf, iif, 
                    pkt_block,
                    eth_type);
            break;
        default: ;
    }
}

bool 
l2_frame_recv_qualify_on_interface( dp_ctx_t *dp_ctx,
                                    dp_vrf_t *vrf,
                                    dp_intf_t *interface, 
                                    pkt_block_t *pkt_block,
                                    uint16_t *output_vlan_id){

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;

    *output_vlan_id = 0;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
                        is_pkt_vlan_tagged(ethernet_hdr);

    /* Presence of IP address on interface makes it work in L3 mode,
     * while absence of IP-address automatically make it work in
     * L2 mode provided that it is operational either in ACCESS mode or TRUNK mode.*/

    /* case 10 : If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/

    tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
        "Pkt : %s received on interface %s being tested for "
        "RECV-Qualification test\n", pkt_block_str(pkt_block), interface->if_name);

    if (!interface->ip_addr &&
            !interface->switchport) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
            "failed RECV-Qualification test : Interface is neither L3 interface or L2 switchport\n",
            pkt_block_str(pkt_block), interface->if_name);

        return false;
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
                pkt_block_str(pkt_block), interface->if_name);
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
                pkt_block_str(pkt_block), interface->if_name,  
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
                pkt_block_str(pkt_block), interface->if_name);
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
                pkt_block_str(pkt_block), interface->if_name,  pkt_vlan_id);
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
            pkt_block_str(pkt_block), interface->if_name);
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
        pkt_block_str(pkt_block), interface->if_name);    

    interface->recvd_pkt_dropped++;
    return false;
}

bool 
is_arp_pkt_for_svi_interface (dp_ctx_t *dp_ctx,
                              dp_vrf_t *vrf,
                              pkt_block_t *pkt_block)
{
    uint16_t proto;
    pkt_size_t pkt_size;
    arp_hdr_t *arp_hdr;
    uint32_t svi_ip_addr;
    uint16_t vlan_id = 0;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    ethernet_hdr_t *ethernet_hdr = NULL;
    vlan_ethernet_hdr_t *vlan_eth_hdr = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    if (is_pkt_vlan_tagged(ethernet_hdr)) {
        vlan_eth_hdr = (vlan_ethernet_hdr_t *)ethernet_hdr;
        proto = htons(vlan_eth_hdr->type);
        vlan_id = GET_802_1Q_VLAN_ID(&vlan_eth_hdr->vlan_8021q_hdr);
    }   
    else {
        proto = htons(ethernet_hdr->type);
    }

    if (proto != PROTO_ARP) return false;

    arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
    
    if (htons(arp_hdr->op_code) != ARP_BROAD_REQ && 
         htons(arp_hdr->op_code) != ARP_REPLY) return false;

    /* Lookup Vlan Inteface */
    dp_intf_t *svi_intf = dp_look_up_interface_by_vlan_id(dp_ctx->dp_intf_ht, vlan_id);

    if (!svi_intf) return false;

    return (svi_intf->ip_addr == htonl(arp_hdr->dst_ip)) ;
}

bool
svi_interface_intercept_arp_pkt (dp_ctx_t *dp_ctx,
                                dp_vrf_t *vrf,
                                pkt_block_t *pkt_block) {

    uint16_t l3_proto;
    pkt_size_t pkt_size;
    
    vlan_ethernet_hdr_t *vlan_eth_hdr;
    dp_intf_t *interface = pkt_block->ingress_intf;
    
    assert(pkt_block_verify_pkt(pkt_block, ETH_HDR));

    vlan_eth_hdr = ( vlan_ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);
    uint16_t pkt_vlan_id = GET_802_1Q_VLAN_ID(&vlan_eth_hdr->vlan_8021q_hdr);
    l3_proto = vlan_eth_hdr->type;

    /* Step 1*/
    if (!interface->switchport) return false;

    /* Step 2 */
    dp_intf_t *vlan_intf = NULL;
    
    if (interface->l2_mode == DP_LAN_ACCESS_MODE) {
        vlan_intf = interface->vlan_intf;
    }
    else if (interface->l2_mode == DP_LAN_TRUNK_MODE) {   
        vlan_intf = dp_look_up_interface_by_vlan_id(
                    dp_ctx->dp_intf_ht, pkt_vlan_id);
    }
    else {
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s recvd on switchport %s which is neither "
            "in Access nor in Trunk mode, Pkt Dropped\n",
            pkt_block_str(pkt_block), interface->if_name);
        return true;
    }

    if (!vlan_intf) {
        /* It means, the pkt is recvd on switchport interface but
         * the interface is not operating in any vlan*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s recvd on switchport %s which is not bound to any vlan, pkt Dropped\n",
            pkt_block_str(pkt_block), interface->if_name);
        return true;
    }

    uint32_t svi_ip_addr;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    assert (vrf == vlan_intf->vrf);

    /*Process ARP packets destined for SVI interface */
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr));

    if (htons(arp_hdr->op_code) == ARP_REPLY) {

        arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table, arp_hdr, vlan_intf);
        return true;
    }

    if (htons(arp_hdr->op_code) != ARP_BROAD_REQ) return true;

    svi_ip_addr = vlan_intf->ip_addr;

    tracer(dp_ctx->dptr, DL2FWD | DFLOW,
           "Pkt : %s recvd on SVI interface %s is ARP Broadcast "
           "request for SVI IP, Sending ARP reply\n",
           pkt_block_str(pkt_block), vlan_intf->if_name);

    /* Overhead ARP Boradcast pkt and update ARP cache */
    arp_table_update_from_arp_reply(dp_ctx, vrf, vrf->arp_table,
                                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr),
                                    vlan_intf);

    arp_hdr_t *arp_hdr_in = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)vlan_eth_hdr));

    pkt_size_t arp_reply_pkt_size = VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD +
                                    (pkt_size_t)sizeof(arp_hdr_t);

    vlan_ethernet_hdr_t *vlan_ethernet_hdr_reply =
        (vlan_ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(arp_reply_pkt_size);

    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tci_vid = 0;
    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tci_vid |= htons((uint16_t)pkt_vlan_id);
    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tci_dei = 0;
    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tci_pcp = 0;
    vlan_ethernet_hdr_reply->vlan_8021q_hdr.tpid = htons(VLAN_8021Q_PROTO);

    l2_prepare_arp_reply_msg((ethernet_hdr_t *)vlan_ethernet_hdr_reply,
                             &arp_hdr_in->src_mac, arp_hdr_in->src_ip,
                             &vlan_intf->mac_add, svi_ip_addr);

    pkt_block_t *pkt_block2 = pkt_block_get_new(
            (uint8_t *)vlan_ethernet_hdr_reply, arp_reply_pkt_size);
    pkt_block_set_starting_hdr_type(pkt_block2, ETH_HDR);

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

    dp_send_pkt_out(dp_ctx, interface, pkt_block2);
    pkt_block_dereference(pkt_block2);
    return true;
}
