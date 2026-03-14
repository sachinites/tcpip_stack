#include <stdlib.h>
#include <memory.h>
#include "../../pkt_block.h"
#include "../../net.h"
#include "dp_intf.h"
#include "dp_intf_store.h"
#include "../../FireWall/acl/acldb.h"
#include "../../Tracer/tracer.h"
#include "../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../../common/l2_hdrs.h"
#include "../../common/l3_hdrs.h"
#include "../Layer3/layer3.h"
#include "../Layer2/vxlan/vxlan_dp.h"
#include "dp_intf_log.h"
#include "../dp_utils.h"
#include "../dp_uapi.h"
#include "../Layer3/Gre/gre-fwd.h"
#include "../Layer3/SRv6/srv6-endpoint.h"
#include "../../common/cmn_api.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "../Layer2/switching/mac_table.h"

typedef int (*SendPacketOut_fptr)(
            dp_ctx_t *, 
            dp_intf_t *, pkt_block_t *);

extern bool LinuxRtr;

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ;

/**
 * Payload for recv/send path: packet pointer, interface index, and size.
 * Used when passing packets into the datapath event dispatcher.
 */
typedef struct ev_dis_pkt_data_ {

    unsigned char *pkt;
    uint32_t ifindex;
    uint32_t pkt_size;

} ev_dis_pkt_data_t;


/* Helper APIs */

static int
send_xmit_out (dp_intf_t *intf, pkt_block_t *pkt_block)
{
    pkt_size_t pkt_size;
    ev_dis_pkt_data_t *ev_dis_pkt_data;

    dp_ctx_t *local_dp_ctx = intf->dp_ctx;
    dp_ctx_t *peer_dp_ctx = intf->nbr_intf->dp_ctx;
    dp_intf_t *peer_end = intf->nbr_intf;

    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!(intf->is_up))
    {
        intf->xmit_pkt_dropped++;
        return 0;
    }

    if (pkt_size > MAX_PACKET_BUFFER_SIZE)
    {
        cprintf("Error : DCTX :%s, Pkt Size exceeded\n", local_dp_ctx->ctx_name);
        return -1;
    }

    tracer (local_dp_ctx->dptr, DFLOW_DET, 
        "Pkt : %s Wired out of interface %s\n", 
        pkt_block_str (pkt_block), intf->if_name);

    ev_dis_pkt_data = (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

    ev_dis_pkt_data->ifindex = peer_end->port_id;
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
    memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
    ev_dis_pkt_data->pkt_size = pkt_size;

    tcp_dump_send_logger(local_dp_ctx, intf,
                         pkt_block, pkt_block_get_starting_hdr(pkt_block));

    if (!pkt_q_enqueue(EV_DP(peer_dp_ctx), 
                       DP_PKT_Q(peer_dp_ctx),
                       (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t)))
    {
        cprintf("%s : Fatal : Ingress Pkt QueueExhausted\n", peer_dp_ctx->ctx_name);
        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        free (ev_dis_pkt_data);
    }

    intf->pkt_sent++;
    return pkt_size;
}

static int
SendPacketOutSwitchport(dp_intf_t *Intf, pkt_block_t *pkt_block)
{

    pkt_size_t pkt_size;

    DP_IntfL2Mode intf_l2_mode = Intf->l2_mode;

    if (intf_l2_mode == DP_LAN_MODE_NONE)
    {
        return 0;
    }

    ethernet_hdr_t *ethernet_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(ethernet_hdr);

    switch (intf_l2_mode)
    {

    case DP_LAN_ACCESS_MODE:
    {
        uint16_t intf_vlan_id = Intf->vlan_id;

        /*Case 1 : If interface is operating in ACCESS mode, but
         not in any vlan, and pkt is also untagged, then simply
         forward it. This is default Vlan unaware case*/
        if (!intf_vlan_id && !vlan_8021q_hdr)
        {
            return send_xmit_out(Intf, pkt_block);
        }

        /*Case 2 : if oif is VLAN aware, but pkt is untagged, simply
         drop the packet. This is not an error, it is a L2 switching
         behavior*/
        if (intf_vlan_id && !vlan_8021q_hdr)
        {
            return 0;
        }

        /*Case 3 : If oif is VLAN AWARE, and pkt is also tagged,
          forward the frame only if vlan IDs matches after untagging
          the frame*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id == GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {
            untag_pkt_with_vlan_id(pkt_block);
            return send_xmit_out(Intf, pkt_block);
        }

        /* case 4 : if vlan id in pkt do not matches with the vlan id of
            the interface*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id != GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {
            return 0;
        }

        /*case 5 : if oif is vlan unaware but pkt is vlan tagged,
         simply drop the packet.*/
        if (!intf_vlan_id && vlan_8021q_hdr)
        {
            return 0;
        }
    }
    break;
    case DP_LAN_TRUNK_MODE:
    {
        uint16_t pkt_vlan_id = 0;

        if (vlan_8021q_hdr)
        {
            pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        }

        if (pkt_vlan_id &&
            dp_is_vlan_member(Intf->vlan_bitmap, pkt_vlan_id))
        {
            return send_xmit_out(Intf, pkt_block);
        }

        /*Do not send the pkt in any other case*/
        return 0;
    }
    break;
    case DP_LAN_MODE_NONE:
        break;
    default:;
    }
    return 0;
}

static void
vlan_send_pkt_out_all_trunk_ports(dp_intf_t *vlan_intf,
                                  pkt_block_t *pkt_block,
                                  dp_intf_t *exempt_intf,
                                  bool only_trunk_ports)
{
    int i;
    dp_intf_t *member_port;
    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++)
    {
        member_port = vlan_intf->mports[i];
        if (!member_port || member_port == exempt_intf)
            continue;
        if (!member_port->is_up)
            continue;
        if (member_port->l2_mode == DP_LAN_MODE_NONE) continue;
        if (only_trunk_ports && (member_port->l2_mode != DP_LAN_TRUNK_MODE))
            continue;
        send_xmit_out(member_port, pkt_block);
    }
}

static void
dp_VlanPacketFlood (dp_intf_t *vlan_intf, 
                    pkt_block_t *pkt_block, 
                    dp_intf_t *exempt_intf) {

    int i;
    dp_intf_t *member_port;

    ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

    if (is_pkt_vlan_tagged (eth_hdr)) {

        vlan_send_pkt_out_all_trunk_ports (vlan_intf, pkt_block, exempt_intf, true);
        untag_pkt_with_vlan_id(pkt_block);
        vlan_send_pkt_out_all_trunk_ports (vlan_intf, pkt_block, exempt_intf, false);
    }
    else {

        vlan_send_pkt_out_all_trunk_ports (vlan_intf, pkt_block, exempt_intf, false);
        tag_pkt_with_vlan_id(pkt_block, vlan_intf->vlan_id);
        vlan_send_pkt_out_all_trunk_ports (vlan_intf, pkt_block, exempt_intf, true);
    }
}

static int 
PhysicalInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    if (intf->switchport)
    {
        return SendPacketOutSwitchport(intf, pkt_block);
    }
    else
    {
        return send_xmit_out(intf, pkt_block);
    }
}

static int 
VlanInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    dp_VlanPacketFlood (intf, pkt_block, NULL);    
    return 0;
}

static int 
GRETunnelInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    pkt_size_t pkt_size;
    bool no_modify = false;
    pkt_block_t *pkt_block_copy;

    if (!intf->is_up) { return 0; }
    
    if (pkt_block->no_modify) {
        no_modify = pkt_block->no_modify;
        pkt_block_copy = pkt_block_dup (pkt_block);
        pkt_block = pkt_block_copy;
    }

    gre_encasulate (dp_ctx, pkt_block);
    pkt_block->exclude_oif = intf;
    pkt_block_get_pkt (pkt_block, &pkt_size);

    /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t)));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = htonl(dp_ctx->rtr_id);
    ip_hdr->dst_ip = htonl(intf->gre_tunnel_dst_ip);
    ip_hdr->protocol = GRE_PROTO;
    ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);
    dp_send_ip_data (dp_ctx, intf->vrf, pkt_block);
    intf->pkt_sent++;
    pkt_block_get_pkt (pkt_block, &pkt_size);

    if (no_modify) {
        pkt_block_dereference(pkt_block);
    }

    return pkt_size;
}


static int 
VirtualPort_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    pkt_size_t pkt_size;

    if (!intf->olay_tunnel_intf || !intf->is_up) {
        intf->xmit_pkt_dropped++;
        return 0;
    }
    
    assert (pkt_block_get_starting_hdr(pkt_block) == ETH_HDR);

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    assert (vlan_8021q_hdr );

    /* If vport is in trunk mode, then check if vlan id is part of trunk*/
    if (!dp_is_vlan_member (intf->vlan_bitmap, (
        GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))) return 0;

    intf->pkt_sent++;

    dp_send_pkt_out(dp_ctx, intf->olay_tunnel_intf, pkt_block);
    return 0;
}

static int 
RmacInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    pkt_size_t pkt_size;

    assert(pkt_block_verify_pkt(pkt_block, ETH_HDR));

    ethernet_hdr_t *eth_hdr = 
        ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Rmac interface never recvs untagged pkt */
    assert (is_pkt_vlan_tagged (eth_hdr));

    /* Case 1 : If this is ARP Broadcast pkt requesting IP for Rmac interface*/
    /* Case 2 : If this is ARP reply packet recvd by Rmac Interface */
    
    if ( is_arp_pkt_for_svi_interface (dp_ctx, intf->vrf, pkt_block) ) {
            svi_interface_intercept_arp_pkt (dp_ctx, intf->vrf, pkt_block);
            return 0;
    }

    /* Case 3 : if this is any other ethernet pkt with dst mac = RMAC address */

    if (!mac_address_compare ((unsigned char *)intf->dp_ctx->rmac.mac, 
          (unsigned char *)eth_hdr->dst_mac.mac) != 0) {

        intf->recvd_pkt_dropped++;
        return 0;
    }

    untag_pkt_with_vlan_id(pkt_block);
    eth_hdr = ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    dp_promote_pkt_to_layer3 (dp_ctx, intf->vrf, intf,
            pkt_block, eth_hdr->type);

    return 0;
}

static int 
LoopbackInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){
    
    /* black hole the pkt */
    return 0;
}

static int 
NVEInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

    pkt_size_t pkt_size;
    unsigned char ipv4_addr_str1[IPV4_ADDR_LEN_STR] = {0};
    unsigned char ipv4_addr_str2[IPV4_ADDR_LEN_STR] = {0};
    
    if (!intf->is_up) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VxLAN Encapsulation : Error : NVE Interface %s is down\n", intf->if_name);
        intf->xmit_pkt_dropped++;
        return -1;
    }

    if (!pkt_block->encap_data) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VxLAN Encapsulation : Error : Pkt Block has no encap data\n");
        intf->xmit_pkt_dropped++;
        return -1;
    }

    vxlan_encapsulate (dp_ctx, pkt_block);

 /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t)));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *ip_hdr = (ip_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = htonl(dp_ctx->rtr_id);
    ip_hdr->dst_ip = htonl(pkt_block->encap_data->u.vxlan.remote_vtep_ip);
    ip_hdr->protocol = UDP_PROTO;
    ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : Outer IP Hdr Header Attached with Src : %s, Dst %s, Proto = %x\n",
        tcp_ip_covert_ip_n_to_p ( htonl(ip_hdr->src_ip), ipv4_addr_str1),
        tcp_ip_covert_ip_n_to_p ( htonl(ip_hdr->dst_ip), ipv4_addr_str2),
        ip_hdr->protocol );

    dp_send_ip_data (dp_ctx, intf->vrf, pkt_block);
    intf->pkt_sent++;
    return 0;    
}

/* Algorithm 
    1. Remove the outer ethernet header if Data layer passed it
    2. Decap the pkt, and remove ipv6 header + SRH header
    3. Underneath must be ipv4 header, if not drop the pkt
    4. Using ipv4 header, lool up vrf.inet.0 fib where vrf is obtained from 
        intf->srv6_data.steered_dt4_vrf
    5. forward the pkt using fib entry.
*/
static int 
SRv6EndPointEND_DT4InterfaceEgress_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        pkt_block_t *pkt_block){

    pkt_size_t pkt_size;

    /* Step 1: Strip outer ethernet header if the data layer included it */
    if (pkt_block_get_starting_hdr(pkt_block) == ETH_HDR) {
        uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
        ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
        uint32_t eth_hdr_size = GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth_hdr);
        uint8_t *payload = GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
        pkt_block_set_new_pkt(pkt_block, payload, pkt_size - eth_hdr_size);
        pkt_block_set_starting_hdr_type(pkt_block, IP6_HDR);
    }

    /* Step 2: Decapsulate: strip the outer IPv6 header and SRH */
    Srv6_decapsulate(pkt_block);

    /* Step 3: Inner payload must be IPv4; drop anything else */
    if (pkt_block_get_starting_hdr(pkt_block) != IP_HDR) {
        tracer(dp_ctx->dptr, DL3FWD | DERR,
            "SRv6 END.DT4: inner packet is not IPv4, dropping\n");
        return 0;
    }

    /* Step 4: Resolve the VRF for the IPv4 FIB lookup */
    dp_vrf_t *steered_vrf = intf->srv6_data.steered_dt4_vrf;
    if (!steered_vrf) {
        tracer(dp_ctx->dptr, DL3FWD | DERR,
            "SRv6 END.DT4: no steered VRF configured on interface %s, dropping\n",
            intf->if_name);
        return 0;
    }

    /* Step 5: Forward the inner IPv4 packet using the steered VRF FIB */
    layer3_ip_route_pkt(dp_ctx, steered_vrf, NULL, pkt_block);
    intf->pkt_sent++;
    
    return 0;
}


/* This array is arranged in sequence of these enums : InterfaceType_t */
static SendPacketOut_fptr intf_xmit_cbk[] = 
    {
        PhysicalInterface_SendPacketOut, 
        VlanInterface_SendPacketOut,
        GRETunnelInterface_SendPacketOut,
        LoopbackInterface_SendPacketOut,
        VirtualPort_SendPacketOut,
        RmacInterface_SendPacketOut,
        0,
        NVEInterface_SendPacketOut,
        SRv6EndPointEND_DT4InterfaceEgress_SendPacketOut,
        0,
        0
    };

void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block) {

    (intf_xmit_cbk[intf->if_type])(dp_ctx, intf, pkt_block);
}

/* -------------------------------------------------- */

/* Pkt Reception APIs */

static void 
dp_pkt_receive(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
                    dp_intf_t *interface,
                    pkt_block_t *pkt_block)
{

    vlan_id_t vlan_id_to_tag = 0;
  
      if (!interface->is_up){
        return;
    }
    
    interface->pkt_recv++;
    tcp_dump_recv_logger(dp_ctx, interface, pkt_block, ETH_HDR);

    /* Access List Evaluation at Layer 2 Entry point*/ 
    #if 0
    if (access_list_evaluate_ethernet_packet (
                node, interface, pkt_block, true) 
                == ACL_DENY) {
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : Pkt Dropped : L2 ACL Denied on ingress interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);
        return;
    }
    #endif

    if (l2_frame_recv_qualify_on_interface(dp_ctx,
                                          vrf,
                                          interface, 
                                          pkt_block,
                                          &vlan_id_to_tag) == false){
        
        cprintf("Error : L2 Frame Rejected on node %s(%s)\n", 
            dp_ctx->ctx_name, interface->if_name);
            
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : L2 Frame Rejected in Interface %s, qualification Test Failed\n", 
            pkt_block_str(pkt_block), interface->if_name);

        return;
    }

    if ((interface->switchport &&
            interface->l2_mode != DP_LAN_MODE_NONE)) {

        pkt_block->ingress_intf = interface;

        if (vlan_id_to_tag) {
           
            tag_pkt_with_vlan_id (pkt_block, vlan_id_to_tag);
            tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Tagged with VLAN ID %d\n", 
                pkt_block_str(pkt_block), vlan_id_to_tag);
        }

        if (vlan_id_to_tag == 0) {

            /* We did not tag the pkt because pkt was already tagged.*/
            vlan_8021q_hdr_t *vlan_8021q_hdr;

            assert ((vlan_8021q_hdr = 
                is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, NULL))));

            vlan_id_to_tag = (vlan_id_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        }

        l2_switch_recv_frame(dp_ctx,
                    vlan_id_to_tag,
                    interface, pkt_block);
    }

    /* If packet is Recvd on GRE interface and pkt is vlan tagged, 
        it means GRE is being used for VLAN extension */
    else if (interface->if_type == DP_INTF_TYPE_GRE_TUNNEL &&
                pkt_block_verify_pkt (pkt_block, ETH_HDR) &&
                is_pkt_vlan_tagged (pkt_block_get_ethernet_hdr(pkt_block))) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Being recieved on GRE Interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);  

        dp_pkt_receive (dp_ctx, interface->virtual_port->vrf, interface->virtual_port, pkt_block);
    }

    else if (interface->ip_addr){

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
            "Pkt : %s : Recvd on L3 Interface %s, being protmoted to L3Fwding\n", 
            pkt_block_str(pkt_block), interface->if_name);
            
        pkt_block->ingress_intf = interface;
        promote_pkt_to_layer2(dp_ctx, interface->vrf, interface, pkt_block);
    }

    else {
        /* We dont know what to do with the pkt*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : pkt dropped, Unknown pkt recvd on Interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);
        interface->recvd_pkt_dropped++;
    }
}

extern void
dp_pkt_recvr_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    dp_ctx_t *dp_ctx;
    pkt_block_t *pkt_block;
	dp_intf_t *recv_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

    dp_ctx = (dp_ctx_t *)(ev_dis->app_data);

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		recv_intf = dp_look_up_interface(dp_ctx->dp_intf_ht, ev_dis_pkt_data->ifindex);
        assert(recv_intf);

		pkt = ev_dis_pkt_data->pkt;		

        pkt_block = pkt_block_get_new((uint8_t *)pkt, ev_dis_pkt_data->pkt_size);
        pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);

		dp_pkt_receive(dp_ctx, recv_intf->vrf,
                    recv_intf, 
                    pkt_block);

        pkt_block_dereference(pkt_block);
		free (ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
	}
}

int
dp_inject_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface){
 
    uint8_t *pkt;
    pkt_size_t pkt_size;

    if (!interface->is_up){
        return 0;
    }

    dp_ctx_t  *nbr_dp_ctx = dp_ctx;
    dp_intf_t *peer_intf = interface;

	ev_dis_pkt_data_t *ev_dis_pkt_data;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

	ev_dis_pkt_data =  (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

	ev_dis_pkt_data->ifindex = peer_intf->port_id;
	ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

	pkt_q_enqueue(EV_DP(nbr_dp_ctx), 
                  DP_PKT_Q(nbr_dp_ctx),
                  (char *)ev_dis_pkt_data,
                  sizeof(ev_dis_pkt_data_t));

    return pkt_size; 
}

int
send_pkt_flood(dp_ctx_t *dp_ctx, 
               dp_intf_t *exempted_intf, 
               pkt_block_t *pkt_block) {

    dp_intf_t *intf; 

    struct hashtable_itr *itr = hashtable_iterator(dp_ctx->dp_intf_ht);

    while ((intf = (dp_intf_t *)hashtable_iterator_value(itr))) {
    
        if(!intf) {
            free(itr);
            return 0;
        }

        if(intf == exempted_intf) {
            hashtable_iterator_advance(itr);
            continue;
        }
        dp_send_pkt_out(dp_ctx, intf, pkt_block);
        hashtable_iterator_advance(itr);
    } 
    free(itr);
    
    return 0;
}

void dp_pkt_xmit_intf_job_cbk(event_dispatcher_t *ev_dis,
                              void *pkt, uint32_t pkt_size)
{

    dp_intf_t *dp_intf;
    pkt_block_t *pkt_block;

    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    ev_dis_pkt_data_t *ev_dis_pkt_data =
        (ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

    if (!ev_dis_pkt_data)
    {
        return;
    }

    for (; ev_dis_pkt_data;
         ev_dis_pkt_data = (ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size))
    {

        dp_intf = dp_look_up_interface(dp_ctx->dp_intf_ht, ev_dis_pkt_data->ifindex);

        if (!dp_intf)
        {
            free(ev_dis_pkt_data);
            continue;
        }
        pkt_block = (pkt_block_t *)ev_dis_pkt_data->pkt;
        dp_send_pkt_out(dp_ctx, dp_intf, pkt_block);
        pkt_block_dereference(pkt_block);
        free(ev_dis_pkt_data);
    }
}

void 
dp_uapi_xmit_pkt(dp_ctx_t *dp_ctx, uint32_t ifindex, pkt_block_t *pkt_block) {

    ev_dis_pkt_data_t *ev_dis_pkt_data = (ev_dis_pkt_data_t *)
        calloc(1, sizeof(ev_dis_pkt_data_t));

    ev_dis_pkt_data->ifindex = ifindex;

    ev_dis_pkt_data->pkt = (unsigned char *)pkt_block;

    pkt_block_reference(pkt_block);

    pkt_q_enqueue(EV_DP(dp_ctx),
                  &dp_ctx->cp_to_dp_xmit_intf_pkt_q,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
}