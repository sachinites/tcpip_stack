#include "../../pkt_block.h"
#include "../../net.h"
#include "dp_intf.h"
#include "dp_intf_store.h"
#include "../../FireWall/acl/acldb.h"
#include "../../Tracer/tracer.h"
#include "../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../../common/l2_hdrs.h"
#include "../../common/l3_hdrs.h"
#include "../../Layer3/layer3.h"
#include "../Layer2/vxlan/vxlan_dp.h"
#include "dp_intf_log.h"
#include "../dp_utils.h"


typedef int (*SendPacketOut_fptr)(
            dp_ctx_t *, 
            dp_intf_t *, pkt_block_t *);

extern bool LinuxRtr;

extern void
promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ;

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
    ev_dis_pkt_data->pkt = dp_get_new_pkt_buffer(pkt_size);
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
    np_tcp_ip_send_ip_data (dp_ctx, intf->vrf, pkt_block);
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

    promote_pkt_to_layer3 (dp_ctx, intf->vrf, intf,
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

    np_tcp_ip_send_ip_data (dp_ctx, intf->vrf, pkt_block);
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
        NVEInterface_SendPacketOut,
        0,
        0,
        0
    };

void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block) {

    (intf_xmit_cbk[intf->if_type])(dp_ctx, intf, pkt_block);
}
