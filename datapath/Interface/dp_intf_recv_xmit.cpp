#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <fcntl.h>

#include "../../libs/pkt-block/pkt_block.h"
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
#include "../../libs/Tracer/tracer.h"
#include "../../libs/common/l2_hdrs.h"
#include "../../libs/common/l3_hdrs.h"

#include "dp_intf.h"
#include "dp_intf_log.h"
#include "dp_intf_store.h"

#include "../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../Layer3/layer3.h"
#include "../Layer2/vxlan/vxlan_dp.h"

#include "../dp_ctx.h"
#include "../dp_utils.h"
#include "../dp_uapi.h"
#include "../Layer3/Gre/gre-fwd.h"
#include "../Layer3/SRv6/srv6-endpoint.h"
#include "../Layer2/switching/mac_table.h"

typedef int (*SendPacketOut_fptr)(
            dp_ctx_t *, 
            dp_intf_t *, pkt_block_t *);

extern bool LinuxRtr;
extern int cprintf (const char* format, ...);

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      pkt_block_t *pkt_block);

/**
 * Payload for recv/send path: packet pointer, interface index, and size.
 * Used when passing packets into the datapath event dispatcher.
 */
typedef struct ev_dis_pkt_data_ {

    unsigned char *pkt;
    uint32_t ifindex;
    uint32_t pkt_size;

} ev_dis_pkt_data_t;

static int
linux_send_xmit_out (dp_intf_t *dp_intf, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    assert (LinuxRtr);
        
    int sockfd = dp_intf->LinuxRtr_sockfd;

    if (sockfd < 0) {

        cprintf ("%s : Error : Failed to create raw socket for Intf %s: errno : %d\n",
            dp_intf->if_name, strerror(errno));

        return -1;
    }

    char *pkt = (char *)pkt_block_get_pkt (pkt_block, &pkt_size);

    if (pkt_size <= 0 || pkt_size > MAX_MTU) { 

        cprintf ("%s : Error : Invalid packet length recvd on Intf %s : %dB\n",
            dp_intf->if_name, pkt_size);

        return -1;
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = dp_intf->port_id;
    sll.sll_halen = 6; // MAC address length

    memcpy(sll.sll_addr, dp_intf->mac_add.mac, 6);
    
    ssize_t bytes_sent = sendto(sockfd, pkt, pkt_size, 0, 
                               (struct sockaddr*)&sll, sizeof(sll));
    
    assert (bytes_sent > 0);
    dp_intf->pkt_sent++;
    return (int)bytes_sent;
}

/* Helper APIs */

static int
send_xmit_out (dp_intf_t *intf, pkt_block_t *pkt_block)
{
    pkt_size_t pkt_size;
    ev_dis_pkt_data_t *ev_dis_pkt_data;

    dp_ctx_t *local_dp_ctx = intf->dp_ctx;
    
    if (!(intf->is_up))
    {
        cprintf("Error : DCTX : %s, Interface %s is not up\n", 
            local_dp_ctx->ctx_name, intf->if_name);
        intf->xmit_pkt_dropped++;
        return -1;
    }

    if (pkt_block->pkt_size > MAX_PACKET_BUFFER_SIZE)
    {
        cprintf("Error : DCTX : %s, Pkt Size exceeded\n", local_dp_ctx->ctx_name);
        intf->xmit_pkt_dropped++;
        return -1;
    }    

    tracer (local_dp_ctx->dptr, DFLOW_DET, 
        "Pkt : %s Wired out of interface %s\n", 
        pkt_block_str (pkt_block), intf->if_name);

    if (LinuxRtr) {
        return linux_send_xmit_out (intf, pkt_block);
    }

    dp_ctx_t *peer_dp_ctx = intf->nbr_intf->dp_ctx;
    dp_intf_t *peer_end = intf->nbr_intf;

    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    ev_dis_pkt_data = (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

    ev_dis_pkt_data->ifindex = peer_end->port_id;
    ev_dis_pkt_data->pkt = (unsigned char *)XCALLOC_BUFF(0, pkt_size);
    memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
    ev_dis_pkt_data->pkt_size = pkt_size;

    tcp_dump_send_logger(local_dp_ctx, intf,
                         pkt_block, pkt_block_get_starting_hdr(pkt_block));

    if (!pkt_q_enqueue(EV_DP(peer_dp_ctx), 
                       DP_PKT_Q(peer_dp_ctx),
                       (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t)))
    {
        cprintf("%s : Fatal : Ingress Pkt QueueExhausted\n", peer_dp_ctx->ctx_name);
        XFREE(ev_dis_pkt_data->pkt);
        free (ev_dis_pkt_data);
    }

    intf->pkt_sent++;
    return pkt_size;
}

static int
SendPacketOutSwitchport(dp_ctx_t *dp_ctx, dp_intf_t *Intf, pkt_block_t *pkt_block)
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
        uint16_t intf_vlan_id = Intf->vlan_intf->vlan_id;

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
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Access port %s dropped outgoing untagged packet\n", 
                pkt_block_str(pkt_block), Intf->if_name);
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
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Access port dropped %s outgoing tagged packet with mismatched vlan id\n", 
                pkt_block_str(pkt_block), Intf->if_name);
            return 0;
        }

        /*case 5 : if oif is vlan unaware but pkt is vlan tagged,
         simply drop the packet.*/
        if (!intf_vlan_id && vlan_8021q_hdr)
        {
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Vlan unaware Access port %s dropped outgoing tagged packet\n", 
                pkt_block_str(pkt_block), Intf->if_name);
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

        tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
            "Pkt %s Dropped : Reason : Trunk port %s dropped outgoing packet\n", 
            pkt_block_str(pkt_block), Intf->if_name);

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

        if (only_trunk_ports && (member_port->l2_mode == DP_LAN_TRUNK_MODE)) 
             send_xmit_out(member_port, pkt_block);
        else if (!only_trunk_ports && (member_port->l2_mode == DP_LAN_ACCESS_MODE))
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
        return SendPacketOutSwitchport(dp_ctx, intf, pkt_block);
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
    pkt_block_get_pkt (pkt_block, &pkt_size);

    /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t)));
    pkt_block_update_new_hdr_type (pkt_block, IP_PROTO_IP_IN_IP);
    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = htonl(dp_ctx->rtr_id);
    ip_hdr->dst_ip = htonl(intf->gre_tunnel_dst_ip);
    ip_hdr->protocol = IP_PROTO_GRE;
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
    
    assert (pkt_block_get_starting_hdr(pkt_block) == ETHERNET_HEADER);

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
    vlan_8021q_hdr_t *vlan_8021q_hdr;

    assert(pkt_block_verify_pkt(pkt_block, ETHERNET_HEADER));

    ethernet_hdr_t *eth_hdr = 
        ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Rmac interface never recvs untagged pkt */
    assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (eth_hdr)));

    /* Case 1 : If this is ARP Broadcast pkt requesting IP for Rmac interface*/
    /* Case 2 : If this is ARP reply packet recvd by Rmac Interface */

    tracer (dp_ctx->dptr, DL2FWD , 
        "Rmac Interface %s : Recvd pkt %s with vlan tag : %d\n", 
        intf->if_name, pkt_block_str(pkt_block), TCI_VID(vlan_8021q_hdr->tci));
    
    if ( is_arp_pkt_for_svi_interface (dp_ctx, pkt_block) ) {
            svi_interface_intercept_arp_pkt (dp_ctx, intf->vrf, pkt_block);
            return 0;
    }

    /* Case 3 : if this is any other ethernet pkt with dst mac = RMAC address */

    if (!mac_address_compare ((unsigned char *)dp_ctx->rmac.mac, 
          (unsigned char *)eth_hdr->dst_mac.mac) != 0) {

        intf->recvd_pkt_dropped++;
        return 0;
    }

    untag_pkt_with_vlan_id(pkt_block);
    assert (eth_hdr->type == ntohs (ETH_TYPE_IPv4));
    pkt_block_set_new_pkt(
        pkt_block, (uint8_t *)(GET_ETHERNET_HDR_PAYLOAD(eth_hdr)),
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD);
    dp_promote_pkt_to_layer3 (dp_ctx, intf->vrf, intf, pkt_block);

    return 0;
}

static int 
LoopbackInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){
    
    /* black hole the pkt */
    return 0;
}

static int 
NVEInterface_SendPacketOut (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block){

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
    pkt_block_update_new_hdr_type (pkt_block, IP_PROTO_IP_IN_IP);
    ip_hdr_t *ip_hdr = (ip_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = htonl(dp_ctx->rtr_id);
    ip_hdr->dst_ip = htonl(pkt_block->encap_data->u.vxlan.remote_vtep_ip);
    ip_hdr->protocol = IP_PROTO_UDP;
    ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : Outer IP Hdr Header Attached with Src : %s, Dst %s, Proto = %x\n",
        tcp_ip_covert_ip_n_to_p ( ntohl(ip_hdr->src_ip), ipv4_addr_str1),
        tcp_ip_covert_ip_n_to_p ( ntohl(ip_hdr->dst_ip), ipv4_addr_str2),
        ip_hdr->protocol );

    dp_send_ip_data (dp_ctx, intf->vrf, pkt_block);
    intf->pkt_sent++;
    return 0;    
}

static int 
VlanFloodInterface_SendPacketOut(
                                    dp_ctx_t *dp_ctx, 
                                    dp_intf_t *vfif_intf, 
                                    pkt_block_t *pkt_block) {

    dp_intf_t *exempt_intf = (dp_intf_t *)pkt_block->ingress_intf;

    assert (exempt_intf);

    assert (pkt_block_get_starting_hdr(pkt_block) == ETHERNET_HEADER);

    ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);
    assert (vlan_8021q_hdr);
    uint16_t vlan_id = (uint16_t)TCI_VID(vlan_8021q_hdr->tci);

    dp_intf_t *vlan_intf  = exempt_intf->l2_mode == DP_LAN_ACCESS_MODE ?
                    exempt_intf->vlan_intf : \
                    dp_look_up_interface_by_vlan_id (dp_ctx->dp_vlan_intf_ht, vlan_id);

    if (!vlan_intf) return -1;

    dp_VlanPacketFlood (vlan_intf, pkt_block, exempt_intf);
    vfif_intf->pkt_sent++;
    
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
    if (pkt_block_get_starting_hdr(pkt_block) == ETHERNET_HEADER) {
        uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
        ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
        uint32_t eth_hdr_size = GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth_hdr);
        uint8_t *payload = GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
        pkt_block_set_new_pkt(pkt_block, payload, pkt_size - eth_hdr_size);
        pkt_block_update_new_hdr_type(pkt_block, IP_PROTO_IPv6);
    }

    /* Step 2: Decapsulate: strip the outer IPv6 header and SRH */
    Srv6_decapsulate(pkt_block);

    /* Step 3: Inner payload must be IPv4; drop anything else */
    if (pkt_block_get_starting_hdr(pkt_block) != IP_PROTO_IP_IN_IP) {
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
        VlanFloodInterface_SendPacketOut,
        NVEInterface_SendPacketOut,
        SRv6EndPointEND_DT4InterfaceEgress_SendPacketOut,
        0,
        0
    };

void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block) {

    tracer(dp_ctx->dptr, DL3FWD_DET | DL2FWD_DET | DL2SW_DET,
        "Sending out frame %s out of interface %s\n", 
        pkt_block_str(pkt_block), intf->if_name);

    assert (pkt_block);

    (intf_xmit_cbk[intf->if_type])(dp_ctx, intf, pkt_block);
}

/* -------------------------------------------------- */

/* Pkt Reception APIs */

static void 
dp_pkt_entry_point(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
                    dp_intf_t *interface,
                    pkt_block_t *pkt_block)
{

    vlan_id_t vlan_id_to_tag = 0;
  
      if (!interface->is_up){
        return;
    }
    
    interface->pkt_recv++;
    tcp_dump_recv_logger(dp_ctx, interface, pkt_block, ETHERNET_HEADER);

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

        pkt_block->ingress_intf = (uintptr_t)interface;

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
                pkt_block_verify_pkt (pkt_block, ETHERNET_HEADER) &&
                is_pkt_vlan_tagged (pkt_block_get_ethernet_hdr(pkt_block))) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Being recieved on GRE Interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);  

        dp_pkt_entry_point (dp_ctx, interface->virtual_port->vrf,
                            interface->virtual_port, 
                            pkt_block);
    }

    else if (interface->ip_addr){

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
            "Pkt : %s : Recvd on L3 Interface %s, being protmoted to L3Fwding\n", 
            pkt_block_str(pkt_block), interface->if_name);
            
        pkt_block->ingress_intf = (uintptr_t)interface;
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
    uint8_t *pkt_start;
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

        /* Raw sockets deliver the Ethernet frame without the trailing FCS
         * (the kernel/NIC strips it on receive).  The rest of the stack uses
         * ETH_HDR_SIZE_EXCL_PAYLOAD = 18 (header + 4-byte FCS) for all frame-
         * size arithmetic, so allocate pkt_size + ETH_FCS_SIZE here to keep
         * the accounting consistent.  The extra 4 bytes are zeroed by calloc
         * and act as a zero-FCS placeholder, exactly as internally-built
         * frames do. Without this, promote_pkt_to_layer2 subtracts 4 bytes
         * too many, and SET_COMMON_ETH_FCS later overwrites the last 4 bytes
         * of the ICMP payload, corrupting the ICMP checksum on forwarded pkts. */
        pkt_block = pkt_block_get_new_pkt_buffer(ev_dis_pkt_data->pkt_size + (LinuxRtr ? ETH_FCS_SIZE : 0));
        pkt_start = (uint8_t *)pkt_block_get_pkt(pkt_block, 0);
        memcpy (pkt_start, ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        pkt_block_update_new_hdr_type(pkt_block, ETHERNET_HEADER);

		dp_pkt_entry_point(dp_ctx, recv_intf->vrf,
                    recv_intf, 
                    pkt_block);

        pkt_block_dereference(pkt_block);
        free (ev_dis_pkt_data->pkt);
		free (ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
	}
}

int
dp_submit_packet (dp_ctx_t *dp_ctx,
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
	ev_dis_pkt_data->pkt = (unsigned char *)XCALLOC_BUFF(0, pkt_size);
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

    if (!ev_dis_pkt_data) return;
    
    for (; ev_dis_pkt_data;
         ev_dis_pkt_data = (ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size))
    {
        dp_intf = dp_look_up_interface(dp_ctx->dp_intf_ht, ev_dis_pkt_data->ifindex);
        pkt_block = (pkt_block_t *)ev_dis_pkt_data->pkt;

        if (!dp_intf)
        {
            pkt_block_dereference(pkt_block);
            free(ev_dis_pkt_data);
            continue;
        }
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

/*================== LinuxInterface ========================*/

/*  Start a single thread which will listen on all interfaces for the 
    Raw packet in infinite loop. Use select ( ) to multiplex on all interface
    sockets. When pkt is recvd successfully, create a new pkt_block
    structure and post the packet using dp_pkt_entry_point( ) */

static bool listener_running = false;
static pthread_t listener_thread;
static char buffer[2048];

static void* 
linux_listener_thread(void* arg) {

    int sock_fd;
    int max_fd = 0;
    fd_set read_fds;
    dp_intf_t *dp_intf;
    struct hashtable_itr *itr;
    pkt_block_t *pkt_block;

    dp_ctx_t *dp_ctx = (dp_ctx_t *)arg;
    hashtable_t *dp_intf_ht = dp_ctx->dp_intf_ht;
    
    if (!dp_intf_ht->entrycount) return NULL;

    while (listener_running) {

        FD_ZERO(&read_fds);

        max_fd = 0;
        itr = hashtable_iterator(dp_intf_ht);
        
        while (1) {
            
            dp_intf = (dp_intf_t *)hashtable_iterator_value(itr);
            sock_fd = dp_intf->LinuxRtr_sockfd;

            if (sock_fd > 0) {

                FD_SET(sock_fd , &read_fds);
                if (sock_fd > max_fd) max_fd = sock_fd;
            }
            if (!hashtable_iterator_advance(itr)) break;
        }
        free (itr);
        
        select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        itr = hashtable_iterator(dp_intf_ht);

        while (1) {
            
            dp_intf = (dp_intf_t *)hashtable_iterator_value(itr);

            sock_fd = dp_intf->LinuxRtr_sockfd;

            if (sock_fd > 0 && FD_ISSET(sock_fd, &read_fds)) {
                
                struct sockaddr_ll from_addr;
                socklen_t from_len = sizeof(from_addr);

                ssize_t bytes_received = recvfrom(sock_fd, 
                        buffer,
                        sizeof(buffer), 0,
                        (struct sockaddr*)&from_addr, &from_len);
                
                if (bytes_received <= 0) {

                    if (!hashtable_iterator_advance(itr)) break;
                    continue;
                }
                
                pkt_block = pkt_block_get_new(NULL, 0);
                pkt_block_set_new_pkt(pkt_block, (uint8_t *)buffer, bytes_received);
                pkt_block_update_new_hdr_type (pkt_block, ETHERNET_HEADER);
                dp_submit_packet (dp_ctx, pkt_block, dp_intf); 
                XFREE(pkt_block);
            }

            if (!hashtable_iterator_advance(itr)) break;
        }
        free (itr);
    }

    return NULL;
}

void
Linux_listen_interfaces (dp_ctx_t *dp_ctx) {
    
    dp_intf_t *dp_intf;
    struct hashtable_itr *itr;

    hashtable_t *dp_intf_ht = dp_ctx->dp_intf_ht;

    if (listener_running) {
        return;
    }

    if (!dp_intf_ht->entrycount) return;

    itr = hashtable_iterator(dp_intf_ht);

    while(1) {

        dp_intf = (dp_intf_t *)hashtable_iterator_value(itr);

        if (dp_intf->if_type != DP_INTF_TYPE_PHY) {
            if (!hashtable_iterator_advance(itr)) break;
            continue;
        }

        dp_intf->LinuxRtr_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = dp_intf->port_id;
        
        if (bind(dp_intf->LinuxRtr_sockfd, 
                (struct sockaddr*)&sll, sizeof(sll)) < 0) {

            cprintf ("%s : Error : Failed to bind socket : "
                     "if-name : %s , errno : %s\n", 
                      __FUNCTION__, dp_intf->if_name, strerror(errno));
            close(dp_intf->LinuxRtr_sockfd);
            dp_intf->LinuxRtr_sockfd = 0;
            if (!hashtable_iterator_advance(itr)) break;
            continue;
        }
        
        if (!hashtable_iterator_advance(itr)) break;
    }
    
    free(itr);
    listener_running = true;

    if (listener_running) {
        pthread_create(&listener_thread, 
                       NULL, 
                       linux_listener_thread, dp_ctx);
    }
}
