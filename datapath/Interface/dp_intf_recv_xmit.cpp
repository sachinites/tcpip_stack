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
#include <dirent.h>
#include <assert.h>
#include <poll.h>

#include "../../libs/pkt-block/pkt_mbuf.h"
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
#include "../../libs/Tracer/tracer.h"
#include "../../libs/common/l2_hdrs.h"
#include "../../libs/common/l3_hdrs.h"

// Firewall Lib
#include "../../FireWall/acl/acldb.h"

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "dp_intf.h"
#include "dp_intf_log.h"
#include "dp_intf_store.h"
#include "../Vrfs/dp_vrf.h"

#include "../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../Layer3/layer3.h"
#include "../Layer2/vxlan/vxlan_dp.h"

#include "../dp_ctx.h"
#include "../dp_utils.h"
#include "../dp_uapi.h"
#include "../dp_ctrl.h"
#include "../Layer3/Gre/gre-fwd.h"
#include "../Layer3/SRv6/srv6-endpoint.h"
#include "../Layer2/switching/mac_table.h"

typedef int (*SendPacketOut_fptr)(
            dp_ctx_t *, 
            dp_intf_t *, struct rte_mbuf *);

extern bool LinuxRtr;
extern int cprintf (const char* format, ...);

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      struct rte_mbuf *mbuf);

static int
linux_send_xmit_out (dp_intf_t *dp_intf, struct rte_mbuf *mbuf) {

    pkt_size_t pkt_size;

    assert (LinuxRtr);
        
    int sockfd = dp_intf->LinuxRtr_sockfd;

    if (sockfd < 0) {

        cprintf ("%s : Error : Failed to create raw socket for Intf %s: errno : %d\n",
            dp_intf->if_name, strerror(errno));

        return -1;
    }

    char *pkt = (char *)pkt_mbuf_get_pkt (mbuf, &pkt_size);

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

static int 
dpdk_send_xmit_out(dp_intf_t *dp_intf, struct rte_mbuf *mbuf) {

    int rc = 0;
    assert (pkt_mbuf_get_starting_hdr (mbuf) == ETHERNET_HEADER);

    #ifdef USE_DPDK
    rc = rte_eth_tx_burst(dp_intf_get_dpdk_port_id(dp_intf),
                     (dp_intf->dpdk_tx_queue_lb) % dp_intf->dpdk_max_tx_queues,
                     &mbuf, 1);
    #endif
    dp_intf->dpdk_tx_queue_lb++;
    dp_intf->dpdk_tx_queue_lb = (dp_intf->dpdk_tx_queue_lb % dp_intf->dpdk_max_tx_queues);
    dp_intf->pkt_sent++;
    
    return rc;
}


/* Helper APIs */

static int
send_xmit_out (dp_intf_t *intf, struct rte_mbuf *mbuf)
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

    if (pkt_mbuf_get_data_size(mbuf) > MAX_PACKET_BUFFER_SIZE)
    {
        cprintf("Error : DCTX : %s, Pkt Size exceeded\n", local_dp_ctx->ctx_name);
        intf->xmit_pkt_dropped++;
        return -1;
    }    

    tracer (local_dp_ctx->dptr, DFLOW_DET, 
        "Pkt : %s Wired out of interface %s\n", 
        pkt_mbuf_str (mbuf), intf->if_name);

    if (LinuxRtr) {

        #ifndef USE_DPDK
            return linux_send_xmit_out (intf, mbuf);
        #else 
            return dpdk_send_xmit_out (intf, mbuf);
        #endif
    }

    dp_ctx_t *peer_dp_ctx = intf->nbr_intf->dp_ctx;
    dp_intf_t *peer_end = intf->nbr_intf;

    uint8_t *pkt = pkt_mbuf_get_pkt(mbuf, &pkt_size);

    ev_dis_pkt_data = (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

    ev_dis_pkt_data->ifindex = peer_end->port_id;
    ev_dis_pkt_data->pkt = (unsigned char *)XCALLOC_BUFF(0, pkt_size);
    memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
    ev_dis_pkt_data->pkt_size = pkt_size;

    tcp_dump_send_logger(local_dp_ctx, intf,
                         mbuf, pkt_mbuf_get_starting_hdr(mbuf));

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
SendPacketOutSwitchport(dp_ctx_t *dp_ctx, dp_intf_t *Intf, struct rte_mbuf *mbuf)
{

    pkt_size_t pkt_size;

    DP_IntfL2Mode intf_l2_mode = Intf->l2_mode;

    if (intf_l2_mode == DP_LAN_MODE_NONE)
    {
        return 0;
    }

    ethernet_hdr_t *ethernet_hdr =
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

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
            return send_xmit_out(Intf, mbuf);
        }

        /*Case 2 : if oif is VLAN aware, but pkt is untagged, simply
         drop the packet. This is not an error, it is a L2 switching
         behavior*/
        if (intf_vlan_id && !vlan_8021q_hdr)
        {
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Access port %s dropped outgoing untagged packet\n", 
                pkt_mbuf_str(mbuf), Intf->if_name);
            return 0;
        }

        /*Case 3 : If oif is VLAN AWARE, and pkt is also tagged,
          forward the frame only if vlan IDs matches after untagging
          the frame*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id == GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {
            untag_pkt_with_vlan_id(mbuf);
            return send_xmit_out(Intf, mbuf);
        }

        /* case 4 : if vlan id in pkt do not matches with the vlan id of
            the interface*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id != GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Access port dropped %s outgoing tagged packet with mismatched vlan id\n", 
                pkt_mbuf_str(mbuf), Intf->if_name);
            return 0;
        }

        /*case 5 : if oif is vlan unaware but pkt is vlan tagged,
         simply drop the packet.*/
        if (!intf_vlan_id && vlan_8021q_hdr)
        {
            tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
                "Pkt %s Dropped : Reason : Vlan unaware Access port %s dropped outgoing tagged packet\n", 
                pkt_mbuf_str(mbuf), Intf->if_name);
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
            return send_xmit_out(Intf, mbuf);
        }

        tracer(dp_ctx->dptr, DL2SW_DET | DERR, 
            "Pkt %s Dropped : Reason : Trunk port %s dropped outgoing packet\n", 
            pkt_mbuf_str(mbuf), Intf->if_name);

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
                                  struct rte_mbuf *mbuf,
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
             send_xmit_out(member_port, mbuf);
        else if (!only_trunk_ports && (member_port->l2_mode == DP_LAN_ACCESS_MODE))
             send_xmit_out(member_port, mbuf);
    }
}

static void
dp_VlanPacketFlood (dp_intf_t *vlan_intf, 
                    struct rte_mbuf *mbuf, 
                    dp_intf_t *exempt_intf) {

    int i;
    dp_intf_t *member_port;

    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);

    if (is_pkt_vlan_tagged (eth_hdr)) {

        vlan_send_pkt_out_all_trunk_ports (vlan_intf, mbuf, exempt_intf, true);
        untag_pkt_with_vlan_id(mbuf);
        vlan_send_pkt_out_all_trunk_ports (vlan_intf, mbuf, exempt_intf, false);
    }
    else {

        vlan_send_pkt_out_all_trunk_ports (vlan_intf, mbuf, exempt_intf, false);
        tag_pkt_with_vlan_id(mbuf, vlan_intf->vlan_id);
        vlan_send_pkt_out_all_trunk_ports (vlan_intf, mbuf, exempt_intf, true);
    }
}

static int 
PhysicalInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    if (intf->switchport)
    {
        return SendPacketOutSwitchport(dp_ctx, intf, mbuf);
    }
    else
    {
        return send_xmit_out(intf, mbuf);
    }
}

static int 
VlanInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    dp_VlanPacketFlood (intf, mbuf, NULL);    
    return 0;
}

static int 
GRETunnelInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    pkt_size_t pkt_size;
    bool no_modify = false;
    struct rte_mbuf *mbuf_copy;
    cmn_prefix_t src_ip, dst_ip;

    if (!intf->is_up) { return 0; }
    
    bool pkt_no_modify = pkt_mbuf_get_no_modify_value(mbuf);
    
    if (pkt_no_modify) {
        no_modify = pkt_no_modify;
        mbuf_copy = PKT_MBUF_DUP(mbuf);
        mbuf = mbuf_copy;
    }

    cmn_prefix_initialize_v4(&src_ip, intf->gre_tunnel_src_ip, 32);
    cmn_prefix_initialize_v4(&dst_ip, intf->gre_tunnel_dst_ip, 32);
    gre_encasulate (mbuf, &src_ip, &dst_ip);
    
    dp_send_ip_data (dp_ctx, intf->vrf, mbuf);

    intf->pkt_sent++;
    pkt_mbuf_get_pkt (mbuf, &pkt_size);

    if (no_modify) {
        pkt_mbuf_dereference(mbuf);
    }

    return pkt_size;
}


static int 
VirtualPort_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    pkt_size_t pkt_size;

    if (!intf->olay_tunnel_intf || !intf->is_up) {
        intf->xmit_pkt_dropped++;
        return 0;
    }
    
    assert (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER);

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    assert (vlan_8021q_hdr );

    /* If vport is in trunk mode, then check if vlan id is part of trunk*/
    if (!dp_is_vlan_member (intf->vlan_bitmap, (
        GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))) return 0;

    intf->pkt_sent++;

    dp_send_pkt_out(dp_ctx, intf->olay_tunnel_intf, mbuf);
    return 0;
}

static int 
RmacInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    pkt_size_t pkt_size;
    vlan_8021q_hdr_t *vlan_8021q_hdr = NULL;

    assert(pkt_mbuf_verify_pkt(mbuf, ETHERNET_HEADER));

    ethernet_hdr_t *eth_hdr = 
        ( ethernet_hdr_t  *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    /* Rmac interface never recvs untagged pkt */
    assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (eth_hdr)));

    /* Case 1 : If this is ARP Broadcast pkt requesting IP for Rmac interface*/
    /* Case 2 : If this is ARP reply packet recvd by Rmac Interface */

    tracer (dp_ctx->dptr, DL2FWD , 
        "Rmac Interface %s : Recvd pkt %s with vlan tag : %d\n", 
        intf->if_name, pkt_mbuf_str(mbuf), TCI_VID(vlan_8021q_hdr->tci));
    
    if ( is_arp_pkt_for_svi_interface (dp_ctx, mbuf) ) {

        tracer (dp_ctx->dptr, DL2FWD , 
                "Rmac Interface %s : ARP pkt %s Intercepted by SVI interface\n", 
                intf->if_name, pkt_mbuf_str(mbuf));

        svi_interface_intercept_arp_pkt (dp_ctx, intf->vrf, mbuf);
        return 0;
    }

    /* Case 3 : if this is any other ethernet pkt with dst mac = RMAC address */

    if (!mac_address_compare ((unsigned char *)dp_ctx->rmac.mac, 
          (unsigned char *)eth_hdr->dst_mac.mac) != 0) {

        intf->recvd_pkt_dropped++;
        return 0;
    }

    untag_pkt_with_vlan_id(mbuf);
    eth_hdr = ( ethernet_hdr_t  *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    assert (eth_hdr->type == htons (ETH_TYPE_IPv4));
    pkt_mbuf_slide(mbuf, -1, 1, sizeof (ethernet_hdr_t));
    pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
    pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IP_IN_IP);
    dp_promote_pkt_to_layer3 (dp_ctx, intf->vrf, intf, mbuf);

    return 0;
}

static int 
LoopbackInterface_SendPacketOut(dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){
    
    /* black hole the pkt */
    return 0;
}

static int 
NVEInterface_SendPacketOut (dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf){

    pkt_size_t pkt_size;
    pkt_mbuf_pvt_data_t *pvt_data;
    unsigned char ipv4_addr_str1[IPV4_ADDR_LEN_STR] = {0};
    unsigned char ipv4_addr_str2[IPV4_ADDR_LEN_STR] = {0};
    
    if (!intf->is_up) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VxLAN Encapsulation : Error : NVE Interface %s is down\n", intf->if_name);
        intf->xmit_pkt_dropped++;
        return -1;
    }

    pvt_data = pkt_mbuf_get_pvt_data(mbuf);

    if (!pvt_data->encap_data) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VxLAN Encapsulation : Error : Pkt Block has no encap data\n");
        intf->xmit_pkt_dropped++;
        return -1;
    }

    vxlan_encapsulate (dp_ctx, mbuf);

 /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_mbuf_expand_buffer_left (mbuf, sizeof (ip_hdr_t)));
    pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
    ip_hdr_t *ip_hdr = (ip_hdr_t *) pkt_mbuf_get_pkt(mbuf, &pkt_size);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = htonl(dp_ctx->rtr_id);
    ip_hdr->dst_ip = htonl(pvt_data->encap_data->u.vxlan.remote_vtep_ip);
    ip_hdr->protocol = IP_PROTO_UDP;
    ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : Outer IP Hdr Header Attached with Src : %s, Dst %s, Proto = %x\n",
        tcp_ip_covert_ip_n_to_p ( ntohl(ip_hdr->src_ip), ipv4_addr_str1),
        tcp_ip_covert_ip_n_to_p ( ntohl(ip_hdr->dst_ip), ipv4_addr_str2),
        ip_hdr->protocol );

    dp_send_ip_data (dp_ctx, intf->vrf, mbuf);
    intf->pkt_sent++;
    return 0;    
}

static int 
VlanFloodInterface_SendPacketOut(
                                    dp_ctx_t *dp_ctx, 
                                    dp_intf_t *vfif_intf, 
                                    struct rte_mbuf *mbuf) {

    dp_intf_t *exempt_intf = pkt_mbuf_get_ingress_intf(mbuf);

    assert (exempt_intf);

    assert (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER);

    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);
    assert (vlan_8021q_hdr);
    uint16_t vlan_id = (uint16_t)TCI_VID(vlan_8021q_hdr->tci);

    dp_intf_t *vlan_intf  = exempt_intf->l2_mode == DP_LAN_ACCESS_MODE ?
                    exempt_intf->vlan_intf : \
                    dp_look_up_interface_by_vlan_id (dp_ctx->dp_vlan_intf_ht, vlan_id);

    if (!vlan_intf) return -1;

    dp_VlanPacketFlood (vlan_intf, mbuf, exempt_intf);
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
        struct rte_mbuf *mbuf){

    pkt_size_t pkt_size;

    /* Step 1: Strip outer ethernet header if the data layer included it */
    if (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER) {
        uint8_t *pkt = pkt_mbuf_get_pkt(mbuf, &pkt_size);
        ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
        uint16_t eth_hdr_size = is_pkt_vlan_tagged(eth_hdr)
            ? (uint16_t)sizeof(vlan_ethernet_hdr_t)
            : (uint16_t)sizeof(ethernet_hdr_t);
        pkt_mbuf_slide(mbuf, -1, 1, eth_hdr_size);
        pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
        pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IPv6);
    }

    /* Step 2: Decapsulate: strip the outer IPv6 header and SRH */
    Srv6_decapsulate(mbuf);

    /* Step 3: Inner payload must be IPv4; drop anything else */
    if (pkt_mbuf_get_starting_hdr(mbuf) != IP_PROTO_IP_IN_IP) {
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
    layer3_ip_route_pkt(dp_ctx, steered_vrf, NULL, mbuf);
    intf->pkt_sent++;
    
    return 0;
}

/* This interface is used to steer the MPLS traffic from Default VRF 
    ( ISP Core Side ) to Customer VRF 
    The packet recvd must have already popped out all MPLS Labels and
    top hde of the packet would be IP HDR ( but dont expect )    
    pkt_mbuf_get_starting_hdr () Would return IP_PROTO_IP_IN_IP, because
    we are inferring the top of the pkt SHOULD be IP HDR based on MPLS
    label context ( we land here from LFIB ).

    Algorithm : 
    Route the packet in Customer VRF (intf->steered_vpnv4_vrf)
*/
static int 
VPNv4_XConnect_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf){

    char ip_addr_str[IPV4_ADDR_LEN_STR];

    pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IP_IN_IP);
    assert (intf->port_id == VPNV4_INTF_STEER_IFINDEX);
    
    tracer (dp_ctx->dptr, DL3FWD, 
        "VRF:%s: Dest : %s :  Pkt Context Switched from Def-vrf to VPN VRF\n",
	    intf->steered_vpnv4_vrf->vrf_name,
        pkt_mbuf_ip(mbuf, ip_addr_str));

    layer3_ip_route_pkt(dp_ctx, intf->steered_vpnv4_vrf, NULL, mbuf);
    return 0;
}

extern int 
AC_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf);

extern int 
BD_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf);

extern int 
BD_FloodPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf);


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
        VPNv4_XConnect_SendPacketOut,
        AC_SendPacketOut,
        BD_SendPacketOut,
        BD_FloodPacketOut,
        0,
        0
    };

void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, struct rte_mbuf *mbuf) {

    if (intf->l3_acl_egress) {

        if (access_list_evaluate_mbuf (
            intf->l3_acl_egress.load(std::memory_order_acquire), mbuf) != ACL_PERMIT) 
        {
            tracer(dp_ctx->dptr, DL3FWD_DET,
                "Egress L3 ACL Denied on intf %s, Pkt %s Dropped\n", 
                intf->if_name, pkt_mbuf_str(mbuf));

            return;
        }

    }

    tracer(dp_ctx->dptr, DL3FWD_DET | DL2FWD_DET | DL2SW_DET,
        "Sending out frame %s out of interface %s\n", 
        pkt_mbuf_str(mbuf), intf->if_name);

    (intf_xmit_cbk[intf->if_type])(dp_ctx, intf, mbuf);
}

/* -------------------------------------------------- */

/* Pkt Reception APIs */

void 
dp_pkt_entry_point(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
                    dp_intf_t *interface,
                    struct rte_mbuf *mbuf)
{

    vlan_id_t vlan_id_to_tag = 0;
  
    if (!interface->is_up){
        return;
    }

    pkt_mbuf_set_ingress_intf(mbuf, interface);
    
    if (interface->l3_acl_ingress.load(std::memory_order_acquire)) {

        if (access_list_evaluate_mbuf (
            interface->l3_acl_ingress.load(std::memory_order_acquire), mbuf) != ACL_PERMIT) 
        {
            tracer(dp_ctx->dptr, DL3FWD_DET,
                "Ingress L3 ACL Denied on intf %s, Pkt %s Dropped\n", 
                interface->if_name, pkt_mbuf_str(mbuf));

            return;
        }

    }

    interface->pkt_recv++;
    tcp_dump_recv_logger(dp_ctx, interface, mbuf, ETHERNET_HEADER);

    if (l2_frame_recv_qualify_on_interface(dp_ctx,
                                          vrf,
                                          interface, 
                                          mbuf,
                                          &vlan_id_to_tag) == false){
        
        cprintf("Error : L2 Frame Rejected on node %s(%s)\n", 
            dp_ctx->ctx_name, interface->if_name);
            
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : L2 Frame Rejected in Interface %s, qualification Test Failed\n", 
            pkt_mbuf_str(mbuf), interface->if_name);

        return;
    }

    if ((interface->switchport &&
            interface->l2_mode != DP_LAN_MODE_NONE)) {

        if (vlan_id_to_tag) {
           
            tag_pkt_with_vlan_id (mbuf, vlan_id_to_tag);
            tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Tagged with VLAN ID %d\n", 
                pkt_mbuf_str(mbuf), vlan_id_to_tag);
        }

        if (vlan_id_to_tag == 0) {

            /* We did not tag the pkt because pkt was already tagged.*/
            vlan_8021q_hdr_t *vlan_8021q_hdr;

            assert ((vlan_8021q_hdr = 
                is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL))));

            vlan_id_to_tag = (vlan_id_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        }

        l2_switch_recv_frame(dp_ctx,
                    vlan_id_to_tag,
                    interface, mbuf);
    }

    /* If packet is Recvd on GRE interface and pkt is vlan tagged, 
        it means GRE is being used for VLAN extension */
    else if (interface->if_type == DP_INTF_TYPE_GRE_TUNNEL &&
                pkt_mbuf_verify_pkt (mbuf, ETHERNET_HEADER) &&
                is_pkt_vlan_tagged (pkt_mbuf_get_ethernet_hdr(mbuf))) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Being recieved on GRE Interface %s\n", 
            pkt_mbuf_str(mbuf), interface->if_name);  

        dp_pkt_entry_point (dp_ctx, interface->virtual_port->vrf,
                            interface->virtual_port, 
                            mbuf);
    }

    else if (interface->ip_addr){

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
            "Pkt : %s : Recvd on L3 Interface %s, being protmoted to L3Fwding\n", 
            pkt_mbuf_str(mbuf), interface->if_name);
            
        promote_pkt_to_layer2(dp_ctx, interface->vrf, interface, mbuf);
    }

    else {
        /* We dont know what to do with the pkt*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : pkt dropped, Unknown pkt recvd on Interface %s\n", 
            pkt_mbuf_str(mbuf), interface->if_name);
        interface->recvd_pkt_dropped++;
    }
}

/* This fn is a data path thread which is NON DPDK (share same CPU as control
    plane.)*/
extern void
dp_pkt_recvr_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    dp_ctx_t *dp_ctx;
    uint8_t *pkt_start;
    struct rte_mbuf *mbuf;
	dp_intf_t *recv_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

    dp_ctx = (dp_ctx_t *)(ev_dis->app_data);

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

        recv_intf = dp_ctx->intf_table[ev_dis_pkt_data->ifindex];
        assert(recv_intf);

		pkt_start = (uint8_t *)ev_dis_pkt_data->pkt;		

        /* Socket lift the packet without Ethernet FCS. To compensate, pretend
            that we have FCS in the end of ethernet pkt*/
        mbuf = PKT_MBUF_WRAP(
                    dp_ctx->mbuf_pools[0], /* default Mem-pool as it is Non DPDK mode flow */
                    pkt_start,
                    ev_dis_pkt_data->pkt_size + (LinuxRtr ? ETH_FCS_SIZE : 0));
    
        pkt_mbuf_update_new_hdr_type(mbuf, ETHERNET_HEADER);

		dp_pkt_entry_point(dp_ctx, recv_intf->vrf,
                    recv_intf, 
                    mbuf);

        pkt_mbuf_dereference(mbuf);
        XFREE (ev_dis_pkt_data->pkt);
		XFREE (ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
	}
}

int
send_pkt_flood(dp_ctx_t *dp_ctx, 
               dp_intf_t *exempted_intf, 
               struct rte_mbuf *mbuf) {

    dp_intf_t *intf; 

    DP_FOR_ALL_INTF(dp_ctx, intf) {

        if (intf == exempted_intf) {
            continue;
        }
        dp_send_pkt_out(dp_ctx, intf, mbuf);

    } DP_FOR_ALL_INTF_END;
    
    return 0;
}

void dp_pkt_xmit_intf_job_cbk(event_dispatcher_t *ev_dis,
                              void *pkt, uint32_t pkt_size)
{

    dp_intf_t *dp_intf;
    struct rte_mbuf *mbuf;

    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    ev_dis_pkt_data_t *ev_dis_pkt_data =
        (ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

    if (!ev_dis_pkt_data) return;
    
    for (; ev_dis_pkt_data;
         ev_dis_pkt_data = (ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size))
    {
        dp_intf = dp_ctx->intf_table[ev_dis_pkt_data->ifindex];
        mbuf = (struct rte_mbuf *)ev_dis_pkt_data->pkt;

        if (!dp_intf)
        {
            pkt_mbuf_dereference(mbuf);
            free(ev_dis_pkt_data);
            continue;
        }
        dp_send_pkt_out(dp_ctx, dp_intf, mbuf);
        pkt_mbuf_dereference(mbuf);
        free(ev_dis_pkt_data);
    }
}

void 
dp_uapi_xmit_pkt(dp_ctx_t *dp_ctx, uint32_t ifindex, struct rte_mbuf *mbuf) {

    ev_dis_pkt_data_t *ev_dis_pkt_data = (ev_dis_pkt_data_t *)
        calloc(1, sizeof(ev_dis_pkt_data_t));

    ev_dis_pkt_data->ifindex = ifindex;

    ev_dis_pkt_data->pkt = (unsigned char *)mbuf;

    pkt_mbuf_ref_inc(mbuf);

    pkt_q_enqueue(EV_DP(dp_ctx),
                  &dp_ctx->cp_to_dp_xmit_intf_pkt_q,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
}

/*================== LinuxInterface ========================*/

/*  Start a single thread which will listen on all interfaces for the 
    Raw packet in infinite loop. Use select ( ) to multiplex on all interface
    sockets. When pkt is recvd successfully, create a new mbuf
    structure and post the packet using dp_pkt_entry_point( ) */

static bool listener_running = false;
static pthread_t listener_thread;
static char buffer[2048];

static void* 
linux_listener_thread(void* arg) {

    int sock_fd;
    int nfds;
    int poll_idx;
    dp_intf_t *dp_intf;
    struct rte_mbuf *mbuf;
    ev_dis_pkt_data_t *ev_dis_pkt_data;
    struct pollfd pollfds[DP_MAX_INTF];
    dp_intf_t *poll_intfs[DP_MAX_INTF];

    dp_ctx_t *dp_ctx = (dp_ctx_t *)arg;

    /* Early exit if no interfaces are registered */
    bool has_intf = false;
    for (int _i = 0; _i < DP_MAX_INTF && !has_intf; _i++) {
        if (dp_ctx->intf_table[_i]) has_intf = true;
    }
    if (!has_intf) return NULL;

    while (listener_running) {

        nfds = 0;

        for (int _i = 0; _i < DP_MAX_INTF; _i++) {
            dp_intf = dp_ctx->intf_table[_i];
            if (!dp_intf) continue;
            sock_fd = dp_intf->LinuxRtr_sockfd;
            if (sock_fd <= 0) continue;

            pollfds[nfds].fd = sock_fd;
            pollfds[nfds].events = POLLIN;
            pollfds[nfds].revents = 0;
            poll_intfs[nfds] = dp_intf;
            nfds++;
        }

        if (!nfds) {
            usleep(100000);
            continue;
        }

        if (poll(pollfds, nfds, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (poll_idx = 0; poll_idx < nfds; poll_idx++) {

            if (!(pollfds[poll_idx].revents & POLLIN))
                continue;

            dp_intf = poll_intfs[poll_idx];
            sock_fd = pollfds[poll_idx].fd;

                struct sockaddr_ll from_addr;
                socklen_t from_len = sizeof(from_addr);

                ssize_t bytes_received = recvfrom(sock_fd,
                        buffer,
                        sizeof(buffer), 0,
                        (struct sockaddr*)&from_addr, &from_len);

                if (bytes_received <= 0) continue;

                ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC2(0, 1, ev_dis_pkt_data_t);
                ev_dis_pkt_data->ifindex = dp_intf->port_id;
                ev_dis_pkt_data->pkt = (unsigned char *)XCALLOC_BUFF(0, bytes_received);
                memcpy(ev_dis_pkt_data->pkt, buffer, bytes_received);
                ev_dis_pkt_data->pkt_size = bytes_received;

                pkt_q_enqueue(EV_DP(dp_ctx),
                              DP_PKT_Q(dp_ctx),
                              (char *)ev_dis_pkt_data,
                              sizeof(ev_dis_pkt_data_t));
        }
    }

    return NULL;
}

void
Linux_listen_interfaces (dp_ctx_t *dp_ctx) {
    
    dp_intf_t *dp_intf;

    if (listener_running) {
        return;
    }

    for (int _i = 0; _i < DP_MAX_INTF; _i++) {

        dp_intf = dp_ctx->intf_table[_i];
        if (!dp_intf) continue;

        if (dp_intf->if_type != DP_INTF_TYPE_PHY) continue;

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
        }
    }

    listener_running = true;

    if (listener_running) {
        pthread_create(&listener_thread, 
                       NULL, 
                       linux_listener_thread, dp_ctx);
    }
}

/* ================== DPDK CPU port mapping ========================*/
/* 
#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u"
#define CORE_ID_FILE "topology/core_id"
#define NUMA_NODE_PATH "/sys/devices/system/node"

CPU 2 exist if below path exist:
/sys/devices/system/cpu/cpu2/topology/core_id

CPU2 is present on socket 1 if below path exist :
/sys/devices/system/node/node1/cpu2

Numa Node 

/sys/devices/system/node/node0
/sys/devices/system/node/node1
/sys/devices/system/node/node2
etc ...

*/

#define MAX_CPUS_PER_NUMA   64
#define MAX_PORTS_PER_CPU   16

uint8_t 
system_get_max_numa_node_count () {

    DIR *dir;
    struct dirent *entry;
    uint8_t max_numa_node_id = 0;

    dir = opendir("/sys/devices/system/node");

    if (dir != NULL) {

        while ((entry = readdir(dir)) != NULL) {

            // Look for entries of the form nodeX where X is a number
            if (strncmp(entry->d_name, "node", 4) == 0) {

                char *endptr;
                long node_num = strtol(entry->d_name + 4, &endptr, 10);

                if (*endptr == '\0' && node_num >= 0) {
                    if ((uint16_t)node_num > max_numa_node_id)
                        max_numa_node_id = (uint16_t)node_num;
                }
            }
        }

        closedir(dir);
    }

    return max_numa_node_id + 1;
}

static uint8_t
system_get_cpus_per_numa_nodes(uint8_t numa_node_id, 
                               uint8_t *cpu_array) {

    DIR *dir;
    struct dirent *entry;
    uint8_t cpu_count = 0;
    char path[256];

    snprintf(path, sizeof(path),
             "/sys/devices/system/node/node%u", numa_node_id);

    dir = opendir(path);

    if (dir == NULL) return 0;

    while ((entry = readdir(dir)) != NULL) {

        if (strncmp(entry->d_name, "cpu", 3) == 0) {

            char *endptr;
            long cpu_id = strtol(entry->d_name + 3, &endptr, 10);

            if (*endptr == '\0' && cpu_id >= 0) {

                if (cpu_count < MAX_CPUS_PER_NUMA) {
                    cpu_array[cpu_count] = (uint8_t)cpu_id;
                    cpu_count++;
                }
            }
        }
    }

    closedir(dir);
    return cpu_count;
}

static uint8_t 
system_port_get_numa_node(uint32_t port_id) {

    int socket_id = rte_eth_dev_socket_id((uint16_t)port_id);

    /* rte_eth_dev_socket_id() returns -1 (SOCKET_ID_ANY) when
       NUMA info is unavailable (e.g. single-socket machines).
       Fall back to NUMA node 0 in that case. */
    if (socket_id < 0) return 0;

    return (uint8_t)socket_id;
}

typedef struct cpu_port_map_ {

    uint8_t  cpu_id;
    uint8_t  numa_node_id;
    uint16_t port_ids[MAX_PORTS_PER_CPU];
    uint8_t  port_count;

} cpu_port_map_t;

typedef struct numa_cpu_info_ {

    uint8_t cpu_ids[MAX_CPUS_PER_NUMA];
    uint8_t cpu_count;

} numa_cpu_info_t;

/*
 * Build a mapping of CPU -> assigned port IDs.
 *
 * Algorithm:
 *   1. Discover NUMA topology: which CPUs sit on which NUMA node.
 *   2. Exclude core 0 (reserved for control plane) from port assignment.
 *      On a single-core machine, core 0 is kept as a fallback since there
 *      is no other core available.
 *   3. For every physical port, look up its NUMA node.
 *   4. Assign the port to the least-loaded CPU on that NUMA node
 *      (fewest ports so far), guaranteeing uniform distribution.
 *   5. Return the resulting cpu_port_map_t array (caller must free it).
 *
 * Out-params:
 *   map_count_out  – number of entries in the returned array (one per CPU
 *                    that has at least one port assigned).
 *
 * Returns NULL on allocation failure or when there are no physical ports.
 */
cpu_port_map_t *
Linux_dpdk_build_cpu_port_map(dp_ctx_t *dp_ctx, uint8_t *map_count_out) {

    *map_count_out = 0;

    /* ---- 1. Discover NUMA topology ---- */
    uint8_t numa_count = system_get_max_numa_node_count();
    if (numa_count == 0) return NULL;

    numa_cpu_info_t *numa_info =
        (numa_cpu_info_t *)calloc(numa_count, sizeof(numa_cpu_info_t));
    if (!numa_info) return NULL;

    for (uint8_t n = 0; n < numa_count; n++) {
        uint8_t cpus[MAX_CPUS_PER_NUMA];
        numa_info[n].cpu_count =
            system_get_cpus_per_numa_nodes(n, cpus);
        memcpy(numa_info[n].cpu_ids, cpus, numa_info[n].cpu_count);
    }

    /* ---- 2. Count total CPUs to size the output map ---- */
    uint16_t total_cpus = 0;
    for (uint8_t n = 0; n < numa_count; n++)
        total_cpus += numa_info[n].cpu_count;

    if (total_cpus == 0) { free(numa_info); return NULL; }

    /* Reserve core 0 for control plane unless this is a single-core machine */
    if (total_cpus > 1) {
        for (uint8_t n = 0; n < numa_count; n++) {
            numa_cpu_info_t *ni = &numa_info[n];
            for (uint8_t c = 0; c < ni->cpu_count; c++) {
                if (ni->cpu_ids[c] == 0) {
                    memmove(&ni->cpu_ids[c], &ni->cpu_ids[c + 1],
                            (ni->cpu_count - c - 1) * sizeof(ni->cpu_ids[0]));
                    ni->cpu_count--;
                    total_cpus--;
                    break;
                }
            }
        }
        if (total_cpus == 0) { free(numa_info); return NULL; }
    }

    cpu_port_map_t *map =
        (cpu_port_map_t *)calloc(total_cpus, sizeof(cpu_port_map_t));
    if (!map) { free(numa_info); return NULL; }

    /* Pre-fill CPU IDs and their NUMA node into the map */
    uint16_t idx = 0;
    for (uint8_t n = 0; n < numa_count; n++) {
        for (uint8_t c = 0; c < numa_info[n].cpu_count; c++) {
            map[idx].cpu_id = numa_info[n].cpu_ids[c];
            map[idx].numa_node_id = n;
            map[idx].port_count = 0;
            idx++;
        }
    }

    /* Build a fast cpu_id -> map index lookup (sparse, indexed by cpu_id) */
    uint8_t max_cpu_id = 0;
    for (uint16_t i = 0; i < total_cpus; i++) {
        if (map[i].cpu_id > max_cpu_id) max_cpu_id = map[i].cpu_id;
    }
    uint16_t *cpu_to_map_idx =
        (uint16_t *)calloc(max_cpu_id + 1, sizeof(uint16_t));
    if (!cpu_to_map_idx) { free(numa_info); free(map); return NULL; }
    for (uint16_t i = 0; i < total_cpus; i++)
        cpu_to_map_idx[map[i].cpu_id] = i;

    /* ---- 3. Assign each physical port to the least-loaded CPU on its NUMA node ---- */
    for (int _i = 0; _i < DP_MAX_INTF; _i++) {

        dp_intf_t *dp_intf = dp_ctx->intf_table[_i];
        if (!dp_intf) continue;

        if (dp_intf->if_type != DP_INTF_TYPE_PHY)
            continue;

        uint8_t port_numa = system_port_get_numa_node(dp_intf->port_id);
        if (port_numa >= numa_count) continue;

        numa_cpu_info_t *ni = &numa_info[port_numa];
        if (ni->cpu_count == 0) continue;

        /* Pick the CPU on this NUMA node that currently has the fewest ports */
        uint16_t best_mi = cpu_to_map_idx[ni->cpu_ids[0]];
        for (uint8_t c = 1; c < ni->cpu_count; c++) {
            uint16_t candidate = cpu_to_map_idx[ni->cpu_ids[c]];
            if (map[candidate].port_count < map[best_mi].port_count)
                best_mi = candidate;
        }

        if (map[best_mi].port_count < MAX_PORTS_PER_CPU) {
            map[best_mi].port_ids[map[best_mi].port_count] = dp_intf->port_id;
            map[best_mi].port_count++;
        }
    }
    free(cpu_to_map_idx);
    free(numa_info);

    /* ---- 4. Compact: keep only CPUs that have ports assigned ---- */
    uint8_t used = 0;
    for (uint16_t i = 0; i < total_cpus; i++) {
        if (map[i].port_count > 0) {
            if (i != used)
                map[used] = map[i];
            used++;
        }
    }

    *map_count_out = used;
    return map;  /* caller frees with free() */
}

#define BURST_SIZE 32

typedef struct datapath_pkt_entry_thread_data_ {

    uint8_t n_ports;
    dp_intf_t **ports_array;
    struct rte_mempool *mempool;

} datapath_pkt_entry_thread_data_t;

static void *
dpdk_dp_pkt_entry_thread_function(void *arg){

    uint8_t p;
    uint16_t nb_rx, i;
    dp_intf_t *dp_intf;
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth;
    
    datapath_pkt_entry_thread_data_t *th_data = 
        (datapath_pkt_entry_thread_data_t *)arg;
    
    struct rte_mbuf *bufs[BURST_SIZE];

    while (1) {

        for (p = 0; p < th_data->n_ports; p++) {

            dp_intf = th_data->ports_array[p];

            for (uint16_t q_id = 0; q_id < dp_intf->dpdk_max_rx_queues; q_id++) {

                nb_rx = rte_eth_rx_burst(
                            dp_intf->port_id - 1, 
                            q_id,
                            bufs, BURST_SIZE);
                
                if (unlikely(nb_rx == 0)) continue;

                /* Now process the Burst of packets */
                for (i = 0; i < nb_rx; i++) {
                    
                    mbuf = bufs[i];
                    /* DPDK lift the packet without Ethernet FCS. 
                    To compensate, pretend that we have FCS in the end of 
                    ethernet pkt */
                    pkt_mbuf_slide (mbuf, 1, 1, ETH_FCS_SIZE);
                    pkt_mbuf_update_new_hdr_type (mbuf, ETHERNET_HEADER);
                    dp_pkt_entry_point (dp_intf->dp_ctx, dp_intf->vrf, dp_intf, mbuf);
                    pkt_mbuf_dereference(mbuf);
                }
            }
        }
    }
}

void
DPDK_PollInterfaces(dp_ctx_t *dp_ctx) {

    dp_intf_t *dp_intf;
    cpu_set_t cpu_set;
    char thread_name[32];
    cpu_port_map_t *entry;
    uint8_t map_count = 0;
    pthread_attr_t thread_attr;
    datapath_pkt_entry_thread_data_t *th_data;

    cpu_port_map_t *map = Linux_dpdk_build_cpu_port_map(dp_ctx, &map_count);

    if (!map || map_count == 0) return;

    for (uint8_t i = 0; i < map_count; i++) {

        entry = &map[i];

        cprintf("NUMA %u : CPU %u  ->  port IDs: ",
               entry->numa_node_id, entry->cpu_id);

        for (uint8_t p = 0; p < entry->port_count; p++) {
            cprintf("%u%s", entry->port_ids[p],
                   (p + 1 < entry->port_count) ? ", " : "");
        }
        cprintf("\n");
    }

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    
    for (uint8_t i = 0; i < map_count; i++) {

        entry = &map[i];
        
        pthread_t *dp_thread = (pthread_t *)calloc (1, sizeof (pthread_t));
        CPU_ZERO(&cpu_set);
        CPU_SET(entry->cpu_id, &cpu_set);

        pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu_set);

        th_data = (datapath_pkt_entry_thread_data_t *)
                    calloc (1, sizeof (datapath_pkt_entry_thread_data_t));
        th_data->n_ports = entry->port_count;
        th_data->ports_array = (dp_intf_t **)
                    calloc (entry->port_count, sizeof (dp_intf_t *));

        for (uint8_t p = 0; p < entry->port_count; p++) {

            /* Note : map contains the exact port id which are used in data-path*/
            dp_intf = dp_ctx->intf_table[entry->port_ids[p]];
            assert(dp_intf);
            th_data->ports_array[p] = dp_intf;
        }

        th_data->mempool = dp_ctx->mbuf_pools[entry->numa_node_id];

        memset (thread_name, 0, sizeof (thread_name));
        snprintf (thread_name, sizeof (thread_name), "DPDK-C-%u", entry->cpu_id);
        pthread_create(dp_thread, &thread_attr, 
                dpdk_dp_pkt_entry_thread_function, (void *)th_data);
        pthread_setname_np(*dp_thread, (const char *)thread_name);
    }

    free(map);
}

void
DPDK_PollInterfaces_load_balancing (dp_ctx_t *dp_ctx) {

    
}

/*
 * dpdk_port_configure - Initialize and start a single DPDK-managed Ethernet port.
 *
 * Follows the standard DPDK port initialization lifecycle:
 *   1. Validate port existence
 *   2. Query hardware capabilities (max queues, offloads, etc.)
 *   3. Configure the device with the desired number of RX/TX queues
 *   4. Clamp descriptor ring sizes to hardware-supported values
 *   5. Resolve NUMA node affinity for memory allocation
 *   6. Allocate RX queues (each backed by the shared mbuf_pool)
 *   7. Allocate TX queues
 *   8. Start the device (NIC begins receiving/transmitting)
 *   9. Enable promiscuous mode so all wire traffic is visible
 *
 * @dp_intf   : datapath interface object (used for logging)
 * @port_id   : DPDK port identifier
 * @mbuf_pool : pre-allocated packet buffer pool shared across all RX queues
 */
static void 
dpdk_port_configure(dp_intf_t *dp_intf,
                    uint16_t port_id, 
                    struct rte_mempool *mbuf_pool) {

    int rc;
    uint16_t port_numa_node;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;

    cprintf ("%s: Configuring NIC:%s(%u) ...\n", 
            __FUNCTION__, dp_intf->if_name, port_id);

    /* Step 1: Sanity check — confirm port_id maps to a recognized DPDK device */
    assert (rte_eth_dev_is_valid_port(port_id));

    /* Zero-initialize configs; a zeroed port_conf selects driver defaults
       (no RSS, no offloads, no VLAN filtering) */
    memset (&port_conf, 0, sizeof(port_conf));
    memset (&dev_info, 0, sizeof(dev_info));

    /* Step 2: Query NIC/driver capabilities — we need max_rx_queues and
       max_tx_queues to know how many queues the hardware supports */
    rte_eth_dev_info_get(port_id, &dev_info);

    /* Step 3: Device-level configuration. Tells the driver how many RX/TX
       queues to allocate (we request the hardware maximum) and applies
       the global port settings from port_conf. Must be called before any
       queue setup. Transitions port state: UNUSED -> CONFIGURED */
    rc = rte_eth_dev_configure(port_id, 
                            dev_info.max_rx_queues, 
                            dev_info.max_tx_queues, &port_conf);
    assert (!rc);

    dp_intf->dpdk_max_rx_queues = dev_info.max_rx_queues;
    dp_intf->dpdk_max_tx_queues = dev_info.max_tx_queues;

    /* Step 4: The requested ring sizes (RX_RING_SIZE / TX_RING_SIZE) may
       not be exactly supported by the hardware. This call clamps nb_rxd
       and nb_txd to the nearest valid values the driver accepts */
    rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    assert(!rc);
    cprintf ("Intf : %s, Rx Ring Size : %u, Tx Ring Size : %u\n", 
        dp_intf->if_name, nb_rxd, nb_txd);

    /* Step 5: Determine NUMA node the NIC is attached to. Allocating ring
       buffers on the same NUMA node avoids expensive cross-socket memory
       access. Falls back to node 0 if the socket cannot be determined */
    int socket_id = rte_eth_dev_socket_id(port_id);
    port_numa_node = socket_id < 0 ? 0 : socket_id;

    /* Step 6: Set up all RX queues. Each queue gets a descriptor ring of
       nb_rxd entries on the port's NUMA node. The mbuf_pool supplies
       packet buffers where the NIC will DMA incoming frames */
    for (int i = 0; i < dev_info.max_rx_queues; i++)
    {
        rc = rte_eth_rx_queue_setup(port_id, i, nb_rxd,
                                    port_numa_node, 
                                    NULL, mbuf_pool);
        assert(!rc);
    }

    /* Step 7: Set up all TX queues. Same NUMA-aware allocation, but no
       mbuf_pool is needed — the application provides mbufs at send time */
    for (int i = 0; i < dev_info.max_tx_queues; i++)
    {
        rc = rte_eth_tx_queue_setup(port_id, i, nb_txd,
                                    port_numa_node, 
                                    NULL);
        assert(!rc);
    }

    /* Step 8: Start the device. Programs the hardware with all queue and
       config info from above. After this the NIC is live — it can receive
       and transmit packets. Transitions port state: CONFIGURED -> STARTED */
    rc = rte_eth_dev_start(port_id);
    assert(!rc);

    /* Step 9: Enable promiscuous mode — NIC accepts all packets on the
       wire, not just those matching its MAC address. Required for a
       TCP/IP stack that may handle traffic for multiple addresses,
       perform bridging, or need full wire visibility for debugging */
    rc = rte_eth_promiscuous_enable(port_id);
    assert(!rc);
}

void
DPDK_ConfigureInterfaces(dp_ctx_t *dp_ctx) {

    dp_intf_t *dp_intf;

    uint16_t port_cnt = 0;

    for (int _i = 0; _i < DP_MAX_INTF; _i++) {
        if (dp_ctx->intf_table[_i]) port_cnt++;
    }

    if (!port_cnt) return;

    for (int _i = 0; _i < DP_MAX_INTF; _i++) {

        dp_intf = dp_ctx->intf_table[_i];
        if (!dp_intf) continue;

        if (dp_intf->if_type != DP_INTF_TYPE_PHY) continue;

        uint16_t dpdk_port_id = dp_intf_get_dpdk_port_id(dp_intf);
        int socket_id = rte_eth_dev_socket_id(dpdk_port_id);
        uint16_t port_numa_node = socket_id < 0 ? 0 : socket_id;

        dpdk_port_configure(dp_intf, dpdk_port_id,
            dp_ctx->mbuf_pools[port_numa_node]);
    }
}
