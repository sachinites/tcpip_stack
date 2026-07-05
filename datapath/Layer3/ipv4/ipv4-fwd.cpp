
#include <assert.h>
#include <arpa/inet.h>
#include "../../../libs/Tracer/tracer.h"

#include "../../../libs/common/l3_hdrs.h"
#include "../../../libs/common/l2_hdrs.h"
#include "../../../libs/common/l4_hdrs.h"

#include "../../dp_ctx.h"
#include "../../dp_utils.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp_uapi.h"
#include "../../Interface/dp_intf.h"
#include "../../../libs/pkt-block/pkt_mbuf.h"

#include "../../FIB/fib_nh.h"
#include "../Gre/gre-fwd.h"
#include "../../Interface/dp_intf_log.h"
#include "../../Interface/dp_intf_store.h"
#include "../ping.h"

extern int cprintf (const char* format, ...) ;

extern void 
vpnv4_ingress_pe_encap_srv6 (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             struct rte_mbuf *mbuf, 
                             fib_nh_t *srv6_nh);
                             
extern void 
dp2cp_punt_pkt_to_layer4(void *_node,
                           Interface *recv_intf,
                           struct rte_mbuf *mbuf,
                           int L4_protocol_number);

extern void
dp2cp_punt_pkt_to_layer5(void *_node,
                                  uint32_t recv_intf_ifindex,
                                  struct rte_mbuf *mbuf,
                                  gen_proto_id_t hdr_code);

extern void
dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *oif,
                     struct rte_mbuf *mbuf,
                     gen_proto_id_t hdr_type);

extern void
layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface,
                      struct rte_mbuf *mbuf,
                      fib_nh_t *nh);

extern void 
vxlan_decapsulate (dp_ctx_t *dp_ctx,
                   struct rte_mbuf *mbuf, uint32_t src_vtep_ip);

extern void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf) ;

void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					struct rte_mbuf *mbuf) {

    char nh_str[48];
    int8_t nf_result;
    char *l4_hdr, *l5_hdr;
    ip_hdr_t *ip_hdr = NULL;
    uint32_t next_hop_ip= 0;
    char dest_ip_addr[IPV4_ADDR_LEN_STR];

    /* We are in L3 IP land, so starting hdr type must be IP_PROTO_IP_IN_IP */
    assert (pkt_mbuf_get_starting_hdr(mbuf) == IP_PROTO_IP_IN_IP);

    ip_hdr = (ip_hdr_t *)pkt_mbuf_get_ip_hdr(mbuf);

    tcp_ip_covert_ip_n_to_p(ntohl(ip_hdr->dst_ip), (c_string)dest_ip_addr);

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s : Trying to route ... \n", 
        vrf->vrf_name, dest_ip_addr);

        nf_result = nf_invoke_netfilter_hook(
            NF_IP_PRE_ROUTING,
            mbuf, 
            dp_ctx->ctx_pvt_data,
            interface,
            IP_PROTO_IP_IN_IP);

    switch(nf_result) {
        case NF_ACCEPT:
        break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD_DET, 
        "VRF %s: Dest : %s : Pkt Qualified L3 ACL Test\n", vrf->vrf_name, dest_ip_addr);

    /* Re-fetch ip_hdr: the NF hook above may have expanded/reallocated the
     * packet buffer, invalidating the pointer cached before the hook call. */
    ip_hdr = (ip_hdr_t *)pkt_mbuf_get_ip_hdr(mbuf);

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v4(&prefix, ntohl(ip_hdr->dst_ip), 32);
    
    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "VRF %s: Pkt : %s :  Pkt Dropped :  No L3 Route\n", 
            vrf->vrf_name, dest_ip_addr);
        return;
    }


    tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Pkt : %s : L3 Route Found\n", 
            vrf->vrf_name, dest_ip_addr);

    /* Handle Rejected/Discarded routes */
    if (IS_BIT_SET (nh->fwd_info->fwd_flags, FIB_NH_FWD_F_REJECT) ||
        IS_BIT_SET (nh->fwd_info->fwd_flags, FIB_NH_FWD_F_DISCARD)) {

        tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Pkt : %s : L3 Route found is Reject/Discard route\n",
            vrf->vrf_name, dest_ip_addr);

        /* For Reject/Discard route, we do not forward the pkt to next hop.
           Instead, we drop the pkt after optionally sending ICMP unreachable
           message back to sender in case of Reject route. */

        tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Pkt : %s : Dropping pkt as this is a Discard/Reject route\n",
            vrf->vrf_name, dest_ip_addr);
        return;
    }
    
    
    /* VPNv4 case : when vrf.inet FIB has SRv6 nexthop 
       Handover to ipv6 forwarding stack ... */

    if (IS_BIT_SET (nh->fwd_info->fwd_flags, FIB_NH_FWD_F_SRv6_FORWARD)) {

        tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Pkt : %s : L3 forwarding switched from v4 to v6 "
            "for VPNv4 case where nexthop is SRv6\n", 
            vrf->vrf_name, dest_ip_addr);

        return vpnv4_ingress_pe_encap_srv6(dp_ctx, vrf, mbuf, nh);
    }

    /*L3 route exist, 3 cases now : 
     * case 1 : pkt is destined to self(this router only)
     * case 2 : pkt is destined for host machine connected to directly attached subnet
     * case 3 : pkt is to be forwarded to next router*/

    if ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_CONNECTED) || 
        (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL))
    {
        /* case 1 and case 2 are possible here*/

        /* case 1 : local delivery:  dst ip address in pkt must exact match with
         * ip of any local interface of the router, including loopback*/

        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s : L3 Route found is local route\n",
            vrf->vrf_name, dest_ip_addr);

        if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL) {

            tracer (dp_ctx->dptr, DL3FWD, 
                "VRF %s: Pkt : %s : Pkt is for Local Delivery, IP protocol = %s\n",   
                vrf->vrf_name, dest_ip_addr, proto_id_str(ip_hdr->protocol));

            l4_hdr = (char *)INCREMENT_IPHDR(ip_hdr);
            l5_hdr = l4_hdr;

            switch(ip_hdr->protocol) {

                case IP_PROTO_ICMP:
                {
                    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)l4_hdr;

                    if (icmp_hdr->type == ICMP_ECHO_REQ) {

                        /* Build an ICMP echo reply and route it back to the sender */
                        pkt_size_t icmp_size = (pkt_size_t)
                            (pkt_mbuf_get_data_size(mbuf) - IP_HDR_LEN_IN_BYTES(ip_hdr));

                        struct rte_mbuf *reply = dp_pkt_mbuf_get_new(dp_ctx,
                                                sizeof(ip_hdr_t) + icmp_size);

                        pkt_mbuf_update_new_hdr_type(reply, IP_PROTO_IP_IN_IP);

                        ip_hdr_t *rip = (ip_hdr_t *)pkt_mbuf_get_ip_hdr(reply);
                        initialize_ip_hdr(rip);
                        rip->src_ip       = ip_hdr->dst_ip;   /* our local address */
                        rip->dst_ip       = ip_hdr->src_ip;   /* reply to the sender */
                        rip->protocol     = IP_PROTO_ICMP;
                        rip->total_length = htons((uint16_t)(sizeof(ip_hdr_t) + icmp_size));
                        rip->checksum     = ip_checksum(rip);

                        icmp_hdr_t *ricmp = (icmp_hdr_t *)INCREMENT_IPHDR(rip);
                        memcpy(ricmp, icmp_hdr, icmp_size);
                        ricmp->type     = ICMP_ECHO_REP;
                        ricmp->code     = 0;
                        ricmp->checksum = 0;
                        ricmp->checksum = icmp_checksum(ricmp, icmp_size);

                        dp_send_ip_data(dp_ctx, vrf, reply);
                        pkt_mbuf_dereference(reply);

                    } else if (icmp_hdr->type == ICMP_ECHO_REP) {

                        if (dp_ctx->active_ping_ctx) {
                            ping_echo_reply_recvd(dp_ctx->active_ping_ctx, mbuf);
                        } else {
                            cprintf("IP Address : %s, ping success\n", dest_ip_addr);
                        }
                    }
                    return;
                }

                case IP_PROTO_UDP:
                    /* VxLAN Block !! */
                    {
                        /* Check if this is VxLAN pkt, then no need to punt to CP */
                        pkt_size_t ip_hr_size;
                        ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_mbuf_get_pkt(mbuf, &ip_hr_size);
                        udp_hdr_t *udp_hdr = (udp_hdr_t *)INCREMENT_IPHDR(ip_hdr);
                        ip_hr_size = (pkt_size_t)((char *)udp_hdr - (char *)ip_hdr);
                        /* Strip the IP header: shrink head by ip_hr_size. */
                        pkt_mbuf_slide(mbuf, -1, 1, (uint16_t)ip_hr_size);
                        pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_UDP);
                        vxlan_decapsulate(dp_ctx, mbuf, ntohl(ip_hdr->src_ip));
                        return;
                    }

                    /* TODO: dp2cp_punt_pkt_to_layer4 needs old Interface type */
                    dp2cp_punt_pkt_to_layer4(
                                            dp_ctx->ctx_pvt_data,
                                            (Interface *)NULL,
                                            mbuf,
                                            IP_PROTO_UDP);

                    return;

                case IP_PROTO_IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    /* Strip the outer IP header: shrink head by its length. */
                    pkt_mbuf_slide(mbuf, -1, 1,
                                    (uint16_t)IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
                     
                    tracer (dp_ctx->dptr, DL3FWD, 
                        "VRF %s: Pkt : %s : Pkt is being subjected to L3 Routing again a per Inner Header\n",
                        vrf->vrf_name, dest_ip_addr);

                    layer3_ip_route_pkt(dp_ctx, vrf,
                                        interface, 
                                        mbuf);
                    return;

                case IP_PROTO_GRE:
                {
                    char gre_t_src_addr[IPV4_ADDR_LEN_STR];
                    char gre_t_dst_addr[IPV4_ADDR_LEN_STR];

                    /* Strip the IP header to expose the GRE header. */
                    pkt_mbuf_slide(mbuf, -1, 1,
                                    (uint16_t)IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_GRE);
                    tcp_ip_covert_ip_n_to_p ( ntohl (ip_hdr->dst_ip), (c_string)gre_t_src_addr);
                    tcp_ip_covert_ip_n_to_p ( ntohl (ip_hdr->src_ip), (c_string)gre_t_dst_addr);

                    tracer (dp_ctx->dptr, DL3FWD, 
                           "VRF %s: Pkt : %s : Pkt is being subjected to GRE Decapsulation, Tunnel key : [%s, %s]\n", 
                           vrf->vrf_name, dest_ip_addr, gre_t_src_addr, gre_t_dst_addr);

                    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL);
                    pkt_mbuf_slide(mbuf, -1, 1,
                                    (uint16_t)sizeof (gre_hdr_t));
                    
                    dp_intf_t *gre_intf = dp_lookup_gre_tunnel_intf 
                            (dp_ctx, 
                            ntohl (ip_hdr->dst_ip), 
                            ntohl (ip_hdr->src_ip));

                    if (!gre_intf) {

                        tracer (dp_ctx->dptr, DL3FWD | DTUNNEL | DERR, 
                            "Error : VRF %s: Pkt : %s : GRE tunnel do not exist for Tunnel key : [%s, %s], Pkt Dropped\n",
                            vrf->vrf_name, dest_ip_addr, gre_t_src_addr, gre_t_dst_addr );
                            dp_ctx->pkt_dropped++;
                        return;
                    }

                    if (!gre_intf->is_tunnel_up) {

                        tracer (dp_ctx->dptr, DL3FWD | DTUNNEL | DERR, 
                            "Error : VRF %s: Pkt : %s : GRE tunnel for Tunnel key : [%s, %s] is not Active, Pkt Dropped\n",
                            vrf->vrf_name, dest_ip_addr, gre_t_src_addr, gre_t_dst_addr);
                            gre_intf->recvd_pkt_dropped++;
                        return;
                    }

                    switch (ntohs(gre_hdr->protocol_type)) {

                        case ETH_TYPE_IPv4:
                        {
                            pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
                            tracer(dp_ctx->dptr, DTUNNEL_DET | DFLOW,
                                   "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_mbuf_str(mbuf));
                            gre_intf->pkt_recv++;
                            layer3_ip_route_pkt(dp_ctx, vrf, gre_intf, mbuf); // Pass an overlay tunnel interface here 
                        }
                        break;

                        case ETH_TYPE_GRE:
                        {
                            pkt_mbuf_update_new_hdr_type (mbuf, ETHERNET_HEADER);
                            tracer(dp_ctx->dptr, DTUNNEL_DET | DFLOW,
                                   "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_mbuf_str(mbuf));
                            dp_pkt_entry_point(dp_ctx, vrf, gre_intf,  mbuf);
                        }
                        break;
                    }

                    return;
                }
                default: ;
            }

            tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s : Pkt is being subjected to Layer 5\n",
                vrf->vrf_name, pkt_mbuf_str (mbuf));

            /* TODO: dp2cp_punt_pkt_to_layer5 needs old Interface type */
            dp2cp_punt_pkt_to_layer5(
                dp_ctx->ctx_pvt_data, NULL,
                mbuf,
                IP_PROTO_IP_IN_IP);

            return;
        }
         
        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/

    /* Forwarded packet: decrement TTL regardless of whether the destination
     * is directly connected or remote (RFC 1122 §3.2.1.7). */
    ip_hdr->ttl--;

    if (ip_hdr->ttl == 0) {
        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Pkt Dropped : TTL Expired\n",
            vrf->vrf_name, dest_ip_addr);
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s :  Nexthop found OIF %s, Gw : %s\n", 
        vrf->vrf_name, pkt_mbuf_str (mbuf), 
        nh->fwd_info->oif->if_name, 
        cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

    /* If src ip address is not feeded by application, then take the OIF IP address*/
    if (ip_hdr->src_ip == 0) {
        
        char ip_addr_str[IPV4_ADDR_LEN_STR];
        ip_hdr->src_ip = htonl(nh->fwd_info->oif->ip_addr);
        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt: %s : Using OIF IP as Src IP : %s\n", 
            vrf->vrf_name, pkt_mbuf_str (mbuf), 
            tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->src_ip), (c_string)ip_addr_str)); 

    }

    /* Checksum must be zeroed before recomputing: computing it over a packet
     * that already has a valid checksum field yields 0 (verification identity),
     * which would silently corrupt every forwarded packet. */
    ip_hdr->checksum = 0;
    ip_hdr->checksum = ip_checksum(ip_hdr);

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n",
        vrf->vrf_name, pkt_mbuf_str (mbuf));

    dp_demote_pkt_to_layer2 (
            dp_ctx,
            vrf,           /*Current processing node*/
            ntohl(ip_hdr->dst_ip),     /*next hop IP is dest itself as dest is present in local subnet*/
            nh->fwd_info->oif,           /*No oif as dest is present in local subnet*/
            mbuf,  /*Network Layer payload and size*/
            IP_PROTO_IP_IN_IP);        /*Network Layer need to tell Data link layer, what type of payload it is passing down*/

        return;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if (ip_hdr->ttl == 0) {

        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Pkt Dropped : TTL Expired\n",
            vrf->vrf_name, dest_ip_addr);
        return;
    }

    ip_hdr->checksum = 0;
    ip_hdr->checksum = ip_checksum(ip_hdr);

    tracer (dp_ctx->dptr, DL3FWD_DET, "VRF %s: Dest : %s :  TTL Reduced to %d\n",
        vrf->vrf_name, dest_ip_addr, ip_hdr->ttl);

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
            vrf->vrf_name, dest_ip_addr, 
            nh->fwd_info->oif->if_name, 
            cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

    nf_result = nf_invoke_netfilter_hook(
                        NF_IP_FORWARD,
                        mbuf,
                        dp_ctx->ctx_pvt_data,
                        nh->fwd_info->oif,
                        IP_PROTO_IP_IN_IP);

    switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        default: ;
    }

    next_hop_ip = nh->fwd_info->nh_addr.u.v4_addr;
   
    tcp_dump_l3_fwding_logger(dp_ctx, vrf, 
        (unsigned char *)nh->fwd_info->oif->if_name, 
        (unsigned char *)nh_str);

    nf_result = nf_invoke_netfilter_hook(
                    NF_IP_POST_ROUTING,
		            mbuf,
		            dp_ctx->ctx_pvt_data, 
                    nh->fwd_info->oif,
                    IP_PROTO_IP_IN_IP);

    switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        break;
    }

    tracer (dp_ctx->dptr, DL3FWD, 
        "VRF %s: Dest : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", vrf->vrf_name, dest_ip_addr);

    /* Check if GRE encapsulation is required */
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_TUNNEL) {

        uint16_t encap_proto = gre_encasulate(mbuf, 
                      &nh->fwd_info->u.gre_fwd.gre_tunnel_src, 
                      &nh->fwd_info->u.gre_fwd.gre_tunnel_dst);

        tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Pkt is GRE encapsulated to Tunnel end point %s\n",
            vrf->vrf_name,
            tcp_ip_covert_ip_n_to_p(nh->fwd_info->u.gre_fwd.gre_tunnel_dst.u.v4_addr, (c_string)dest_ip_addr),
            proto_id_str(encap_proto));
    }
    
    dp_demote_pkt_to_layer2(dp_ctx, 
            vrf, 
            next_hop_ip,
            nh->fwd_info->oif,
            mbuf,
            IP_PROTO_IP_IN_IP); /*Network Layer need to tell Data link layer, 
                                what type of payload it is passing down*/
}

/* An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void demote_packet_to_layer3(dp_ctx_t *dp_ctx,
                             uint8_t vrf_id,
                             struct rte_mbuf *mbuf,
                             gen_proto_id_t protocol_number, /*L4 or L5 protocol type*/
                             uint32_t dest_ip_address)
{

    byte *pkt;
    ip_hdr_t iphdr;
    char nh_str[48];
    byte dst_ip_addr_str[IPV4_ADDR_LEN_STR];
    pkt_size_t pkt_size;

    tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Pkt Arrived in L3-land from Top\n", 
        tcp_ip_covert_ip_n_to_p(dest_ip_address, dst_ip_addr_str));

    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, vrf_id);

    if (!vrf) {
        tracer (dp_ctx->dptr, DL3FWD | DERR, "Error : Invalid Vrf for packet Dest %s\n",
            pkt_mbuf_str(mbuf));
        return;
    }

    initialize_ip_hdr(&iphdr);  
      
    pkt = pkt_mbuf_get_pkt(mbuf,  &pkt_size);

    /*Now fill the non-default fields*/
    iphdr.protocol = (uint8_t)protocol_number;

    uint32_t addr_int =  dp_ctx->rtr_id;
    iphdr.src_ip = htonl(addr_int);
    iphdr.dst_ip = htonl(dest_ip_address);

    iphdr.total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    uint8_t *new_pkt = NULL;
    pkt_size_t new_pkt_size = 0 ;

    /* Make a room in pkt to accomodate IP Hdr */
    if (!pkt_mbuf_expand_buffer_left (mbuf, IP_HDR_LEN_IN_BYTES((&iphdr)))) {
        return;
    }

    new_pkt = pkt_mbuf_get_pkt (mbuf,  &new_pkt_size);
    pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_IP_IN_IP);

    memcpy((char *)new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v4(&prefix, htonl(iphdr.dst_ip), 32);
    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "VRF %s: Pkt : %s :  Pkt Dropped :  No L3 Route\n", 
            vrf->vrf_name, pkt_mbuf_str(mbuf));
        return;
    }

    bool is_direct_route = (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_CONNECTED) || 
                           (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL);
    
    if(is_direct_route){

        int8_t nf_result = nf_invoke_netfilter_hook(
                NF_IP_LOCAL_OUT,
				mbuf,
				dp_ctx->ctx_pvt_data, NULL,
                IP_PROTO_IP_IN_IP);

        switch (nf_result)
        {
            case NF_ACCEPT:
                break;
            case NF_DROP:
            case NF_STOLEN:
            case NF_STOP:
                return;
        }

        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Direct Route found, Pkt is being demoted to L2 Layer\n", 
            vrf->vrf_name, dst_ip_addr_str);

        dp_demote_pkt_to_layer2(dp_ctx, 
                         vrf,
                         dest_ip_address,
                         0,
                         mbuf,
                         IP_PROTO_IP_IN_IP);
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    
    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, "VRF %s: Dest : %s :  Pkt Dropped : No nexthop found\n", 
            vrf->vrf_name, dst_ip_addr_str);
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
            vrf->vrf_name, dst_ip_addr_str, 
            nh->fwd_info->oif->if_name, 
            cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

#if 0
    if (access_list_evaluate_ip_packet(node, 
                nexthop->oif, 
                (ip_hdr_t *)pkt_mbuf_get_ip_hdr(mbuf),
                false) == ACL_DENY) {

        pkt_mbuf_dereference (mbuf);
        l3_route_unlock(l3_route);
        thread_using_route_done(l3_route);
        return;
    }
#endif 
    next_hop_ip = nh->fwd_info->nh_addr.u.v4_addr;

    tcp_dump_l3_fwding_logger(dp_ctx, vrf, 
        (unsigned char *)nh->fwd_info->oif->if_name, 
        (unsigned char *)nh_str);

    int8_t nf_result = nf_invoke_netfilter_hook(
            NF_IP_LOCAL_OUT,
			mbuf,
			dp_ctx->ctx_pvt_data, 
            nh->fwd_info->oif,
            IP_PROTO_IP_IN_IP);

    switch (nf_result) 
    {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
            return;
    }

    tracer (dp_ctx->dptr, DL3FWD, 
        "VRF %s: Dest : %s :  Pkt is being demoted to L2 Layer\n",
        vrf->vrf_name, dst_ip_addr_str);
        
    dp_demote_pkt_to_layer2(dp_ctx, vrf,
            next_hop_ip,
            nh->fwd_info->oif,
            mbuf,
            IP_PROTO_IP_IN_IP);

    nh->hit_count++;
}


void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf) {

    char ip_addr_str[IPV4_ADDR_LEN_STR];

    assert (pkt_mbuf_verify_pkt (mbuf, IP_PROTO_IP_IN_IP));

    ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_mbuf_get_ip_hdr(mbuf);

    /* This API expects that IP-HDR must have following fields set */
    assert (ip_hdr->protocol);

    // Src IP may or may not be set already. If not set, we will determine it
    //assert (ip_hdr->src_ip);

    if (!ip_hdr->dst_ip) {

        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "Error : Dst IP address could not be determined, cannot send the pkt\n");

        cprintf ("Error : %s : Dst IP address could not be determined, cannot send the pkt\n", 
            dp_ctx->ctx_name);

        return;
    }

    assert (ip_hdr->total_length);

    tracer (dp_ctx->dptr, DL3FWD, "VRF:%s Dest:%s  NP Recvd Routing Request\n",
            vrf->vrf_name, pkt_mbuf_ip(mbuf, ip_addr_str));

    layer3_ip_route_pkt (dp_ctx, vrf, (dp_intf_t *)NULL, mbuf); 
}


