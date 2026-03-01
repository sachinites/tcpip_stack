
#include <assert.h>
#include <arpa/inet.h>
#include "../../../Tracer/tracer.h"

#include "../../../common/l3_hdrs.h"
#include "../../../common/l2_hdrs.h"
#include "../../../common/cmn_api.h"

#include "../../dp_ctx.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../Interface/dp_intf.h"
#include "../../../pkt_block.h"

#include "../../FIB/fib_nh.h"
#include "../Gre/gre-fwd.h"
#include "../../Interface/dp_intf_log.h"

extern void 
dp2cp_punt_pkt_to_layer4(void *_node,
                           Interface *recv_intf,
                           pkt_block_t *pkt_block,
                           int L4_protocol_number);

extern void
dp2cp_punt_pkt_to_layer5(void *_node,
                                  uint32_t recv_intf_ifindex,
                                  pkt_block_t *pkt_block,
                                  hdr_type_t hdr_code);

extern void
dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *oif,
                     pkt_block_t *pkt_block,
                     hdr_type_t hdr_type);

extern void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx,
                                  dp_vrf_t *vrf,
                                  dp_intf_t *interface,
                                  pkt_block_t *pkt_block);

void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					pkt_block_t *pkt_block) {

    char nh_str[48];
    int8_t nf_result;
    char *l4_hdr, *l5_hdr;
    ip_hdr_t *ip_hdr = NULL;
    uint32_t next_hop_ip= 0;
    char dest_ip_addr[IPV4_ADDR_LEN_STR];

    /* We are in L3 IP land, so starting hdr type must be IP_HDR */
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_HDR ||
                pkt_block_get_starting_hdr(pkt_block) == IP_IN_IP_HDR);

    ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->dst_ip), (c_string)dest_ip_addr);

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s : Trying to route ... \n", 
        vrf->vrf_name, dest_ip_addr);

        nf_result = nf_invoke_netfilter_hook(
            NF_IP_PRE_ROUTING,
            pkt_block, 
            dp_ctx->ctx_pvt_data,
            interface,
            IP_HDR);

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

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v4(&prefix, htonl(ip_hdr->dst_ip), 32);
    
    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "VRF %s: Pkt : %s :  Pkt Dropped :  No L3 Route\n", vrf->vrf_name, pkt_block_str(pkt_block));
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s : L3 Route Found\n", vrf->vrf_name, dest_ip_addr);

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

        tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s : L3 Route found is local route\n", dest_ip_addr);

        if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL) {

            tracer (dp_ctx->dptr, DL3FWD, 
                "Pkt : %s : Pkt is for Local Delivery, IP protocol = %s\n",   
                 dest_ip_addr, proto_name_str(ip_hdr->protocol));

            l4_hdr = (char *)INCREMENT_IPHDR(ip_hdr);
            l5_hdr = l4_hdr;

            switch(ip_hdr->protocol) {

                case MTCP:
                    /* TODO: dp2cp_punt_pkt_to_layer4 needs old Interface type */
                    dp2cp_punt_pkt_to_layer4(dp_ctx->ctx_pvt_data, 
                            NULL,
							pkt_block, ip_hdr->protocol);
                    return;

                case ICMP_PROTO:
                    cprintf("IP Address : %s, ping success\n", dest_ip_addr);
                    return;

                case UDP_PROTO:
                        /* TODO: dp2cp_punt_pkt_to_layer4 needs old Interface type */
                        dp2cp_punt_pkt_to_layer4 (
                                              dp_ctx->ctx_pvt_data,
                                             (Interface *)NULL,
										      pkt_block,
                                              UDP_PROTO);
                    return;

                case PROTO_IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    pkt_block_set_new_pkt(pkt_block, 
                                         (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                        pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_block_set_starting_hdr_type (pkt_block, IP_IN_IP_HDR);
                     
                    tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to L3 Routing again a per Inner Header\n", dest_ip_addr);

                    layer3_ip_route_pkt(dp_ctx, vrf,
                                        interface, 
                                        pkt_block);
                    return;

                case GRE_PROTO:
                {
                    char gre_t_src_addr[IPV4_ADDR_LEN_STR];
                    char gre_t_dst_addr[IPV4_ADDR_LEN_STR];

                    pkt_block_set_new_pkt (pkt_block, 
                                           (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                           pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_block_set_starting_hdr_type (pkt_block, GRE_HDR);
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->dst_ip), (c_string)gre_t_src_addr);
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->src_ip), (c_string)gre_t_dst_addr);

                    tracer (dp_ctx->dptr, DL3FWD, 
                           "Pkt : %s : Pkt is being subjected to GRE Decapsulation, Tunnel key : [%s, %s]\n", 
                           dest_ip_addr, gre_t_src_addr, gre_t_dst_addr);

                    // FIX ME
                    gre_decapsulate (dp_ctx, vrf, pkt_block, NULL
                            /*gre_lookup_tunnel_intf (node, htonl(ip_hdr->dst_ip), htonl(ip_hdr->src_ip))*/);
                    return;
                }
                default: ;
            }

            tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to Layer 5\n",  pkt_block_str (pkt_block));

            /* TODO: dp2cp_punt_pkt_to_layer5 needs old Interface type */
            dp2cp_punt_pkt_to_layer5(
                dp_ctx->ctx_pvt_data, NULL,
                pkt_block,
                IP_HDR);

            return;
        }
         
        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/

    tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s :  Nexthop found OIF %s, Gw : %s\n", 
        pkt_block_str (pkt_block), 
        nh->fwd_info->oif->if_name, 
        cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

    /* If src ip address is not feeded by application, then take the OIF IP address*/
    if (ip_hdr->src_ip == 0) {
        
        char ip_addr_str[IPV4_ADDR_LEN_STR];
        ip_hdr->src_ip = htonl(nh->fwd_info->oif->ip_addr);
        tracer (dp_ctx->dptr, DL3FWD, "Pkt: %s : Using OIF IP as Src IP : %s\n", 
            pkt_block_str (pkt_block), 
            tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->src_ip), (c_string)ip_addr_str)); 
    }

    tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", pkt_block_str (pkt_block));

    dp_demote_pkt_to_layer2 (
            dp_ctx,
            vrf,           /*Current processing node*/
            htonl(ip_hdr->dst_ip),     /*next hop IP is dest itself as dest is present in local subnet*/
            nh->fwd_info->oif,           /*No oif as dest is present in local subnet*/
            pkt_block,  /*Network Layer payload and size*/
            IP_HDR);        /*Network Layer need to tell Data link layer, what type of payload it is passing down*/

        return;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if (ip_hdr->ttl == 0) {

        tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Pkt Dropped : TTL Expired\n", dest_ip_addr);
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD_DET, "Dest : %s :  TTL Reduced to %d\n", dest_ip_addr, ip_hdr->ttl);

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
            dest_ip_addr, 
            nh->fwd_info->oif->if_name, 
            cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

    nf_result = nf_invoke_netfilter_hook(
                        NF_IP_FORWARD,
                        pkt_block,
                        dp_ctx->ctx_pvt_data,
                        nh->fwd_info->oif,
                        IP_HDR);

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
		            pkt_block,
		            dp_ctx->ctx_pvt_data, 
                    nh->fwd_info->oif,
                    IP_HDR);

    switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        break;
    }

    tracer (dp_ctx->dptr, DL3FWD, 
        "Dest : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", dest_ip_addr);

    dp_demote_pkt_to_layer2(dp_ctx, 
            vrf, 
            next_hop_ip,
            nh->fwd_info->oif,
            pkt_block,
            IP_HDR); /*Network Layer need to tell Data link layer, 
                                what type of payload it is passing down*/
}

/* An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void demote_packet_to_layer3(dp_ctx_t *dp_ctx,
                             uint8_t vrf_id,
                             pkt_block_t *pkt_block,
                             hdr_type_t protocol_number, /*L4 or L5 protocol type*/
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
            pkt_block_str(pkt_block));
        return;
    }

    initialize_ip_hdr(&iphdr);  
      
    pkt = pkt_block_get_pkt(pkt_block,  &pkt_size);

    /*Now fill the non-default fields*/
    iphdr.protocol = tcp_ip_convert_internal_proto_to_std_proto(protocol_number);

    uint32_t addr_int =  dp_ctx->rtr_id;
    iphdr.src_ip = htonl(addr_int);
    iphdr.dst_ip = htonl(dest_ip_address);

    iphdr.total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    uint8_t *new_pkt = NULL;
    pkt_size_t new_pkt_size = 0 ;

    /* Make a room in pkt to accomodate IP Hdr */
    if (!pkt_block_expand_buffer_left (pkt_block, IP_HDR_LEN_IN_BYTES((&iphdr)))) {
        return;
    }

    new_pkt = pkt_block_get_pkt (pkt_block,  &new_pkt_size);
    pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);

    memcpy((char *)new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v4(&prefix, htonl(iphdr.dst_ip), 32);
    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "VRF %s: Pkt : %s :  Pkt Dropped :  No L3 Route\n", 
            vrf->vrf_name, pkt_block_str(pkt_block));
        return;
    }

    bool is_direct_route = (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_CONNECTED) || 
                           (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL);
    
    if(is_direct_route){

        int8_t nf_result = nf_invoke_netfilter_hook(
                NF_IP_LOCAL_OUT,
				pkt_block,
				dp_ctx->ctx_pvt_data, NULL,
                IP_HDR);

        switch (nf_result)
        {
            case NF_ACCEPT:
                break;
            case NF_DROP:
            case NF_STOLEN:
            case NF_STOP:
                return;
        }

        tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Direct Route found, Pkt is being demoted to L2 Layer\n", 
            dst_ip_addr_str);

        dp_demote_pkt_to_layer2(dp_ctx, 
                         vrf,
                         dest_ip_address,
                         0,
                         pkt_block,
                         IP_HDR);
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    
    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, "Dest : %s :  Pkt Dropped : No nexthop found\n", 
            dst_ip_addr_str);
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
            dst_ip_addr_str, 
            nh->fwd_info->oif->if_name, 
            cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str));

    if (pkt_block->exclude_oif &&
            pkt_block->exclude_oif == nh->fwd_info->oif) assert(0);

#if 0
    if (access_list_evaluate_ip_packet(node, 
                nexthop->oif, 
                (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block),
                false) == ACL_DENY) {

        pkt_block_dereference (pkt_block);
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
			pkt_block,
			dp_ctx->ctx_pvt_data, 
            nh->fwd_info->oif,
            IP_HDR);

    switch (nf_result) 
    {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
            return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Pkt is being demoted to L2 Layer\n", dst_ip_addr_str);
    dp_demote_pkt_to_layer2(dp_ctx, vrf,
            next_hop_ip,
            nh->fwd_info->oif,
            pkt_block,
            IP_HDR);

    nh->hit_count++;
}


void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block) {

    char ip_addr_str[IPV4_ADDR_LEN_STR];

    assert (pkt_block_verify_pkt (pkt_block, IP_HDR));

    ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    /* This API expects that IP-HDR must have following fields set */
    assert (ip_hdr->protocol);

    // Src IP may or may not be set already. If not set, we will determine it
    //assert (ip_hdr->src_ip);

    assert (ip_hdr->dst_ip);
    assert (ip_hdr->total_length);

    tracer (dp_ctx->dptr, DL3FWD, "Dest : %s : NP Recvd Routing Request\n", pkt_ip(pkt_block, ip_addr_str));

    layer3_ip_route_pkt (dp_ctx, vrf, (dp_intf_t *)NULL, pkt_block); 
}


