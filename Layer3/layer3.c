/*
 * =====================================================================================
 *
 *       Filename:  layer3.c
 *
 *    Description:  This file defines the routines for Layer 3
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 05:24:38  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <memory.h>
#include <stdlib.h>
#include <pthread.h>
#include "../common/l3_hdrs.h"
#include "../FIB/fib_nh.h"
#include "../FIB/fib.h"
#include "../datapath/Interface/dp_intf.h"
#include "../router_init.h"
#include "../datapath/dp_ctx.h"
#include "../Layer2/layer2.h"
#include "../Layer5/layer5.h"
#include "rt_table/nexthop.h"
#include "../Threads/refcount.h"
#include "layer3.h"
#include "../tcpconst.h"
#include "../comm.h"
#include "netfilter.h"
#include "../notif.h"
#include "rt_notif.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../lmm_enums.h"
#include "../FireWall/acl/acldb.h"
#include "../mtrie/mtrie.h"
#include "../pkt_block.h"
#include "../prefix-list/prefixlst.h"
#include "../FireWall/Connection/conn.h"
#include "../Interface/InterfaceUApi.h"
#include "../common/cp2dp.h"
#include "../Tracer/tracer.h"
#include "ipv6/ipv6_route.h"
#include "../datapath/Interface/dp_intf_log.h"

extern graph_t *topo;

extern int
nh_flush_nexthops(nexthop_t **nexthop);

extern void
layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface,
                      pkt_block_t *pkt_block);

extern void
promote_pkt_to_layer4(void *node, Interface *recv_intf, 
                      pkt_block_t *pkt_block,
                      int L4_protocol_number);

/*import function from layer 2*/
extern void
demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *outgoing_intf, 
                     pkt_block_t *pkt_block,
                     hdr_type_t hdr_type);

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
                    /* TODO: promote_pkt_to_layer4 needs old Interface type */
                    promote_pkt_to_layer4(dp_ctx->ctx_pvt_data, 
                            NULL,
							pkt_block, ip_hdr->protocol);
                    return;

                case ICMP_PROTO:
                    cprintf("IP Address : %s, ping success\n", dest_ip_addr);
                    return;

                case UDP_PROTO:
                        /* TODO: promote_pkt_to_layer4 needs old Interface type */
                        promote_pkt_to_layer4 (
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
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->dst_ip), gre_t_src_addr);
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->src_ip), gre_t_dst_addr);

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

            /* TODO: promote_pkt_from_layer3_to_layer5 needs old Interface type */
            promote_pkt_from_layer3_to_layer5(
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
            tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->src_ip), ip_addr_str)); 
    }

    tracer (dp_ctx->dptr, DL3FWD, "Pkt : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", pkt_block_str (pkt_block));

    demote_pkt_to_layer2 (
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
        nh->fwd_info->oif->if_name, nh_str);

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

    demote_pkt_to_layer2(dp_ctx, 
            vrf, 
            next_hop_ip,
            nh->fwd_info->oif,
            pkt_block,
            IP_HDR); /*Network Layer need to tell Data link layer, 
                                what type of payload it is passing down*/
}

/* Return true if policy is passed, else false */

static void
_layer3_pkt_recv_from_layer2(dp_ctx_t *dp_ctx,
                             dp_vrf_t *vrf,
                             dp_intf_t *interface,
                             pkt_block_t *pkt_block,
                             int L3_protocol_type) {

    pkt_size_t pkt_size;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    assert(pkt_block_verify_pkt (pkt_block, ETH_HDR));

    pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(L3_protocol_type){
        
        case ETH_IP:
        case PROTO_IP_IN_IP:

            /* Remove the Data link Hdr from the pkt */
            pkt_block_set_new_pkt( pkt_block,
                    (uint8_t *)pkt_block_get_ip_hdr(pkt_block),
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD + ETH_FCS_SIZE);
            pkt_block_set_starting_hdr_type(pkt_block, 
                L3_protocol_type == ETH_IP ? IP_HDR : IP_IN_IP_HDR);

            tracer (dp_ctx->dptr, DL3FWD, "Dest : %s :  Pkt Arrived in L3-land from Layer 2\n",
                pkt_ip(pkt_block, ip_addr_str));

            layer3_ip_route_pkt(dp_ctx, vrf, interface, pkt_block);
            break;

        case ETH_IP6:
            pkt_block_set_new_pkt( pkt_block,
                    (uint8_t *)pkt_block_get_ip6_hdr(pkt_block),
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD + ETH_FCS_SIZE);
            pkt_block_set_starting_hdr_type(pkt_block, IP6_HDR);
            layer3_ipv6_route_pkt(dp_ctx, vrf, interface, pkt_block);            
            break;

        default:
            ;
    }
}

/* A public API to be used by L2 or other lower Layers to promote
 * pkts to Layer 3 in TCP IP Stack*/
void
promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,               /*Current node on which the pkt is received*/
                      dp_intf_t *interface,  /*ingress interface*/
                      pkt_block_t *pkt_block, /*L3 payload*/
                      int L3_protocol_number) {  /*obtained from eth_hdr->type field*/
	
	_layer3_pkt_recv_from_layer2(dp_ctx, vrf, interface,
				pkt_block,
				L3_protocol_number);
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

        demote_pkt_to_layer2(dp_ctx, 
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
        nh->fwd_info->oif->if_name, nh_str);

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
    demote_pkt_to_layer2(dp_ctx, vrf,
            next_hop_ip,
            nh->fwd_info->oif,
            pkt_block,
            IP_HDR);

    nh->hit_count++;
}

/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/
void
layer3_ping_fn(node_t *node, c_string dst_ip_addr, uint32_t count){

    uint32_t i;
    uint32_t addr_int;

    addr_int = tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    cprintf("\nSrc node : %s, Ping ip : %s", node->node_name, dst_ip_addr);

    for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, ICMP_PROTO);
    }
}

void
layer3_ero_ping_fn(node_t *node, 
                    c_string dst_ip_addr, 
                    c_string ero_ip_address){

    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer (sizeof (ip_hdr_t));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *inner_ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE);
    inner_ip_hdr->protocol = ICMP_PROTO;
    uint32_t addr_int = tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node));
    inner_ip_hdr->src_ip = htonl(addr_int);
    addr_int =  tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    inner_ip_hdr->dst_ip = htonl(addr_int);
    addr_int = tcp_ip_convert_ip_p_to_n(ero_ip_address);
    cp2dp_send_ip_data (node, pkt_block, addr_int, PROTO_IP_IN_IP);
    pkt_block_dereference(pkt_block);
}

void
np_tcp_ip_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block) {

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

extern int 
ip_traffic_generate_handler(int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable) {

    int i;
    uint32_t count = 1;
    uint8_t protocol;
    uint32_t addr_int;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    char *src_addr_str = NULL;
    char *dst_addr_str = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "src-addr"))
            src_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-addr"))
            dst_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "count"))
            count = atoi(tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "protocol"))
            protocol = atoi(tlv->value);

   } TLV_LOOP_END;
   
   node = node_get_node_by_name(topo, node_name);

   addr_int = tcp_ip_convert_ip_p_to_n(dst_addr_str );

   for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, protocol);
    }
    
    return 0;
}
