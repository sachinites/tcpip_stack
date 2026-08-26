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
#include <arpa/inet.h>
#include <memory.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <semaphore.h>
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"

#include "../router_init.h"
#include "../libs/common/l3_hdrs.h"
#include "../utils.h"
#include "../dpal/cp2dp.h"
#include "../cmdcodes.h"
#include "../datapath/Layer3/ping.h"

extern graph_t *topo;

static void
layer3_ero_ping_fn(node_t *node, 
                    c_string dst_ip_addr, 
                    c_string ero_ip_address){

    ip_hdr_t inner_ip_hdr;

    initialize_ip_hdr(&inner_ip_hdr);
    inner_ip_hdr.total_length = htons(IP_HDR_DEFAULT_SIZE);
    inner_ip_hdr.protocol = IP_PROTO_ICMP;
    inner_ip_hdr.src_ip = htonl(tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node)));
    inner_ip_hdr.dst_ip = htonl(tcp_ip_convert_ip_p_to_n(dst_ip_addr));

    cp2dp_send_ip_data(node, NODE_DEF_VRF(node),
                       (uint8_t *)&inner_ip_hdr, IP_HDR_DEFAULT_SIZE,
                       tcp_ip_convert_ip_p_to_n(ero_ip_address),
                       IP_PROTO_IP_IN_IP);
}



extern int 
ip_traffic_generate_handler(int64_t cmdcode,
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
        cp2dp_send_ip_data (node, NODE_DEF_VRF(node), NULL, 0, addr_int, protocol);
    }
    
    return 0;
}

int
ping_handler(int64_t cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable){

    node_t *node;
    uint32_t count = 1;
    c_string ip_addr = NULL;
    c_string src_ip = NULL;
    c_string ero_ip_addr = NULL;
    c_string node_name = NULL;
    c_string vrf_name = NULL;

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ip-address"))
            ip_addr = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "src-ip"))
            src_ip = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ero-ip-address"))
            ero_ip_addr = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "count"))
            count = atoi(tlv->value);
        else if(parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    vrf_t *vrf = vrf_name ? vrf_get_by_name(node, vrf_name) : NODE_DEF_VRF(node);

    switch(cmdcode){

        case CMDCODE_PING:
        {
            struct timespec ts;
            uint32_t ip_addr_int;

            ip_addr_int = tcp_ip_convert_ip_p_to_n(ip_addr);

            ping_ctx_t *pctx = (ping_ctx_t *)calloc (1, sizeof (ping_ctx_t ));

            pctx->vrf_id = vrf->vrf_id;
            cmn_prefix_initialize_v4(&pctx->dst, ip_addr_int, 32);
            if (src_ip) {
                cmn_prefix_initialize_v4(&pctx->src,
                                         tcp_ip_convert_ip_p_to_n(src_ip), 32);
            }
            sem_init(&pctx->cli_unblock_sem, 0, 0);
            pctx->count = count;

            cp2dp_ping_request (node, pctx);

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;
            int rc = sem_timedwait(&pctx->cli_unblock_sem, &ts);
            
            if (rc == -1 && errno == ETIMEDOUT) {

                cprintf ("Ping Timeout ....\n");

                if (pctx->ping_thread) {
                    pthread_cancel (*pctx->ping_thread);
                    pthread_join (*pctx->ping_thread, NULL);
                    free (pctx->ping_thread);
                    pctx->ping_thread = NULL;
                    sem_destroy(&pctx->reply_sem);
                }
            }

            sem_destroy(&pctx->cli_unblock_sem);

            /* Summary */
            uint32_t lost = pctx->sent - pctx->received;
            uint32_t loss_pct = pctx->sent ? (lost * 100 / pctx->sent) : 0;

            cprintf("\n--- %s ping statistics ---\n", ip_addr);
            cprintf("%u packets transmitted, %u received, %u%% packet loss\n",
                    pctx->sent, pctx->received, loss_pct);

            if (pctx->received > 0)
            {
                cprintf("RTT min/avg/max = %u/%u/%u us\n",
                        pctx->rtt_min,
                        (uint32_t)(pctx->rtt_sum / pctx->received),
                        pctx->rtt_max);
            }

            assert (!pctx->ping_thread);
            free(pctx);
        }
        break;
        
        case CMDCODE_ERO_PING:
            layer3_ero_ping_fn(node, ip_addr, ero_ip_addr);
            break;
        default:
            ;
    }

    return 0;
}
