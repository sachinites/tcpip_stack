/*
 * =====================================================================================
 *
 *       Filename:  Layer5.c
 *
 *    Description:  This file represents the application making use of our virtual TCP/IP stack
 *
 *        Version:  1.0
 *        Created:  Thursday 26 September 2019 07:48:10  IST
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

#include "graph.h"
#include "../tcpconst.h"
#include <stdint.h>
#include "ddcp/ddcp.h"
#include "layer5.h"
#include <stdio.h>


static app_layer_cb 
    app_layer_cb_arr[MAX_PROTOCOL_NO_SUPPORTED]\
    [MAX_APPL_LAYER_CALLBACKS_PER_PROTO_SUPPORTED];

static void
layer5_invoke_app_cb(node_t *node, interface_t *recv_intf, 
                     char *l5_hdr, /*Application Data*/
                     uint32_t pkt_size, 
                     uint32_t L5_protocol,
                     uint32_t flags){

    int i = 0;
    for(; i < MAX_APPL_LAYER_CALLBACKS_PER_PROTO_SUPPORTED; i++){
        if(app_layer_cb_arr[L5_protocol][i]){
            app_layer_cb_arr[L5_protocol][i](node, recv_intf, l5_hdr, pkt_size, flags);
            continue;
        }
        return;
    }
}

void
promote_pkt_to_layer5(node_t *node, interface_t *recv_intf,
        char *l5_hdr, uint32_t pkt_size,
        uint32_t L5_protocol, uint32_t flags){

    switch(L5_protocol){
        case USERAPP1:
            break;
#if 0
        case DDCP_MSG_TYPE_UCAST_REPLY:
           ddcp_process_ddcp_reply_msg(node, l5_hdr);
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
           ddcp_process_ddcp_query_msg(node, recv_intf, (ethernet_hdr_t *)l5_hdr, pkt_size);
           break;
#endif
        default:
            layer5_invoke_app_cb(node, recv_intf, l5_hdr, pkt_size, L5_protocol, flags);
            ;
    }
}

void
layer5_register_l5_protocol_interest(uint32_t L5_protocol, 
                                app_layer_cb _app_layer_cb){

    int i = 0;
    for(; i < MAX_APPL_LAYER_CALLBACKS_PER_PROTO_SUPPORTED; i++){
        if(app_layer_cb_arr[L5_protocol][i]){
            if(app_layer_cb_arr[L5_protocol][i] == _app_layer_cb){
                assert(0); /*Why register again !!*/
            }
        }
        else{
            app_layer_cb_arr[L5_protocol][i] = _app_layer_cb;
            return;
        }
    }
    printf("Error %s() : Could not register application "
            "Callback for L3 protocol interest\n", __FUNCTION__);
}

void
layer5_deregister_l5_protocol_interest(uint32_t L5_protocol,
                                    app_layer_cb _app_layer_cb){
                                    
    int i = 0;                                   
    for(; i < MAX_APPL_LAYER_CALLBACKS_PER_PROTO_SUPPORTED; i++){
        
        if(app_layer_cb_arr[L5_protocol][i] == _app_layer_cb){
            app_layer_cb_arr[L5_protocol][i] = NULL;
        }
    }
}
