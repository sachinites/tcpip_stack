/*
 * =====================================================================================
 *
 *       Filename:  comm.c
 *
 *    Description:  This file contains the routines to implement the communication between nodes
 *
 *        Version:  1.0
 *        Created:  Thursday 19 September 2019 10:31:35  IST
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

#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h> // for close
#include <netdb.h>  /*for struct hostent*/
#include "comm.h"
#include "graph.h"
#include "net.h"
#include "EventDispatcher/event_dispatcher.h"

pkt_q_t recvr_pkt_q;

static void
pkt_recvr_job_cbk(void *pkt, uint32_t pkt_size){

	node_t *receving_node;
	interface_t *recv_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(&pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(&pkt_size)) {

		receving_node = ev_dis_pkt_data->recv_node;
		recv_intf = ev_dis_pkt_data->recv_intf;
		pkt = ev_dis_pkt_data->pkt;		
		recv_intf->intf_nw_props.pkt_recv++;

		pkt_receive(receving_node, recv_intf, 
					pkt,
					ev_dis_pkt_data->pkt_size);

		free(ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
		free(pkt);
	}
}

/* called from init_tcp_ip_stack() at the
 * time of initialization
 * */
void
init_pkt_recv_queue() {

	init_pkt_q(&recvr_pkt_q, pkt_recvr_job_cbk);
}

int
send_pkt_to_self(char *pkt, uint32_t pkt_size,
                interface_t *interface){

    int rc = 0;    
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = sending_node;
  
	ev_dis_pkt_data_t *ev_dis_pkt_data;
 
    if(!IF_IS_UP(interface)){
        return 0;
    }

    interface_t *other_interface =  interface;

	ev_dis_pkt_data = calloc(1, sizeof(ev_dis_pkt_data_t));

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_intf = other_interface;
	ev_dis_pkt_data->pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

	pkt_q_enqueue(&recvr_pkt_q, (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
	
	tcp_dump_send_logger(sending_node, interface, 
			pkt, pkt_size, ETH_HDR);

    return pkt_size; 
       
}

/*Public APIs to be used by the other modules*/
int
send_pkt_out(char *pkt, uint32_t pkt_size, 
             interface_t *interface){

	ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = get_nbr_node(interface);
    
    
    if(!IF_IS_UP(interface)){
		interface->intf_nw_props.xmit_pkt_dropped++;
        return 0;
    }

    if(!nbr_node)
        return -1;

    if(pkt_size > MAX_PACKET_BUFFER_SIZE){
        printf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }

    interface_t *other_interface = &interface->link->intf1 == interface ? \
                                    &interface->link->intf2 : &interface->link->intf1;

	ev_dis_pkt_data = calloc(1, sizeof(ev_dis_pkt_data_t));

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_intf = other_interface;
	ev_dis_pkt_data->pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

	pkt_q_enqueue(&recvr_pkt_q, (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
	
	interface->intf_nw_props.pkt_sent++;
	tcp_dump_send_logger(sending_node, interface, 
			pkt, pkt_size, ETH_HDR);

    return pkt_size; 
}

extern void
layer2_frame_recv(node_t *node, interface_t *interface,
                     char *pkt, uint32_t pkt_size);

int
pkt_receive(node_t *node, interface_t *interface,
            char *pkt, uint32_t pkt_size){

    tcp_dump_recv_logger(node, interface, 
            (char *)pkt, pkt_size, ETH_HDR);
    
    /*Make room in the packet buffer by shifting the data towards
      right so that tcp/ip stack can append more hdrs to the packet 
      as required */
    pkt = pkt_buffer_shift_right(pkt, pkt_size, 
            MAX_PACKET_BUFFER_SIZE - IF_NAME_SIZE);
    
    /*Do further processing of the pkt here*/
    layer2_frame_recv(node, interface, pkt, pkt_size );
    return 0;
}

int
send_pkt_flood(node_t *node, interface_t *exempted_intf, 
                char *pkt, uint32_t pkt_size){

    uint32_t i = 0;
    interface_t *intf; 

    for( ; i < MAX_INTF_PER_NODE; i++){

        intf = node->intf[i];
        if(!intf) return 0;

        if(intf == exempted_intf)
            continue;

        send_pkt_out(pkt, pkt_size, intf);
    }
    return 0;
}
