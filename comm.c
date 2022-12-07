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

#include <pthread.h>
#include <netinet/in.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h> // for close
#include <netdb.h>  /*for struct hostent*/
#include <sys/socket.h>
#include "LinuxMemoryManager/uapi_mm.h"
#include "EventDispatcher/event_dispatcher.h"
#include "comm.h"
#include "graph.h"
#include "net.h"
#include "Layer2/layer2.h"
#include "FireWall/acl/acldb.h"
#include "pkt_block.h"
#include "Interface/Interface.h"

extern graph_t *topo;

extern void
l2_switch_recv_frame(node_t *node,
                                     interface_t *interface,
                                     pkt_block_t *pkt_block);

extern void
network_start_pkt_receiver_thread(void);

extern void
dp_pkt_recvr_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size);
extern void
node_init_udp_socket(node_t *node);

extern void
dp_pkt_recvr_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    pkt_block_t *pkt_block;
	node_t *receving_node;
	interface_t *recv_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		receving_node = ev_dis_pkt_data->recv_node;
		recv_intf = ev_dis_pkt_data->recv_intf;
		pkt = ev_dis_pkt_data->pkt;		
		recv_intf->intf_nw_props.pkt_recv++;

        pkt_block = pkt_block_get_new((uint8_t *)pkt, ev_dis_pkt_data->pkt_size);
        pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);

        /* Bump the ref counter since pkt is not being injected into data path*/
        pkt_block_reference(pkt_block);

		dp_pkt_receive(receving_node,
                    recv_intf, 
                    pkt_block);

		XFREE(ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
	}
}

int
send_pkt_to_self (
                pkt_block_t *pkt_block,
                interface_t *interface){
 
    uint8_t *pkt;
    pkt_size_t pkt_size;

    node_t *sending_node = interface->att_node;
    node_t *nbr_node = sending_node;
  
	ev_dis_pkt_data_t *ev_dis_pkt_data;
 
    if (!IF_IS_UP(interface)){
        return 0;
    }

    interface_t *other_interface =  interface;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

	ev_dis_pkt_data = (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_intf = other_interface;
	ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

	pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node) ,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
	
	tcp_dump_send_logger(sending_node,
                                           interface, 
			                               pkt_block,
                                           pkt_block_get_starting_hdr(pkt_block) );

    return pkt_size; 
}

/*Public APIs to be used by the other modules*/
int
send_pkt_out (pkt_block_t *pkt_block,
             interface_t *interface){

    pkt_size_t pkt_size;
	ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = get_nbr_node(interface);
    
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!IF_IS_UP(interface)){
		interface->intf_nw_props.xmit_pkt_dropped++;
        return 0;
    }

    if (!nbr_node)
        return -1;

    if (pkt_size > MAX_PACKET_BUFFER_SIZE){
        printf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }

#if 0
    /* Access List Evaluation at Layer 2 Exit point*/
    if (access_list_evaluate_ethernet_packet(
            interface->att_node, interface, 
           pkt_block, false)  == ACL_DENY) {
        return -1;
    }
#endif 
    interface_t *other_interface = &interface->link->intf1 == interface ? \
                                    &interface->link->intf2 : &interface->link->intf1;

	ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC(0,1, ev_dis_pkt_data_t);

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_intf = other_interface;
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

    tcp_dump_send_logger(sending_node, interface, 
			pkt_block, pkt_block_get_starting_hdr(pkt_block));

	if (!pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node),
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t))) {

        printf ("%s : Fatal : Ingress Pkt QueueExhausted\n", nbr_node->node_name);

        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        XFREE(ev_dis_pkt_data);
    }
	
	interface->intf_nw_props.pkt_sent++;
    interface->intf_nw_props.bit_rate.new_bit_stats += pkt_size * 8;
    
    return pkt_size; 
}

int
send_pkt_out2 (pkt_block_t *pkt_block,
             Interface *interface){

    pkt_size_t pkt_size;
	ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = interface->GetNbrNode();
    
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!(interface->is_up)){
        interface->Xmit_pkt_dropped_inc();
        return 0;
    }

    if (!nbr_node)
        return -1;

    if (pkt_size > MAX_PACKET_BUFFER_SIZE){
        printf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }

#if 0
    /* Access List Evaluation at Layer 2 Exit point*/
    if (access_list_evaluate_ethernet_packet(
            interface->att_node, interface, 
           pkt_block, false)  == ACL_DENY) {
        return -1;
    }
#endif 

    Interface *other_interface = interface->GetOtherInterface();

	ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC(0,1, ev_dis_pkt_data_t);

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_Intf = other_interface;
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

#if 0
    tcp_dump_send_logger(sending_node, interface, 
			pkt_block, pkt_block_get_starting_hdr(pkt_block));
#endif 

	if (!pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node),
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t))) {

        printf ("%s : Fatal : Ingress Pkt QueueExhausted\n", nbr_node->node_name);

        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        XFREE(ev_dis_pkt_data);
    }
	
    interface->PktSentInc();
    interface->BitRateNewBitStatsInc(pkt_size * 8);
    
    return pkt_size; 
}

void
dp_pkt_receive (node_t *node, 
                           interface_t *interface,
                           pkt_block_t *pkt_block){

    uint32_t vlan_id_to_tag = 0;
  
    tcp_dump_recv_logger(node, interface, pkt_block, ETH_HDR);

#if 0
    /* Access List Evaluation at Layer 2 Entry point*/ 
    if (access_list_evaluate_ethernet_packet(
                node, interface, pkt_block, true) 
                == ACL_DENY) {

        assert(!pkt_block_dereference(pkt_block));
        return;
    }
#endif 

    if (l2_frame_recv_qualify_on_interface(
                                          node,
                                          interface, 
                                          pkt_block,
                                          &vlan_id_to_tag) == false){
        
        printf("L2 Frame Rejected on node %s(%s)\n", 
            node->node_name, interface->if_name);
        assert(!pkt_block_dereference(pkt_block));
        return;
    }

    if ( (vlan_id_to_tag) &&
       (( IF_L2_MODE(interface) == ACCESS) || (IF_L2_MODE(interface) == TRUNK))) {

        tag_pkt_with_vlan_id (pkt_block, vlan_id_to_tag);
        l2_switch_recv_frame(node, interface, pkt_block);
        assert(!pkt_block_dereference(pkt_block));
    }

    else if (IS_INTF_L3_MODE(interface)){
            promote_pkt_to_layer2(node, interface, pkt_block);
    }
}

int
send_pkt_flood(node_t *node, 
               interface_t *exempted_intf, 
               pkt_block_t *pkt_block) {

    uint32_t i = 0;
    interface_t *intf; 

    for( ; i < MAX_INTF_PER_NODE; i++){

        intf = node->intf[i];
        if(!intf) return 0;

        if(intf == exempted_intf)
            continue;

        send_pkt_out(pkt_block, intf);
    }
    return 0;
}

/* Enabling pkt Reception via Socket interface. Each node shall be
listening to UDP port no, so that an external process can inject the
traffic into the topology. Once Node recv the pkt, the traffic will be
set on its course towards destination as per the usual pseudo TCPIP stack
implementation */

static uint32_t udp_port_number = 40000;

static uint32_t 
node_get_next_udp_port_number(void) {
    
    return udp_port_number++;
}

extern void
node_init_udp_socket(node_t *node){

    if(node->udp_port_number)
        return;
    
    node->udp_port_number = node_get_next_udp_port_number();
     
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    
    if(udp_sock_fd == -1){
        printf("Socket Creation Failed for node %s\n", node->node_name);
        return;   
    }

    struct sockaddr_in node_addr;
    node_addr.sin_family      = AF_INET;
    node_addr.sin_port        = node->udp_port_number;
    node_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock_fd, (struct sockaddr *)&node_addr, sizeof(struct sockaddr)) == -1) {
        printf("Error : socket bind failed for Node %s\n", node->node_name);
        return;
    }

    node->udp_sock_fd = udp_sock_fd;
}

static void
_pkt_receive(node_t *receving_node, 
            char *pkt_with_aux_data, 
            uint32_t pkt_size){

    pkt_block_t *pkt_block;
    char *recv_intf_name = pkt_with_aux_data;
    interface_t *recv_intf = node_get_intf_by_name(receving_node, recv_intf_name);

    if(!recv_intf){
        printf("Error : Pkt recvd on unknown interface %s on node %s\n", 
                    recv_intf_name, receving_node->node_name);
        return;
    }

    pkt_block = pkt_block_get_new(NULL, 0);

    pkt_block_set_new_pkt(pkt_block,
                                            (uint8_t *)pkt_with_aux_data + IF_NAME_SIZE, 
                                            pkt_size - IF_NAME_SIZE);

    pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);

    send_pkt_to_self (pkt_block, recv_intf);
    XFREE(pkt_block);
}

static char recv_buffer[MAX_PACKET_BUFFER_SIZE];

static void *
_network_start_pkt_receiver_thread(void *arg){

    node_t *node;
    glthread_t *curr;
    
    fd_set active_sock_fd_set,
           backup_sock_fd_set;
    
    int sock_max_fd = 0;
    int bytes_recvd = 0;
    
    graph_t *topo = (graph_t *)arg;

    uint32_t addr_len = sizeof(struct sockaddr);

    FD_ZERO(&active_sock_fd_set);
    FD_ZERO(&backup_sock_fd_set);
    
    struct sockaddr_in sender_addr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        
        if(!node->udp_sock_fd) 
            continue;

        if(node->udp_sock_fd > sock_max_fd)
            sock_max_fd = node->udp_sock_fd;

        FD_SET(node->udp_sock_fd, &backup_sock_fd_set);
            
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);

    while(1){

        memcpy(&active_sock_fd_set, &backup_sock_fd_set, sizeof(fd_set));

        select(sock_max_fd + 1, &active_sock_fd_set, NULL, NULL, NULL);

        ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

            node = graph_glue_to_node(curr);

            if(FD_ISSET(node->udp_sock_fd, &active_sock_fd_set)){
    
                bytes_recvd = recvfrom(node->udp_sock_fd, (char *)recv_buffer, 
                            MAX_PACKET_BUFFER_SIZE, 0,
                            (struct sockaddr *)&sender_addr,
                            &addr_len);
                
                _pkt_receive(node, recv_buffer, bytes_recvd);
            }
            
        } ITERATE_GLTHREAD_END(&topo->node_list, curr);
    }
    return NULL;
}


extern void
network_start_pkt_receiver_thread(void){

    pthread_attr_t attr;
    static pthread_t recv_pkt_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&recv_pkt_thread, &attr, 
                    _network_start_pkt_receiver_thread, 
                    (void *)topo);
}

void comm_mem_init(){

    MM_REG_STRUCT(0, ev_dis_pkt_data_t);
}