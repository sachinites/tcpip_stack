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
 *Interface
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
#include <poll.h>
#include <errno.h>
#include <rte_ethdev.h>
#include "router_init.h"
#include "datapath/dp_uapi.h"
#include "datapath/dp_utils.h"

extern graph_t *topo;

extern void
network_start_pkt_receiver_thread(void);

extern void node_init_udp_socket(node_t *node);

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
        cprintf("Socket Creation Failed for node %s\n", node->node_name);
        return;   
    }

    struct sockaddr_in node_addr;
    node_addr.sin_family      = AF_INET;
    node_addr.sin_port        = node->udp_port_number;
    node_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock_fd, (struct sockaddr *)&node_addr, sizeof(struct sockaddr)) == -1) {
        cprintf("Error : socket bind failed for Node %s, errno = %d\n", node->node_name, errno);
        return;
    }

    node->udp_sock_fd = udp_sock_fd;
}

static void
_pkt_receive(dp_ctx_t *dp_ctx, 
            c_string pkt_with_aux_data, 
            uint32_t pkt_size){

    ev_dis_pkt_data_t *ev_dis_pkt_data;
    uint32_t ifindex = *(uint32_t *)pkt_with_aux_data;

    const uint16_t aux_data_size = sizeof (uint32_t);

    ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC2(0, 1, ev_dis_pkt_data_t);

    ev_dis_pkt_data->ifindex = ifindex;
    ev_dis_pkt_data->pkt = (unsigned char *)XCALLOC_BUFF(0, pkt_size - aux_data_size);

    memcpy(ev_dis_pkt_data->pkt, 
           pkt_with_aux_data + aux_data_size, 
           pkt_size - aux_data_size);
           
    ev_dis_pkt_data->pkt_size = pkt_size - aux_data_size;

	pkt_q_enqueue(EV_DP(dp_ctx), 
                  DP_PKT_Q(dp_ctx),
                  (char *)ev_dis_pkt_data,
                  sizeof(ev_dis_pkt_data_t));
}

static char recv_buffer[MAX_PACKET_BUFFER_SIZE];

static void *
_network_start_pkt_receiver_thread(void *arg){

    node_t *node;
    glthread_t *curr;
    int bytes_recvd = 0;
    int nfds = 0;
    int poll_idx = 0;
    graph_t *topo = (graph_t *)arg;
    struct pollfd *pollfds = NULL;
    node_t **poll_nodes = NULL;
    socklen_t addr_len = sizeof(struct sockaddr);
    struct sockaddr_in sender_addr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        if (node->udp_sock_fd)
            nfds++;

    } ITERATE_GLTHREAD_END(&topo->node_list, curr);

    if (!nfds)
        return NULL;

    pollfds = (struct pollfd *)calloc(nfds, sizeof(struct pollfd));
    poll_nodes = (node_t **)calloc(nfds, sizeof(node_t *));

    if (!pollfds || !poll_nodes) {
        free(pollfds);
        free(poll_nodes);
        return NULL;
    }

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);

        if (!node->udp_sock_fd)
            continue;

        pollfds[poll_idx].fd = node->udp_sock_fd;
        pollfds[poll_idx].events = POLLIN;
        poll_nodes[poll_idx] = node;
        poll_idx++;

    } ITERATE_GLTHREAD_END(&topo->node_list, curr);

    while (1) {

        int rc = poll(pollfds, nfds, -1);

        if (rc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        for (poll_idx = 0; poll_idx < nfds; poll_idx++) {

            if (!(pollfds[poll_idx].revents & POLLIN))
                continue;

            node = poll_nodes[poll_idx];

            bytes_recvd = recvfrom(node->udp_sock_fd, (char *)recv_buffer,
                        MAX_PACKET_BUFFER_SIZE, 0,
                        (struct sockaddr *)&sender_addr,
                        &addr_len);

            if (bytes_recvd > 0)
                _pkt_receive(node->dp_ctx, recv_buffer, bytes_recvd);
        }
    }

    free(pollfds);
    free(poll_nodes);
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

