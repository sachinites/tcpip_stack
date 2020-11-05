/* This file is a pkt generator to the TCP/IP
 * stack infrastructure . You just need to set the value of
 * below 3 constants, recompile and run this program. This program
 * is a separate executable and is not part if TCP/IP stack framework.
 * To compile this program, simply run Makefile of the TCP/IP Stack.
 * To run this program : ./pkt_gen.exe
 * */

#include <unistd.h>
#include <netinet/in.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h> /*for struct hostent*/
#include "tcp_public.h"


/* Set below three params as per the topology you are running. You
 * need not change anything in this program below (except the while(1)
 * loop in the end if you dont want to inject traffic indefinitely) as
 * long as you are sending pure IP traffic*/

/* Usage : Suppose you want to send the IP traffic from
 * Node S to node D, then set the below constants as follows */
#define SRC_NODE_NAME			"R1"
#define INGRESS_INTF_NAME       "eth7"      /*Specify Any existing interface of the node S.*/ 
#define DEST_IP_ADDR            "122.1.1.3" /*Destination IP Address of the Remote node D of the topology*/
#define PKTS_PER_SECOND			100			/* send 10 pkts per second, you can change it  */

extern pkt_q_t recvr_pkt_q;
extern graph_t *topo;

static char send_buffer[MAX_PACKET_BUFFER_SIZE];

void
pkt_gen(char *src_node_name,
		char *ingress_intf_name,
		char *dest_ip_addr){

    uint32_t n_pkts_send = 0;

	if (!src_node_name) 
		src_node_name = SRC_NODE_NAME;
	else if (!ingress_intf_name)
		ingress_intf_name = INGRESS_INTF_NAME;
	else if (!dest_ip_addr)
		dest_ip_addr = DEST_IP_ADDR;
		
    memset(send_buffer, 0, MAX_PACKET_BUFFER_SIZE);

    /*Prepare pseudo ethernet hdr*/
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(send_buffer);

    /*Dont bother about MAC addresses, just fill them with broadcast mac*/
    layer2_fill_with_broadcast_mac(eth_hdr->src_mac.mac);
    layer2_fill_with_broadcast_mac(eth_hdr->dst_mac.mac);

    eth_hdr->type = ETH_IP;
    SET_COMMON_ETH_FCS(eth_hdr, 20, 0);

    /*Prepare pseudo IP hdr, Just set Dest ip and protocol number*/
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(eth_hdr->payload);
    initialize_ip_hdr(ip_hdr);
    ip_hdr->protocol = ICMP_PRO;
    ip_hdr->dst_ip = tcp_ip_covert_ip_p_to_n(dest_ip_addr);

    uint32_t total_data_size = ETH_HDR_SIZE_EXCL_PAYLOAD + 20;

	ev_dis_pkt_data_t *ev_dis_pkt_data = NULL;

	node_t *node = get_node_by_node_name(topo, src_node_name);
	if(!node) return;

	interface_t *intf = get_node_if_by_name(node, ingress_intf_name);
	if(!intf) return;
 	
    while(1){

		ev_dis_pkt_data = calloc(1, sizeof(ev_dis_pkt_data_t));

		ev_dis_pkt_data->recv_node = node;
		ev_dis_pkt_data->recv_intf = intf;
		ev_dis_pkt_data->pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);
		memcpy(ev_dis_pkt_data->pkt, (char *)eth_hdr, total_data_size);
		ev_dis_pkt_data->pkt_size = total_data_size;

		pkt_q_enqueue(&recvr_pkt_q, (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
		printf("No of pkt sent = %u\n", n_pkts_send++);
        usleep(1000000/PKTS_PER_SECOND); /*100 msec, i.e. 10pkts per sec*/
    }
}

