/* This file is a pkt generator to the TCP/IP
 * stack infrastructure . You just need to set the value of
 * below 3 constants, recompile and run this program. This program
 * is a separate executable and is not part if TCP/IP stack framework.
 * To compile this program, simply run Makefile of the TCP/IP Stack.
 * To run this program : ./pkt_gen.exe
 * */

/* Usage : Suppose you want to send the IP traffic from
 * Node S to node D, then set the below constants as follows */
#define SRC_NODE_UDP_PORT_NO    40000       /*UDP port no of node S, use 'show topology' cmd to know the udp port numbers*/
#define INGRESS_INTF_NAME       "eth7"      /*Specify Any existing interface of the node S.*/ 
#define DEST_IP_ADDR            "122.1.1.2" /*Destination IP Address of the Remote node D of the topology*/


/* Set above three params as per the topology you are running. You
 * need not change anything in this program below (except the while(1)
 * loop in the end if you dont want to inject traffic indefinitely) as
 * long as you are sending pure IP traffic*/

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h> /*for struct hostent*/
#include "tcp_public.h"

static char send_buffer[MAX_PACKET_BUFFER_SIZE];

static int
_send_pkt_out(int sock_fd, char *pkt_data, uint32_t pkt_size, 
        uint32_t dst_udp_port_no){

    int rc;
    struct sockaddr_in dest_addr;

    struct hostent *host = (struct hostent *) gethostbyname("127.0.0.1"); 
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = dst_udp_port_no;
    dest_addr.sin_addr = *((struct in_addr *)host->h_addr);

    rc = sendto(sock_fd, pkt_data, pkt_size, 0, 
            (struct sockaddr *)&dest_addr, sizeof(struct sockaddr));

    return rc;
}


int
main(int argc, char **argv){

    uint32_t n_pkts_send = 0;

    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    
    if(udp_sock_fd == -1){
        printf("Socket Creation Failed, errno = %d\n", errno);
        return 0;
    }

    struct sockaddr_in node_addr;
    node_addr.sin_family      = AF_INET;
    node_addr.sin_port        = 0;
    node_addr.sin_addr.s_addr = INADDR_ANY;

#if 0
    if (bind(udp_sock_fd, (struct sockaddr *)&node_addr, 
        sizeof(struct sockaddr)) == -1) {
        printf("Error : socket bind failed, errno = %d\n", errno);
        return 0;
    }
#endif

    memset(send_buffer, 0, MAX_PACKET_BUFFER_SIZE);
    strncpy(send_buffer, INGRESS_INTF_NAME, IF_NAME_SIZE);

    /*Prepare ethernet hdr*/
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(send_buffer + IF_NAME_SIZE);
    /*Dont bother about MAC addresses, just fill them with broadcast mac*/
    layer2_fill_with_broadcast_mac(eth_hdr->src_mac.mac);
    layer2_fill_with_broadcast_mac(eth_hdr->dst_mac.mac);

    eth_hdr->type = ETH_IP;
    SET_COMMON_ETH_FCS(eth_hdr, 20, 0);

    /*Prepare IP hdr, Just set Dest ip and protocol number*/
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(eth_hdr->payload);
    initialize_ip_hdr(ip_hdr);
    ip_hdr->protocol = ICMP_PRO;
    ip_hdr->dst_ip = tcp_ip_covert_ip_p_to_n(DEST_IP_ADDR);

    uint32_t total_data_size = ETH_HDR_SIZE_EXCL_PAYLOAD + 
                               20 +
                               IF_NAME_SIZE;
    int rc = 0 ;
    while(1){
        rc = _send_pkt_out(udp_sock_fd, send_buffer, 
                total_data_size, SRC_NODE_UDP_PORT_NO);
                n_pkts_send++;
        printf("No of bytes sent = %d, pkt no = %u\n", rc, n_pkts_send);
        sleep(1);
    }
    close(udp_sock_fd);
    return 0;
}

