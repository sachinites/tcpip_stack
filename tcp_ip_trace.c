#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tcp_public.h"

#define TCP_PRINT_BUFFER_SIZE   2048
static char tcp_print_buffer[TCP_PRINT_BUFFER_SIZE];
static char string_buffer[32];

static void init_tcp_print_buffer(){
    memset(tcp_print_buffer, 0, sizeof(tcp_print_buffer));
}

static void init_string_buffer(){
    memset(string_buffer, 0, sizeof(string_buffer));
}

static int
append_no_of_tabs(char *buff, int n){

    /*Will Support Later if Required*/
    return 0;
    int i  = 0, rc = 0;
    for(; i < n; i++){
        rc += sprintf(buff + rc, "\t");
    }
    return rc;
}

static char *
string_ethernet_hdr_type(unsigned short type){

    init_string_buffer();
    switch(type){

        case ETH_IP:
            strncpy(string_buffer, "ETH_IP", strlen("ETH_IP"));
            break;
        case ARP_MSG:
            strncpy(string_buffer, "ARP_MSG", strlen("ARP_MSG"));
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
            strncpy(string_buffer, "DDCP_MSG_TYPE_FLOOD_QUERY", strlen("DDCP_MSG_TYPE_FLOOD_QUERY"));
            break;
        default:
            return NULL;
    }
    return string_buffer;
}

static char *
string_arp_hdr_type(int type){

    init_string_buffer();
    switch(type){
        case ARP_BROAD_REQ:
            strncpy(string_buffer, "ARP_BROAD_REQ", strlen("ARP_BROAD_REQ"));
            break;
        case ARP_REPLY:
            strncpy(string_buffer, "ARP_REPLY", strlen("ARP_REPLY"));
            break;
        default:
            ;
    }
    return string_buffer;
}

static char *
string_ip_hdr_protocol_val(uint8_t type){

    init_string_buffer();
    switch(type){

        case ICMP_PRO:
            strncpy(string_buffer, "ICMP_PRO", strlen("ICMP_PRO"));
            break;
        case DDCP_MSG_TYPE_UCAST_REPLY:
            strncpy(string_buffer, "DDCP_MSG_TYPE_UCAST_REPLY" , strlen("DDCP_MSG_TYPE_UCAST_REPLY"));
            break;
        default:
            return NULL;
    }
    return string_buffer;
}

static int
tcp_dump_appln_hdr(char *buff, char *appln_data, uint32_t pkt_size, int tab_count){

    return 0;
}

static int
tcp_dump_ip_hdr(char *buff, ip_hdr_t *ip_hdr, uint32_t pkt_size, int tab_count){

     int rc = 0;
     char ip1[16];
     char ip2[16];

     rc = append_no_of_tabs(buff, tab_count); 

     tcp_ip_covert_ip_n_to_p(ip_hdr->src_ip, ip1);
     tcp_ip_covert_ip_n_to_p(ip_hdr->dst_ip, ip2);

     rc +=  sprintf(buff + rc, "\n-IP Hdr --------\n");
     rc +=  sprintf(buff + rc, "\tversion    : %u\n"
                      "\tihl     : %u\n"
                      "\ttos     : %d\n"
                      "\ttotal_length : %d\n"
                      "\tttl      : %d\n"
                      "\tprotocol : %s\n"
                      "\tsrc_ip   : %s\n"
                      "\tdst_ip   : %s",
                      ip_hdr->version,
                      ip_hdr->ihl,
                      ip_hdr->tos,
                      IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr),
                      ip_hdr->ttl,
                      string_ip_hdr_protocol_val(ip_hdr->protocol),
                      ip1, ip2);

    switch(ip_hdr->protocol){

        case ICMP_PRO:
            rc += tcp_dump_appln_hdr(buff + rc, INCREMENT_IPHDR(ip_hdr), 
                    IP_HDR_PAYLOAD_SIZE(ip_hdr), tab_count + 1);
            break;
        default:
            ;
    }
    return rc;
}

static int
tcp_dump_arp_hdr(char *buff, arp_hdr_t *arp_hdr, 
                  uint32_t pkt_size, int tab_count){

    int rc = 0;
    rc = append_no_of_tabs(buff, tab_count);
    rc += sprintf(buff, "\n-ARP Hdr --------\n");
    rc += sprintf(buff + rc, "\thw_type : %d\n", arp_hdr->hw_type);
    rc += sprintf(buff + rc, "\tproto_type : %0x\n", arp_hdr->proto_type);
    rc += sprintf(buff + rc, "\thw_addr_len : %d\n", arp_hdr->proto_addr_len);
    rc += sprintf(buff + rc, "\top_code : %s\n", string_arp_hdr_type(arp_hdr->op_code));
    rc += sprintf(buff + rc, "\tsrc mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->src_mac.mac[0],
            arp_hdr->src_mac.mac[1],
            arp_hdr->src_mac.mac[2],
            arp_hdr->src_mac.mac[3],
            arp_hdr->src_mac.mac[4],
            arp_hdr->src_mac.mac[5]);
    rc += sprintf(buff + rc, "\tsrc ip : %s\n", 
            tcp_ip_covert_ip_n_to_p(arp_hdr->src_ip, 0));
    rc += sprintf(buff + rc, "\tdst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->dst_mac.mac[0],
            arp_hdr->dst_mac.mac[1],
            arp_hdr->dst_mac.mac[2],
            arp_hdr->dst_mac.mac[3],
            arp_hdr->dst_mac.mac[4],
            arp_hdr->dst_mac.mac[5]);
    rc += sprintf(buff + rc, "\tdst ip : %s",
            tcp_ip_covert_ip_n_to_p(arp_hdr->dst_ip, 0));
    return rc;
}

static int
tcp_dump_ethernet_hdr(char *buff, ethernet_hdr_t *eth_hdr, 
                        uint32_t pkt_size, int tab_count){

    int rc = 0;
    uint32_t payload_size = pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth_hdr) \
                            - ETH_FCS_SIZE;

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    rc = append_no_of_tabs(buff, tab_count);

    rc +=  sprintf(buff + rc, "\n-Ethernet Hdr --------\n");
    rc += sprintf(buff + rc, "\tDst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n"
            "\tSrc Mac : %02x:%02x:%02x:%02x:%02x:%02x \n"
            "\tType : %-4s\n\tVlan : %-4d\n\tFCS : %-6d\n\tPayload Size = %u",
            eth_hdr->dst_mac.mac[0],
            eth_hdr->dst_mac.mac[1],
            eth_hdr->dst_mac.mac[2],
            eth_hdr->dst_mac.mac[3],
            eth_hdr->dst_mac.mac[4],
            eth_hdr->dst_mac.mac[5],

            eth_hdr->src_mac.mac[0],
            eth_hdr->src_mac.mac[1],
            eth_hdr->src_mac.mac[2],
            eth_hdr->src_mac.mac[3],
            eth_hdr->src_mac.mac[4],
            eth_hdr->src_mac.mac[5],

            string_ethernet_hdr_type(eth_hdr->type),

            vlan_8021q_hdr ? GET_802_1Q_VLAN_ID(vlan_8021q_hdr) : 0,

            vlan_8021q_hdr ? VLAN_ETH_FCS(eth_hdr, payload_size) : \
                ETH_FCS(eth_hdr, payload_size) , 
            
            payload_size);

    switch(eth_hdr->type){

        case ETH_IP:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                     payload_size, tab_count + 1);
            break;
        case ARP_MSG:
            rc += tcp_dump_arp_hdr(buff + rc,
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                    payload_size, tab_count + 1);
            break;
        default:
            ;
    }
    return rc;
}

void
tcp_dump(int sock_fd, 
         char *pkt, uint32_t pkt_size, 
         hdr_type_t hdr_type){

    int rc = 0;
    init_tcp_print_buffer();

    rc += sprintf(tcp_print_buffer + rc, 
            "\n===========Pkt Contents Begin================\n");

    switch(hdr_type){

        case ETH_HDR:
            rc += tcp_dump_ethernet_hdr(tcp_print_buffer + rc, 
                (ethernet_hdr_t *)pkt, pkt_size, 0);
            break;
        case IP_HDR:
            rc += tcp_dump_ip_hdr(tcp_print_buffer + rc, 
                (ip_hdr_t *)pkt, pkt_size, 0);
            break;
        default:
            ;
    }

    rc += sprintf(tcp_print_buffer + rc, 
            "\n===========Pkt Contents Ends================\n");

    if(rc <= TCP_PRINT_BUFFER_SIZE){
        write(sock_fd, tcp_print_buffer, rc);
    }
}
