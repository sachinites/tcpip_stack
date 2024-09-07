#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include "tcp_public.h"

extern graph_t *topo;
static int
tcp_dump_gre_hdr(char *buff, 
                        gre_hdr_t *gre_hdr,
                        pkt_size_t pkt_size);

static c_string
string_ethernet_hdr_type(unsigned short type, char *string_buffer){

    c_string proto_str = NULL;

    switch(type){

        case ETH_IP:
            string_copy((char *)string_buffer, "ETH_IP", strlen("ETH_IP"));
            break;
        case PROTO_ARP:
            string_copy((char *)string_buffer, "ARP_MSG", strlen("ARP_MSG"));
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
            string_copy((char *)string_buffer, "DDCP_MSG_TYPE_FLOOD_QUERY", 
                strlen("DDCP_MSG_TYPE_FLOOD_QUERY"));
            break;
		case NMP_HELLO_MSG_CODE:
			string_copy((char *)string_buffer, "NMP_HELLO_MSG_CODE",
				strlen("NMP_HELLO_MSG_CODE"));
			break;
        default:
            sprintf((char *)string_buffer, "L2 Proto : %hu", type);
            break;
    }
    return string_buffer;
}

static c_string
string_arp_hdr_type(int type,  char *string_buffer){

    switch(type){
        case ARP_BROAD_REQ:
            string_copy((char *)string_buffer, "ARP_BROAD_REQ", strlen("ARP_BROAD_REQ"));
            break;
        case ARP_REPLY:
            string_copy((char *)string_buffer, "ARP_REPLY", strlen("ARP_REPLY"));
            break;
        default:
            ;
    }
    return string_buffer;
}

static c_string
string_ip_hdr_protocol_val(uint16_t type,   c_string string_buffer){

    switch(type){

        case ICMP_PROTO:
            string_copy((char *)string_buffer, "ICMP_PROTO", strlen("ICMP_PROTO"));
            break;
        case UDP_PROTO:
             string_copy((char *)string_buffer, "UDP_PROTO", strlen("UDP_PROTO"));
             break;
        case TCP_PROTO:
             string_copy((char *)string_buffer, "TCP_PROTO", strlen("TCP_PROTO"));
             break;       
        case GRE_PROTO:
             string_copy((char *)string_buffer, "GRE_PROTO", strlen("GRE_PROTO"));
             break;      
        case DDCP_MSG_TYPE_UCAST_REPLY:
            string_copy((char *)string_buffer, "DDCP_MSG_TYPE_UCAST_REPLY" , 
                strlen("DDCP_MSG_TYPE_UCAST_REPLY"));
            break;
        default:
            return NULL;
    }
    return string_buffer;
}


static int
tcp_dump_appln_hdr_protocol_icmp(c_string buff, c_string appln_data, uint32_t pkt_size){

    return 0;
}

static int
tcp_dump_ip_hdr(c_string buff, ip_hdr_t *ip_hdr, pkt_size_t pkt_size){

     int rc = 0;
     byte ip1[16];
     byte ip2[16];
     byte string_buffer[32];
     pkt_block_t *pkt_block;

     tcp_ip_covert_ip_n_to_p(ip_hdr->src_ip, ip1);
     tcp_ip_covert_ip_n_to_p(ip_hdr->dst_ip, ip2);

     rc +=  sprintf((char *)(buff + rc), "IP Hdr : ");
     rc +=  sprintf((char *)(buff + rc), "TL: %dB PRO: %s %s -> %s ttl: %d\n", 
                        IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr),
                      string_ip_hdr_protocol_val(ip_hdr->protocol, string_buffer),
                      ip1, ip2, ip_hdr->ttl);

    switch(ip_hdr->protocol){

        case ICMP_PROTO:
            rc += tcp_dump_appln_hdr_protocol_icmp(
                        buff + rc,
                        (c_string)INCREMENT_IPHDR(ip_hdr), 
                        IP_HDR_PAYLOAD_SIZE(ip_hdr));
            break;
        case UDP_PROTO:
            rc += tcp_dump_transport_udp_protocol(
                        buff + rc,
                        (udp_hdr_t *)(INCREMENT_IPHDR(ip_hdr)), 
                        IP_HDR_PAYLOAD_SIZE(ip_hdr));
            break;            
        break;
        case TCP_PROTO:
        break;
        case GRE_PROTO:
            rc += tcp_dump_gre_hdr(buff + rc, 
                        (gre_hdr_t *)INCREMENT_IPHDR(ip_hdr), 
                        IP_HDR_PAYLOAD_SIZE(ip_hdr));
            break;
        default:
            pkt_block = pkt_block_get_new((uint8_t *)INCREMENT_IPHDR(ip_hdr), 
                                    (pkt_size_t )IP_HDR_PAYLOAD_SIZE(ip_hdr));
            pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);
            pkt_block_reference(pkt_block);

			rc += nfc_pkt_trace_invoke_notif_to_sbscribers(
					ip_hdr->protocol,
					pkt_block,
					buff + rc);	
            XFREE(pkt_block);
            break;
            ;
    }
    return rc;
}

static int
tcp_dump_arp_hdr(c_string buff, arp_hdr_t *arp_hdr, 
                  uint32_t pkt_size){

    int rc = 0;
    byte ip1[16];
    byte ip2[16];
    byte string_buffer[48];

    rc +=  sprintf((char *)buff, "ARP Hdr : ");
    rc += sprintf((char *)buff + rc, "Arp Type: %s %02x:%02x:%02x:%02x:%02x:%02x -> "
            "%02x:%02x:%02x:%02x:%02x:%02x %s -> %s\n",
            string_arp_hdr_type(arp_hdr->op_code, (char *)string_buffer),
            arp_hdr->src_mac.mac[0],
            arp_hdr->src_mac.mac[1],
            arp_hdr->src_mac.mac[2],
            arp_hdr->src_mac.mac[3],
            arp_hdr->src_mac.mac[4],
            arp_hdr->src_mac.mac[5],

            arp_hdr->dst_mac.mac[0],
            arp_hdr->dst_mac.mac[1],
            arp_hdr->dst_mac.mac[2],
            arp_hdr->dst_mac.mac[3],
            arp_hdr->dst_mac.mac[4],
            arp_hdr->dst_mac.mac[5],

            tcp_ip_covert_ip_n_to_p(arp_hdr->src_ip, ip1),
            tcp_ip_covert_ip_n_to_p(arp_hdr->dst_ip, ip2));
    return rc;
}

static int
tcp_dump_ethernet_hdr(char *buff, 
                        ethernet_hdr_t *eth_hdr, 
                        pkt_size_t pkt_size){

    int rc = 0;
    pkt_block_t *pkt_block;
     char string_buffer[32];

    vlan_ethernet_hdr_t *vlan_eth_hdr = NULL;

    uint32_t payload_size = pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth_hdr);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(eth_hdr);

    if(vlan_8021q_hdr){
        vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;
    }

    unsigned short type = vlan_8021q_hdr ? vlan_eth_hdr->type :\
                            eth_hdr->type;

    rc += sprintf(buff + rc, "Eth hdr : ");
    rc += sprintf(buff + rc, "%02x:%02x:%02x:%02x:%02x:%02x -> "
                        "%02x:%02x:%02x:%02x:%02x:%02x %-4s Vlan: %d PL: %dB\n",
            eth_hdr->src_mac.mac[0],
            eth_hdr->src_mac.mac[1],
            eth_hdr->src_mac.mac[2],
            eth_hdr->src_mac.mac[3],
            eth_hdr->src_mac.mac[4],
            eth_hdr->src_mac.mac[5],

            eth_hdr->dst_mac.mac[0],
            eth_hdr->dst_mac.mac[1],
            eth_hdr->dst_mac.mac[2],
            eth_hdr->dst_mac.mac[3],
            eth_hdr->dst_mac.mac[4],
            eth_hdr->dst_mac.mac[5],

            string_ethernet_hdr_type(type, string_buffer),
            vlan_8021q_hdr ? GET_802_1Q_VLAN_ID(vlan_8021q_hdr) : 0,
            payload_size);

    switch(type){

        case ETH_IP:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                     payload_size);
            break;
        case PROTO_ARP:
            rc += tcp_dump_arp_hdr(buff + rc,
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                    payload_size);
            break;
        default:
            pkt_block = pkt_block_get_new(
                                            (uint8_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                                           (pkt_size_t)payload_size);
            pkt_block_set_starting_hdr_type(pkt_block, MISC_APP_HDR);
            pkt_block_reference(pkt_block);

            rc += nfc_pkt_trace_invoke_notif_to_sbscribers(
					type,
					pkt_block,
					buff + rc);
            XFREE(pkt_block);
            break;
    }
    return rc;
}

int
tcp_dump_gre_hdr(char *buff, 
                        gre_hdr_t *gre_hdr,
                        pkt_size_t pkt_size){

    int rc = 0;
     rc += sprintf(buff + rc, "GRE Encap: %s\n", proto_name_str(gre_hdr->protocol_type));

    switch (gre_hdr->protocol_type) {

        case ETH_IP:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)(gre_hdr + 1), 
                    pkt_size - sizeof(gre_hdr_t));
            break;

        case PROTO_GRE_ENCAP_ETHERNET:
            rc += tcp_dump_ethernet_hdr(buff + rc, 
                    (ethernet_hdr_t *)(gre_hdr + 1), 
                    pkt_size - sizeof(gre_hdr_t));
            break;

        default:
            assert(0);
    }
    return rc;
}

static void 
tcp_write_data(int sock_fd, 
               FILE *log_file1, FILE *log_file2, 
               char *out_buff, uint32_t buff_size){

    int rc; 
    char error_msg[64];

    assert(out_buff);

#if 0
    if(buff_size > TCP_PRINT_BUFFER_SIZE){
        memset(error_msg, 0, sizeof(error_msg));
        rc  = sprintf(error_msg , "Error : Insufficient size TCP Print Buffer\n");
        assert(rc < sizeof(error_msg));
        fwrite(error_msg, sizeof(char), rc, log_file1);
        fwrite(error_msg, sizeof(char), rc, log_file2);
        write(sock_fd, error_msg, rc);
        return;
    }
#endif

    if(log_file1){
        rc = fwrite(out_buff, sizeof(char), buff_size, log_file1);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file1);
    }

    if(log_file2){
        rc = fwrite(out_buff, sizeof(char), buff_size, log_file2);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file2);
    }
    
    if(sock_fd == -1)
        return; 

    write(sock_fd, out_buff, buff_size);
}


static void
tcp_dump(int sock_fd, 
         FILE *log_file1,
         FILE *log_file2,
         pkt_block_t *pkt_block,
         hdr_type_t hdr_type,
         c_string out_buff, 
         uint32_t write_OFFset,
         uint32_t out_buff_size){

    int rc = 0;
    uint8_t *pkt = NULL;
    pkt_size_t pkt_size;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(hdr_type){

        case ETH_HDR:
            rc = tcp_dump_ethernet_hdr(out_buff + write_OFFset, 
                (ethernet_hdr_t *)pkt, pkt_size);
            break;
        case IP_HDR:
            rc = tcp_dump_ip_hdr(out_buff + write_OFFset, 
                (ip_hdr_t *)pkt, pkt_size);
            break;
        case GRE_HDR:
            rc = tcp_dump_gre_hdr (out_buff + write_OFFset, 
                (gre_hdr_t *)pkt, pkt_size);
            break;
        default:
			rc = nfc_pkt_trace_invoke_notif_to_sbscribers(
					hdr_type,
                    pkt_block,
					out_buff + write_OFFset);
            break;
    }

    if(!rc){
        return;
    }

    tcp_write_data(sock_fd, log_file1, log_file2, out_buff, write_OFFset + rc);
}

void
tcp_dump_recv_logger(
              node_t *node,
              Interface *intf,
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type){

    int rc = 0 ;
    acl_action_t acl_action;

    if(node->log_info.all || 
        node->log_info.recv ||
        intf->log_info.recv){

        int sock_fd = (topo->gstdout && (node->log_info.is_stdout || 
                        intf->log_info.is_stdout)) ? STDOUT_FILENO : -1;
        
        FILE *log_file1 = (node->log_info.all || node->log_info.recv) ?
                node->log_info.log_file : NULL;
        FILE *log_file2 = (intf->log_info.recv || intf->log_info.all) ?
                intf->log_info.log_file : NULL;

        if (log_file1 && 
             node->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (node->log_info.acc_lst_filter, pkt_block);
           if (acl_action == ACL_DENY) log_file1 = NULL;
        }

        if (log_file2 && 
             intf->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (intf->log_info.acc_lst_filter, pkt_block);
           if (acl_action == ACL_DENY) log_file2 = NULL;
        }

        if(sock_fd == -1 && 
            !log_file1 && !log_file2){
            return;
        }
   
        rc = sprintf (TCP_GET_NODE_RECV_LOG_BUFFER(node), 
                        "\n%s(%s) <-- \n", 
                        node->node_name, intf->if_name.c_str());

        tcp_dump(sock_fd,                  /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                pkt_block,            /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 TCP_GET_NODE_RECV_LOG_BUFFER(node),    /*Buffer into which the formatted output 
                                              is to be written*/
                 rc,                       /*write OFFset*/
                 TCP_PRINT_BUFFER_SIZE - rc);   /*Buffer Max Size*/
    }
}

void
tcp_dump_l3_fwding_logger(node_t *node,
            c_string oif_name, c_string gw_ip){

    int rc = 0;

    if(!node->log_info.l3_fwd)
        return;

    int sock_fd = topo->gstdout && node->log_info.is_stdout ?
                    STDOUT_FILENO : -1 ;
    FILE *log_file1 = (node->log_info.all || node->log_info.l3_fwd) ?
             node->log_info.log_file : NULL;
     
    if(sock_fd == -1 && !log_file1)
        return;

    tcp_init_send_logging_buffer(node);
    
    rc = sprintf(TCP_GET_NODE_SEND_LOG_BUFFER(node), 
            "L3 Fwd : (%s)%s --> %s\n", 
            node->node_name, oif_name, gw_ip);

    tcp_write_data(sock_fd, log_file1, NULL, 
        TCP_GET_NODE_SEND_LOG_BUFFER(node), rc); 
}

void
tcp_dump_send_logger(node_t *node, Interface *intf,
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type){

    int rc = 0;
    acl_action_t acl_action;

    if(node->log_info.all || 
         node->log_info.send ||
         intf->log_info.send){

        int sock_fd = (topo->gstdout && (node->log_info.is_stdout || 
                        intf->log_info.is_stdout)) ? STDOUT_FILENO : -1;

        FILE *log_file1 = (node->log_info.all || node->log_info.send) ?
                node->log_info.log_file : NULL;
        FILE *log_file2 = (intf->log_info.send || intf->log_info.all) ? 
                intf->log_info.log_file : NULL;

        if (log_file1 && 
             node->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (node->log_info.acc_lst_filter, pkt_block);
           if (acl_action == ACL_DENY) log_file1 = NULL;
        }

        if (log_file2 && 
             intf->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (intf->log_info.acc_lst_filter, pkt_block);
           if (acl_action == ACL_DENY) log_file2 = NULL;
        }

        if(sock_fd == -1 && 
            !log_file1 && !log_file2){
            return;
        }

        tcp_init_send_logging_buffer(node);
        
        rc = sprintf(TCP_GET_NODE_SEND_LOG_BUFFER(node),
                "\n%s(%s) --> \n", 
                node->node_name, intf->if_name.c_str());

        tcp_dump(sock_fd,                  /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                 pkt_block,            /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 TCP_GET_NODE_SEND_LOG_BUFFER(node),    /*Buffer into which the formatted output is to be written*/
                 rc,                       /*write OFFset*/
                 TCP_PRINT_BUFFER_SIZE - rc);   /*Buffer Max Size*/
    }
}

static FILE *
initialize_node_log_file(node_t *node){

    char file_name[32];

    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s.txt", node->node_name);

    FILE *fptr = fopen(file_name, "w");

    if(!fptr){
        cprintf("Error : Could not open log file %s, errno = %d\n", 
            file_name, errno);
        return 0;
    }

    return fptr;
}

static FILE *
initialize_interface_log_file(Interface *intf){

    char file_name[64];

    memset(file_name, 0, sizeof(file_name));

    node_t *node = intf->att_node;

    sprintf(file_name, "logs/%s-%s.txt", node->node_name, intf->if_name.c_str());

    FILE *fptr = fopen(file_name, "w");

    if(!fptr){
        cprintf("Error : Could not open log file %s, errno = %d\n", 
            file_name, errno);
        return 0;
    }

    return fptr;
}

void
tcp_ip_init_node_log_info(node_t *node){

    log_t *log_info     = &node->log_info;
    log_info->all       = false;
    log_info->recv      = false;
    log_info->send      = false;
    log_info->is_stdout = false;
    log_info->l3_fwd    = false;
    log_info->log_file  = initialize_node_log_file(node); 
    log_info->acc_lst_filter = NULL;
}

void
tcp_ip_set_all_log_info_params(log_t *log_info, bool status){

    log_info->all    = status;
    log_info->recv   = status;
    log_info->send   = status;
    log_info->l3_fwd = status;
    /*User should explicitely enabled stdout*/
    //log_info->is_stdout = status;
}


void
tcp_ip_init_intf_log_info(Interface *intf){
    
    log_t *log_info     = &intf->log_info;
    log_info->all       = false;
    log_info->recv      = false;
    log_info->send      = false;
    log_info->is_stdout = false;
    log_info->log_file  = initialize_interface_log_file(intf);
    log_info->acc_lst_filter = NULL;
}

void
tcp_ip_de_init_intf_log_info(Interface *intf){
    
    log_t *log_info     = &intf->log_info;
    log_info->all       = false;
    log_info->recv      = false;
    log_info->send      = false;
    log_info->is_stdout = false;
    if (log_info->log_file) {
        close (log_info->log_file);
        log_info->log_file = NULL;
    }
    if ( log_info->acc_lst_filter ) {
        access_list_dereference(intf->att_node, log_info->acc_lst_filter);
        log_info->acc_lst_filter = NULL;
    }
}

static void display_expected_flag(param_t *param, Stack_t *tlv_stack){

    cprintf(" : all | no-all\n");
    cprintf(" : recv | no-recv\n");
    cprintf(" : send | no-send\n");
    cprintf(" : stdout | no-stdout\n");
    cprintf(" : l3-fwd | no-l3-fwd\n");
}

static int
validate_flag_values(stack_t *tlv_stack, c_string value){

    int k = 0;
    int len = strlen((const char *)value);

    if( (string_compare(value, "all",      k = strlen("all"))       ==   0   && k  == len)          || 
        (string_compare(value, "no-all",   k = strlen("no-all"))    ==   0   && k  == len)          ||
        (string_compare(value, "recv",     k = strlen("recv"))      ==   0   && k  == len)          ||
        (string_compare(value, "no-recv",  k = strlen("no-recv"))   ==   0   && k  == len)          ||
        (string_compare(value, "send",     k = strlen("send"))      ==   0   && k  == len)          ||
        (string_compare(value, "no-send",  k = strlen("no-send"))   ==   0   && k  == len)          ||
        (string_compare(value, "stdout",   k = strlen("stdout"))    ==   0   && k  == len)          ||
        (string_compare(value, "no-stdout",k = strlen("no-stdout")) ==   0   && k  == len)          ||
        (string_compare(value, "l3-fwd",   k = strlen("l3-fwd"))    ==   0   && k  == len)          ||
        (string_compare(value, "no-l3-fwd",k = strlen("no-l3-fwd")) ==   0   && k  == len)){
        return LEAF_VALIDATION_SUCCESS;
    }
    return LEAF_VALIDATION_FAILED;
}


void tcp_ip_show_log_status(node_t *node){

    int i = 0;
    Interface *intf;
    log_t *log_info = &node->log_info;
    
    cprintf("Log Status : Device : %s\n", node->node_name);

    cprintf("\tall     : %s\n", log_info->all ? "ON" : "OFF");
    cprintf("\trecv    : %s\n", log_info->recv ? "ON" : "OFF");
    cprintf("\tsend    : %s\n", log_info->send ? "ON" : "OFF");
    cprintf("\tstdout  : %s\n", log_info->is_stdout ? "ON" : "OFF");
    cprintf("\tl3_fwd  : %s\n", log_info->l3_fwd ? "ON" : "OFF");
    cprintf ("\taccess list filter : %s\n", 
            log_info->acc_lst_filter->name ? log_info->acc_lst_filter->name : "none");

    for( ; i < MAX_INTF_PER_NODE; i++){
        intf = node->intf[i];
        if(!intf) continue;

        log_info = &intf->log_info;
        cprintf("\tLog Status : %s(%s)\n", intf->if_name.c_str(), intf->is_up ? "UP" : "DOWN");
        cprintf("\t\tall     : %s\n", log_info->all ? "ON" : "OFF");
        cprintf("\t\trecv    : %s\n", log_info->recv ? "ON" : "OFF");
        cprintf("\t\tsend    : %s\n", log_info->send ? "ON" : "OFF");
        cprintf("\t\tstdout  : %s\n", log_info->is_stdout ? "ON" : "OFF");
        cprintf ("\t\taccess list filter : %s\n", 
            log_info->acc_lst_filter->name ? log_info->acc_lst_filter->name : "none");
    }

    cprintf ("\tDebug Logging Status:\n");

    tracer_t *tr = node->dptr;
    
    if (tracer_is_bit_set (tr, DARP | DARP_DET)) 
        cprintf ("\t  DARP     :     ON\n" );
    else 
        cprintf ("\t  DARP     :     OFF\n" );

    if (tracer_is_bit_set (tr, DL3FWD | DL3FWD_DET)) 
        cprintf ("\t  DL3FWD   :     ON\n" );
    else 
        cprintf ("\t  DL3FWD   :     OFF\n" );    

    if (tracer_is_bit_set (tr, DL2FWD | DL2FWD_DET)) 
        cprintf ("\t  DL2FWD   :     ON\n" );
    else 
        cprintf ("\t  DL2FWD   :     OFF\n" );        
    
    if (tracer_is_bit_set (tr, DRTM | DRTM_DET)) 
        cprintf ("\t  DRTM     :     ON\n" );
    else 
        cprintf ("\t  DRTM     :     OFF\n" );

    if (tracer_is_bit_set (tr, DACL | DACL_DET)) 
        cprintf ("\t  DACL     :     ON\n" );
    else 
        cprintf ("\t  DACL     :     OFF\n" );

    if (tracer_is_bit_set (tr, DIPC | DIPC_DET)) 
        cprintf ("\t  DIPC     :     ON\n" );
    else 
        cprintf ("\t  DIPC     :     OFF\n" );

    if (tracer_is_bit_set (tr, DINTF | DINTF_DET)) 
        cprintf ("\t  DINTF    :     ON\n" );
    else 
        cprintf ("\t  DINTF    :     OFF\n" );

    if (tracer_is_bit_set (tr, DFLOW | DFLOW_DET)) 
        cprintf ("\t  DFLOW    :     ON\n" );
    else 
        cprintf ("\t  DFLOW    :     OFF\n" );

    if (tracer_is_bit_set (tr, DTUNNEL | DTUNNEL_DET)) 
        cprintf ("\t  DTUN     :     ON\n" );
    else 
        cprintf ("\t  DTUN     :     OFF\n" );

    if (tracer_is_bit_set (tr, DL2SW | DL2SW_DET)) 
        cprintf ("\t  DL2SW    :     ON\n" );
    else 
        cprintf ("\t  DL2SW    :     OFF\n" );

    if (tracer_is_bit_set (tr, DTIMER | DTIMER_DET)) 
        cprintf ("\t  DTIMER   :     ON\n" );
    else 
        cprintf ("\t  DTIMER   :     OFF\n" );

    if (tracer_is_bit_set (tr, DALWAYS_FLUSH)) 
        cprintf ("\t  DALWAYS_FLUSH: ON\n" );
    else 
        cprintf ("\t  DALWAYS_FLUSH: OFF\n" );

    if (tracer_is_bit_set (tr, DERR)) 
        cprintf ("\t  DERR     :     ON\n" );
    else 
        cprintf ("\t  DERR     :     OFF\n" );    

    if (tracer_is_bit_set (tr, DALL_LOGGING))
        cprintf ("\t  DALL     :     ON\n" );
    else 
        cprintf ("\t  DALL     :     OFF\n" );
}

int traceoptions_handler(int cmdcode, 
        Stack_t *tlv_stack, 
        op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string if_name;
    uint32_t flags;
    Interface *intf;
    c_string flag_val;
    access_list_t *access_list;
    log_t *log_info = NULL;
    tlv_struct_t *tlv = NULL;
    c_string access_list_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "if-name"))
            if_name =  tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "flag-val"))
            flag_val = tlv->value;
         else if(parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
            access_list_name = tlv->value;
    }TLV_LOOP_END;

    switch(cmdcode){
        case CMDCODE_DEBUG_GLOBAL_STDOUT:
            topo->gstdout = true;
            break;
        case CMDCODE_DEBUG_GLOBAL_NO_STDOUT:
            topo->gstdout = false;
            break;
        case CMDCODE_DEBUG_LOGGING_PER_NODE:
        case CMDCODE_DEBUG_SHOW_LOG_STATUS:
            node =  node_get_node_by_name(topo, node_name);
            log_info = &node->log_info;
        break;
        case CMDCODE_DEBUG_LOGGING_PER_INTF:
            node =  node_get_node_by_name(topo, node_name);
            intf = node_get_intf_by_name(node,(const char *) if_name);
            if(!intf){
                cprintf("Error : No interface %s on Node %s\n", if_name, node_name);
                return -1;
            }
            log_info = &intf->log_info;
        break;

        case CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME:
        node = node_get_node_by_name(topo, node_name);
        access_list = access_list_lookup_by_name(node, access_list_name);
                if (!access_list)
                {
                    cprintf("Error : Access-list do not exist\n");
                    return -1;
                }
                log_info = &node->log_info;
        switch (enable_or_disable)
        {
        case CONFIG_ENABLE:
                if (log_info->acc_lst_filter && (log_info->acc_lst_filter != access_list))
                {
                    access_list_dereference(node, log_info->acc_lst_filter);
                    if (access_list_should_decompile(log_info->acc_lst_filter))
                    {
                        access_list_trigger_uninstall_job(node, log_info->acc_lst_filter, NULL);
                    }
                    log_info->acc_lst_filter = NULL;
                }
                log_info->acc_lst_filter = access_list;
                access_list_reference(log_info->acc_lst_filter);
                if (access_list_should_compile(log_info->acc_lst_filter))
                {
                    access_list_trigger_install_job(node, log_info->acc_lst_filter, NULL);
                }
                break;
        case CONFIG_DISABLE:
                if (!log_info->acc_lst_filter) {
                    return -1;
                }
                if (log_info->acc_lst_filter && (log_info->acc_lst_filter != access_list)) {
                    cprintf("Error : access-list is not configured\n");
                    return -1;
                }
                access_list_dereference (node, log_info->acc_lst_filter);
                if (access_list_should_decompile(log_info->acc_lst_filter))
                {
                    access_list_trigger_uninstall_job(node, log_info->acc_lst_filter, NULL);
                }
                 log_info->acc_lst_filter = NULL;
                break;
        }
        break;
        case CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME_INTF:
        node = node_get_node_by_name(topo, node_name);
        intf = node_get_intf_by_name(node, (const char *)if_name);
        if (!intf)
        {
                cprintf("Error : No interface %s on Node %s\n", if_name, node_name);
                return -1;
        }
        access_list = access_list_lookup_by_name(node, access_list_name);
        if (!access_list)
        {
                cprintf("Error : Access-list do not exist\n");
                return -1;
        }
        log_info = &intf->log_info;
        switch (enable_or_disable)
        {
        case CONFIG_ENABLE:
                if (log_info->acc_lst_filter && (log_info->acc_lst_filter != access_list))
                {
                    access_list_dereference(node, log_info->acc_lst_filter);
                    if (access_list_should_decompile(log_info->acc_lst_filter))
                    {
                        access_list_trigger_uninstall_job(node, log_info->acc_lst_filter, NULL);
                    }
                    log_info->acc_lst_filter = NULL;
                }
                log_info->acc_lst_filter = access_list;
                access_list_reference(log_info->acc_lst_filter);
                if (access_list_should_compile(log_info->acc_lst_filter))
                {
                    access_list_trigger_install_job(node, log_info->acc_lst_filter, NULL);
                }
                break;
        case CONFIG_DISABLE:
                if (!log_info->acc_lst_filter)
                {
                    return -1;
                }
                if (log_info->acc_lst_filter && (log_info->acc_lst_filter != access_list))
                {
                    cprintf("Error : access-list is not configured\n");
                    return -1;
                }
                access_list_dereference(node, log_info->acc_lst_filter);
                if (access_list_should_decompile(log_info->acc_lst_filter))
                {
                    access_list_trigger_uninstall_job(node, log_info->acc_lst_filter, NULL);
                }
                log_info->acc_lst_filter = NULL;
                break;
        }
        break;
        default:
            ;
    }

    if(cmdcode == CMDCODE_DEBUG_LOGGING_PER_NODE ||
            cmdcode == CMDCODE_DEBUG_LOGGING_PER_INTF){
        if(strcmp((const char *)flag_val, "all") == 0){
            tcp_ip_set_all_log_info_params(log_info, true);
        }
        else if(strcmp((const char *)flag_val, "no-all") == 0){
            tcp_ip_set_all_log_info_params(log_info, false);
            
            /*disable logging for all interfaces also*/
            if(cmdcode == CMDCODE_DEBUG_LOGGING_PER_NODE){
                int i = 0;
                Interface *intf;
                for(; i < MAX_INTF_PER_NODE; i++){
                    intf = node->intf[i];
                    if(!intf) continue;
                    tcp_ip_set_all_log_info_params(&intf->log_info, false);
                }
            }
        }
        else if(strcmp((const char *)flag_val, "recv") == 0){
            log_info->recv = true;
        }
        else if(strcmp((const char *)flag_val, "no-recv") == 0){
            log_info->recv = false;
        }
        else if(strcmp((const char *)flag_val, "send") == 0){
            log_info->send = true;
        }
        else if(strcmp((const char *)flag_val, "no-send") == 0){
            log_info->send = false;
        }
        else if(strcmp((const char *)flag_val, "stdout") == 0){
            log_info->is_stdout = true;
        }
        else if(strcmp((const char *)flag_val, "no-stdout") == 0){
            log_info->is_stdout = false;
        }
        else if(strcmp((const char *)flag_val, "l3-fwd") == 0){
            log_info->l3_fwd = true;
        }
        else if(strcmp((const char *)flag_val, "no-l3-fwd") == 0){
            log_info->l3_fwd = false;
        }
    }
    else if(cmdcode == CMDCODE_DEBUG_SHOW_LOG_STATUS){
        tcp_ip_show_log_status(node);
    }
    return 0;
}

static void
tcp_ip_build_node_traceoptions_cli(param_t *node_name_param){

    {
        static param_t traceoptions;
        init_param(&traceoptions, CMD, "traceoptions", 0, 0, INVALID, 0, "traceoptions");
        libcli_register_param(node_name_param, &traceoptions);
        {
            static param_t flag;
            init_param(&flag, CMD, "flag", 0, 0, INVALID, 0, "flag");
            libcli_register_param(&traceoptions, &flag);
            libcli_register_display_callback(&flag, display_expected_flag);
            {
                static param_t flag_val;
                init_param(&flag_val, LEAF, 0, traceoptions_handler, validate_flag_values, STRING, "flag-val", 
                        "<[no-]all | [no-]recv | [no-]send | [no-]stdout | [no-]l3-fwd>");
                libcli_register_param(&flag, &flag_val);
                libcli_param_recursive (&flag_val);
                libcli_set_param_cmd_code(&flag_val, CMDCODE_DEBUG_LOGGING_PER_NODE);
            }
        }
        {
            static param_t acl_filter;
            init_param(&acl_filter, CMD, "access-list", 0, 0, INVALID, 0, "access-list keyword");
            libcli_register_param(&traceoptions, &acl_filter);
            {
                static param_t acl_name;
                init_param(&acl_name, LEAF, 0, traceoptions_handler, NULL, STRING, "access-list-name", "Access-list name");
                libcli_register_param(&acl_filter, &acl_name);
                libcli_set_param_cmd_code(&acl_name, CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME);
            }
        }
    }
}

static void
tcp_ip_build_intf_traceoptions_cli(param_t *intf_name_param){

    {
        static param_t traceoptions;
        init_param(&traceoptions, CMD, "traceoptions", 0, 0, INVALID, 0, "traceoptions");
        libcli_register_param(intf_name_param, &traceoptions);
        {
            static param_t flag;
            init_param(&flag, CMD, "flag", 0, 0, INVALID, 0, "flag");
            libcli_register_param(&traceoptions, &flag);
            libcli_register_display_callback(&flag, display_expected_flag);
            {
                static param_t flag_val;
                init_param(&flag_val, LEAF, 0, traceoptions_handler, validate_flag_values, STRING, "flag-val", 
                    "<[no-]all | [no-]recv | [no-]send | [no-]stdout");
                libcli_register_param(&flag, &flag_val);
                libcli_param_recursive (&flag_val);
                libcli_set_param_cmd_code(&flag_val, CMDCODE_DEBUG_LOGGING_PER_INTF);
            }
        }
        {
            static param_t acl_filter;
            init_param(&acl_filter, CMD, "access-list", 0, 0, INVALID, 0, "access-list keyword");
            libcli_register_param(&traceoptions, &acl_filter);
            {
                static param_t acl_name;
                init_param(&acl_name, LEAF, 0, traceoptions_handler, NULL, STRING, "access-list-name", "Access-list name");
                libcli_register_param(&acl_filter, &acl_name);
                libcli_set_param_cmd_code(&acl_name, CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME_INTF);
            }
        }        
    }
}


/*CLI handlers*/
extern void tcp_ip_traceoptions_cli(param_t *node_name_param,
                                 param_t *intf_name_param){

    assert(!node_name_param || !intf_name_param);
    if(node_name_param){
        tcp_ip_build_node_traceoptions_cli(node_name_param);
    }
    if(intf_name_param){
        tcp_ip_build_intf_traceoptions_cli(intf_name_param);
    }
}

void
tcp_init_send_logging_buffer(node_t *node){

    memset(TCP_GET_NODE_SEND_LOG_BUFFER(node), 0, TCP_PRINT_BUFFER_SIZE);
}

char tlb[TCP_LOG_BUFFER_LEN];

void
init_tcp_logging(node_t *node) {

    unsigned char log_file_name[NODE_NAME_SIZE + 16];
    if (node->node_nw_prop.log_file) return;
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-log.txt", node->node_name);
    node->node_nw_prop.log_file = fopen(log_file_name, "w");
    assert (node->node_nw_prop.log_file);
}

void 
tcp_trace_internal(node_t *node,
			   Interface *interface, 
			   char *buff, const char *fn, int lineno) {

	byte lineno_str[16];
    return;
	fwrite(fn, sizeof(char), strlen(fn), NODE_LOG_FILE(node));
	memset(lineno_str, 0, sizeof(lineno_str));
	sprintf((char *)lineno_str, " (%u) :", lineno);
	fwrite(lineno_str, sizeof(char), strlen((const char *)lineno_str), NODE_LOG_FILE(node));	

	if (node) {
		fwrite(node->node_name, sizeof(char), strlen((const char *)node->node_name), NODE_LOG_FILE(node));
		fwrite(":", sizeof(char), 1, NODE_LOG_FILE(node));
	}
	if (interface) {
		fwrite(interface->if_name.c_str(), sizeof(char), strlen((const char *)interface->if_name.c_str()), NODE_LOG_FILE(node));
		fwrite(":", sizeof(char), 1, NODE_LOG_FILE(node));
	}
    fwrite(buff, sizeof(char), strlen(buff), NODE_LOG_FILE(node));
	fflush(NODE_LOG_FILE(node));
}

void
tcp_ip_refresh_tcp_log_file(node_t *node) {

    node->node_nw_prop.log_file = freopen(NULL, "w", NODE_LOG_FILE(node));
}

#define tcp_trace(node, intf, buff)	\
	tcp_trace_internal(node, intf, buff, __FUNCTION__, __LINE__);

void
tcp_ip_toggle_global_console_logging(void) {

    topo->gstdout  = ! topo->gstdout;

    if (topo->gstdout) {
        cprintf ("\nconsole logging enabled\n");
    }
    else {
        cprintf ("\nconsole logging disabled\n");
    }
}

void
variadic_sprintf (node_t *node, Interface *intf, const char *format, ...)
{
    va_list args;
    va_start(args, format);
   // vsprintf(node->logging_buffer, format, args);
    va_end(args);
}

static int 
tcp_ip_debug_handler (  int cmdcode, 
                                        Stack_t *tlv_stack, 
                                        op_mode enable_or_disable) {

    
   node_t *node;
   c_string node_name;
   tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case DALWAYS_FLUSH:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                tracer_enable_always_flush(node->dptr, true);
            break;
            case CONFIG_DISABLE:
                tracer_enable_always_flush(node->dptr, false);   
            break;
        }
        break;

        case DALL_LOGGING:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                tracer_enable_all_logging(node->dptr, true);
            break;
            case CONFIG_DISABLE:
                tracer_enable_all_logging(node->dptr, true);  
            break;
        }

    }
    /* Handle rest of the cmd codes */
    enable_or_disable == CONFIG_ENABLE ? \
        tracer_log_bit_set(node->dptr, cmdcode) : tracer_log_bit_unset(node->dptr, cmdcode);

    return 0;
}

/* Building debug cli tree */
static void 
libcli_register_param_detail (param_t *root, cmd_callback callback, int cmdcode) {

    param_t *detail = (param_t *)calloc (1, sizeof (param_t));
    init_param(detail, CMD, "detail", callback, 0, INVALID, 0, "detail");
    libcli_register_param(root, detail);
    libcli_set_param_cmd_code(detail, cmdcode);
    libcli_set_tail_config_batch_processing (detail);
}

void 
tcp_ip_build_debug_cli_tree (param_t *root) {

    {
        /* config node <node-name> [no] debug . . .*/
        static param_t debug;
        init_param(&debug, CMD, "debug", 0, 0, INVALID, 0, "debug");
        libcli_register_param(root, &debug);

        {
            /* config node <node-name> [no] debug all*/
            static param_t all;
            init_param(&all, CMD, "all", tcp_ip_debug_handler, 0, INVALID, 0, "all");
            libcli_register_param(&debug, &all);
            libcli_set_param_cmd_code(&all, DALL_LOGGING);
        }

        {
            /* config node <node-name> [no] debug arp [detail]*/
            static param_t arp;
            init_param(&arp, CMD, "arp", tcp_ip_debug_handler, 0, INVALID, 0, "arp");
            libcli_register_param(&debug, &arp);
            libcli_set_param_cmd_code(&arp, DARP);
            libcli_register_param_detail (&arp, tcp_ip_debug_handler, DARP_DET);
        }

        {
            /* config node <node-name> [no] debug l3fwd [detail]*/
            static param_t l3fwd;
            init_param(&l3fwd, CMD, "l3fwd", tcp_ip_debug_handler, 0, INVALID, 0, "Layer 3 Forwarding");
            libcli_register_param(&debug, &l3fwd);
            libcli_set_param_cmd_code(&l3fwd, DL3FWD);
            libcli_register_param_detail (&l3fwd, tcp_ip_debug_handler, DL3FWD_DET);
        }

        {
            /* config node <node-name> [no] debug l2fwd [detail]*/
            static param_t l2fwd;
            init_param(&l2fwd, CMD, "l2fwd", tcp_ip_debug_handler, 0, INVALID, 0, "Layer 2 Forwarding");
            libcli_register_param(&debug, &l2fwd);
            libcli_set_param_cmd_code(&l2fwd, DL3FWD);
            libcli_register_param_detail (&l2fwd, tcp_ip_debug_handler, DL2FWD_DET);
        }

        {
            /* config node <node-name> [no] debug rtm [detail]*/
            static param_t rtm;
            init_param(&rtm, CMD, "rtm", tcp_ip_debug_handler, 0, INVALID, 0, "Routing Table Manager");
            libcli_register_param(&debug, &rtm);
            libcli_set_param_cmd_code(&rtm, DRTM);
            libcli_register_param_detail (&rtm, tcp_ip_debug_handler, DRTM_DET);
        }

        {
            /* config node <node-name> [no] debug acl [detail]*/
            static param_t acl;
            init_param(&acl, CMD, "acl", tcp_ip_debug_handler, 0, INVALID, 0, "Access-List");
            libcli_register_param(&debug, &acl);
            libcli_set_param_cmd_code(&acl, DACL);
            libcli_register_param_detail (&acl, tcp_ip_debug_handler, DACL_DET);
        }

        {
            /* config node <node-name> [no] debug ipc [detail]*/
            static param_t ipc;
            init_param(&ipc, CMD, "ipc", tcp_ip_debug_handler, 0, INVALID, 0, "IPC");
            libcli_register_param(&debug, &ipc);
            libcli_set_param_cmd_code(&ipc, DIPC);
            libcli_register_param_detail (&ipc, tcp_ip_debug_handler, DIPC_DET);
        }

        {
            /* config node <node-name> [no] debug interface [detail]*/
            static param_t intf;
            init_param(&intf, CMD, "interface", tcp_ip_debug_handler, 0, INVALID, 0, "Interface");
            libcli_register_param(&debug, &intf);
            libcli_set_param_cmd_code(&intf, DINTF);
            libcli_register_param_detail (&intf, tcp_ip_debug_handler, DINTF_DET);
        }

        {
            /* config node <node-name> [no] debug flow [detail]*/
            static param_t flow;
            init_param(&flow, CMD, "flow", tcp_ip_debug_handler, 0, INVALID, 0, "Packet Flow");
            libcli_register_param(&debug, &flow);
            libcli_set_param_cmd_code(&flow, DFLOW);
            libcli_register_param_detail (&flow, tcp_ip_debug_handler, DFLOW_DET);
        }

        {
            /* config node <node-name> [no] debug tunnel [detail]*/
            static param_t tunnel;
            init_param(&tunnel, CMD, "tunnel", tcp_ip_debug_handler, 0, INVALID, 0, "Tunnel");
            libcli_register_param(&debug, &tunnel);
            libcli_set_param_cmd_code(&tunnel, DTUNNEL);
            libcli_register_param_detail (&tunnel, tcp_ip_debug_handler, DTUNNEL_DET);
        }

        {
            /* config node <node-name> [no] debug switch [detail]*/
            static param_t switching;
            init_param(&switching, CMD, "switching", tcp_ip_debug_handler, 0, INVALID, 0, "Switching");
            libcli_register_param(&debug, &switching);
            libcli_set_param_cmd_code(&switching, DL2SW);
            libcli_register_param_detail (&switching, tcp_ip_debug_handler, DL2SW_DET);
        }

        {
            /* config node <node-name> [no] debug timer [detail]*/
            static param_t timer;
            init_param(&timer, CMD, "timer", tcp_ip_debug_handler, 0, INVALID, 0, "timer");
            libcli_register_param(&debug, &timer);
            libcli_set_param_cmd_code(&timer, DTIMER);
            libcli_register_param_detail (&timer, tcp_ip_debug_handler, DTIMER_DET);
        }

        {
            /* config node <node-name> [no] debug always-flush*/
            static param_t flush;
            init_param(&flush, CMD, "always-flush", tcp_ip_debug_handler, 0, INVALID, 0, "Set log file always-flush");
            libcli_register_param(&debug, &flush);
            libcli_set_param_cmd_code(&flush, DALWAYS_FLUSH);
        }

        {
            /* config node <node-name> [no] debug error*/
            static param_t error;
            init_param(&error, CMD, "error", tcp_ip_debug_handler, 0, INVALID, 0, "Errors");
            libcli_register_param(&debug, &error);
            libcli_set_param_cmd_code(&error, DERR);
        }

    }

}

int
debug_dp_bits_to_str (char *buffer, uint64_t bits) {

    int rc = 0;

    if (bits & DARP) {
        strcat (buffer, "DARP ");
        rc += 5;
    }
    if (bits & DARP_DET) {
        strcat (buffer, "DARP_DET ");
        rc += 9;
    }
    if (bits & DL3FWD) {
        strcat (buffer, "DL3FWD ");
        rc += 7;
    }
    if (bits & DL3FWD_DET) {
        strcat (buffer, "DL3FWD_DET ");
        rc += 11;
    }
    if (bits & DL2FWD) {
        strcat (buffer, "DL2FWD ");
        rc += 7;
    }
    if (bits & DL2FWD_DET) {
        strcat (buffer, "DL2FWD_DET ");
        rc += 11;
    }
    if (bits & DRTM) {
        strcat (buffer, "DRTM ");
        rc += 5;
    }
    if (bits & DRTM_DET) {
        strcat (buffer, "DRTM_DET ");
        rc += 9;
    }
    if (bits & DACL) {
        strcat (buffer, "DACL ");
        rc += 5;
    }
    if (bits & DACL_DET) {
        strcat (buffer, "DACL_DET ");
        rc += 9;
    }
    if (bits & DIPC) {
        strcat (buffer, "DIPC ");
        rc += 5;
    }
    if (bits & DIPC_DET) {
        strcat (buffer, "DIPC_DET ");
        rc += 9;
    }
    if (bits & DINTF) {
        strcat (buffer, "DINTF ");
        rc += 6;
    }
    if (bits & DINTF_DET) {
        strcat (buffer, "DINTF_DET ");
        rc += 10;
    }
    if (bits & DFLOW) {
        strcat (buffer, "DFLOW ");
        rc += 6;
    }
    if (bits & DFLOW_DET) {
        strcat (buffer, "DFLOW_DET ");
        rc += 10;
    }
    if (bits & DTUNNEL) {
        strcat (buffer, "DTUNNEL ");
        rc += 8;
    }
    if (bits & DTUNNEL_DET) {
        strcat (buffer, "DTUNNEL_DET ");
        rc += 12;
    }
    if (bits & DL2SW) {
        strcat (buffer, "DL2SW ");
        rc += 6;
    }
    if (bits & DL2SW_DET) {
        strcat (buffer, "DL2SW_DET ");
        rc += 10;
    }
    if (bits & DTIMER) {
        strcat (buffer, "DTIMER ");
        rc += 7;
    }
    if (bits & DTIMER_DET) {
        strcat (buffer, "DTIMER_DET ");
        rc += 11;
    }
    if (bits & DERR) {
        strcat (buffer, "DERR ");
        rc += 5;
    }
    return rc;
}