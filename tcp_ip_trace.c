#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include "tcp_public.h"
#include "datapath/Interface/dp_intf.h"
#include "datapath/Interface/dp_intf_store.h"
#include "datapath/Layer3/ping.h"

extern graph_t *topo;

static int
tcp_dump_gre_hdr(char *buff, 
                        gre_hdr_t *gre_hdr,
                        pkt_size_t pkt_size);
extern int
tcp_dump_ip6_hdr(c_string buff, ipv6_hdr_t *ipv6_hdr, pkt_size_t pkt_size);

extern int 
tcp_dump_srh_hdr(unsigned char *buffer, srh_hdr_t *srh_hdr, pkt_size_t pkst_size) ;

static c_string
string_ethernet_hdr_type(unsigned short type, char *string_buffer){

    c_string proto_str = NULL;

    switch(type){

        case ETH_TYPE_IPv4:
            string_copy((char *)string_buffer, "ETH_TYPE_IPv4", strlen("ETH_TYPE_IPv4"));
            break;
        case ETH_TYPE_IPv6:
            string_copy((char *)string_buffer, "ETH_TYPE_IPv6", strlen("ETH_TYPE_IPv6"));
            break;
        case ETH_TYPE_ARP:
            string_copy((char *)string_buffer, "ARP_MSG", strlen("ARP_MSG"));
            break;
        default:
            sprintf((char *)string_buffer, "L2-Proto : %hu", type);
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

        case IP_PROTO_ICMP:
            string_copy((char *)string_buffer, "IP_PROTO_ICMP", strlen("IP_PROTO_ICMP"));
            break;
        case IP_PROTO_ICMPv6:
            string_copy((char *)string_buffer, "IP_PROTO_ICMPv6", strlen("IP_PROTO_ICMPv6"));
            break;
        case IP_PROTO_UDP:
             string_copy((char *)string_buffer, "IP_PROTO_UDP", strlen("IP_PROTO_UDP"));
             break;
        case IP_PROTO_TCP:
             string_copy((char *)string_buffer, "IP_PROTO_TCP", strlen("IP_PROTO_TCP"));
             break;       
        case IP_PROTO_GRE:
             string_copy((char *)string_buffer, "IP_PROTO_GRE", strlen("IP_PROTO_GRE"));
             break;      
        case IP_PROTO_SRH:
                string_copy((char *)string_buffer, "IP_PROTO_SRH", strlen("IP_PROTO_SRH"));
                break;
        default:
            return NULL;
    }
    return string_buffer;
}


static int
tcp_dump_appln_hdr_protocol_icmp(c_string buff, c_string appln_data, uint32_t pkt_size){

    int rc = 0;

    if (pkt_size < sizeof(icmp_hdr_t)) return 0;

    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)appln_data;

    switch (icmp_hdr->type) {

        case ICMP_ECHO_REQ:
            rc += sprintf((char *)buff + rc,
                "ICMP Hdr : Type : Echo-Request(%u)  Code : %u  "
                "Checksum : 0x%04x  Id : %u  Seq : %u\n",
                icmp_hdr->type,
                icmp_hdr->code,
                ntohs(icmp_hdr->checksum),
                ntohs(icmp_hdr->identifier),
                ntohs(icmp_hdr->seq_no));
            break;

        case ICMP_ECHO_REP:
            rc += sprintf((char *)buff + rc,
                "ICMP Hdr : Type : Echo-Reply(%u)  Code : %u  "
                "Checksum : 0x%04x  Id : %u  Seq : %u\n",
                icmp_hdr->type,
                icmp_hdr->code,
                ntohs(icmp_hdr->checksum),
                ntohs(icmp_hdr->identifier),
                ntohs(icmp_hdr->seq_no));
            break;

        default:
            rc += sprintf((char *)buff + rc,
                "ICMP Hdr : Type : %u  Code : %u  Checksum : 0x%04x\n",
                icmp_hdr->type,
                icmp_hdr->code,
                ntohs(icmp_hdr->checksum));
            break;
    }

    return rc;
}

static int 
tcp_dump_application_hdr (c_string buff, uint8_t proto, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    int rc = 0;

    switch(proto){

        case IP_PROTO_ICMP:
            rc += tcp_dump_appln_hdr_protocol_icmp(
                        buff + rc,
                        (c_string)pkt, pkt_size);
            break;
        case IP_PROTO_UDP:
            rc += tcp_dump_transport_udp_protocol(
                        buff + rc,
                        (udp_hdr_t *)pkt, pkt_size);
            break;            
        break;
        case IP_PROTO_TCP:
        break;
        case IP_PROTO_GRE:
            rc += tcp_dump_gre_hdr(buff + rc, 
                        (gre_hdr_t *)pkt, pkt_size );
            break;
        case IP_PROTO_SRH:
            rc += tcp_dump_srh_hdr(buff + rc, 
                        (srh_hdr_t *)pkt, pkt_size);
            break;
        default:
            ;
    }

    return rc;
}

static int
tcp_dump_ip6_hdr(c_string buff, ipv6_hdr_t *ipv6_hdr, pkt_size_t pkt_size){

     int rc = 0;
     char ipv61[48];
     char ipv62[48];
     byte string_buffer[32] = {0};
     pkt_block_t *pkt_block;

    inet_ntop(AF_INET6, ipv6_hdr->src_addr, ipv61, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ipv6_hdr->dst_addr, ipv62, INET6_ADDRSTRLEN);

     rc +=  sprintf((char *)(buff + rc), "IP6 Hdr : ");
     rc +=  sprintf((char *)(buff + rc), "TL: %dB PRO: %s  %s -> %s ttl: %d\n", 
                      sizeof(ipv6_hdr_t) + ipv6_hdr->payload_length,
                      string_ip_hdr_protocol_val(ipv6_hdr->next_header, string_buffer),
                      ipv61, ipv62, ipv6_hdr->hop_limit);

    byte *appln_data = (byte *)(ipv6_hdr + 1);
    pkt_block = pkt_block_get_new(appln_data, pkt_size - sizeof (ipv6_hdr_t));
    rc += tcp_dump_application_hdr (buff + rc, ipv6_hdr->next_header, pkt_block) ;

    XFREE(pkt_block);

    return rc;
}

static int
tcp_dump_ip_hdr(c_string buff, ip_hdr_t *ip_hdr, pkt_size_t pkt_size){

     int rc = 0;
     byte ip1[IPV4_ADDR_LEN_STR];
     byte ip2[IPV4_ADDR_LEN_STR];
     byte string_buffer[32] = {0};
     pkt_block_t *pkt_block;

     tcp_ip_covert_ip_n_to_p( htonl(ip_hdr->src_ip), ip1);
     tcp_ip_covert_ip_n_to_p( htonl(ip_hdr->dst_ip), ip2);

     rc +=  sprintf((char *)(buff + rc), "IP Hdr : ");
     rc +=  sprintf((char *)(buff + rc), 
                    "v:%d ihl:%d TL: %dB PRO: %s %s -> %s ttl: %d\n", 
                      IP_HDR_VERSION(ip_hdr),
                      IP_HDR_IHL(ip_hdr),
                      IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr),
                      string_ip_hdr_protocol_val(ip_hdr->protocol, string_buffer),
                      ip1, ip2, ip_hdr->ttl);

    byte *appln_data = (byte *)INCREMENT_IPHDR(ip_hdr);
    pkt_block = pkt_block_get_new(appln_data, pkt_size - sizeof (ip_hdr_t));
    rc += tcp_dump_application_hdr (buff + rc, ip_hdr->protocol, pkt_block) ;
    XFREE(pkt_block);

    return rc;
}

static int
tcp_dump_arp_hdr(c_string buff, arp_hdr_t *arp_hdr, 
                  uint32_t pkt_size){

    int rc = 0;
    byte string_buffer[48] = {0};
    byte ip1[IPV4_ADDR_LEN_STR];
    byte ip2[IPV4_ADDR_LEN_STR];

    rc +=  sprintf((char *)buff, "ARP Hdr : ");
    rc += sprintf((char *)buff + rc, "Arp Type: %s %02x:%02x:%02x:%02x:%02x:%02x -> "
            "%02x:%02x:%02x:%02x:%02x:%02x %s -> %s\n",
            string_arp_hdr_type(htons(arp_hdr->op_code), (char *)string_buffer),
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

            tcp_ip_covert_ip_n_to_p(htonl(arp_hdr->src_ip), ip1),
            tcp_ip_covert_ip_n_to_p(htonl(arp_hdr->dst_ip), ip2));
            
    return rc;
}

int
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

    unsigned short type = vlan_8021q_hdr ? htons(vlan_eth_hdr->type) :\
                            htons(eth_hdr->type);

    rc += sprintf (buff + rc, "Eth hdr : ");
    rc += sprintf (buff + rc, "%02x:%02x:%02x:%02x:%02x:%02x -> "
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

        case ETH_TYPE_IPv4:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                     payload_size);
            break;
        case ETH_TYPE_IPv6:
            rc += tcp_dump_ip6_hdr(buff + rc, 
                    (ipv6_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                    payload_size);
            break;
        case ETH_TYPE_ARP:
            rc += tcp_dump_arp_hdr(buff + rc,
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                    payload_size);
            break;
        default:
            pkt_block = pkt_block_get_new(
                        (uint8_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr),
                        (pkt_size_t)payload_size);
            pkt_block_update_new_hdr_type(pkt_block, type);
            rc += nfc_pkt_trace_invoke_notif_to_sbscribers(
					type,
					pkt_block,
					buff + rc
                    );
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
     rc += sprintf(buff + rc, "GRE Encap: %s\n", proto_id_str(htons(gre_hdr->protocol_type)));

    switch (htons(gre_hdr->protocol_type)) {

        case ETH_TYPE_IPv4:
            rc += tcp_dump_ip_hdr(buff + rc, 
                    (ip_hdr_t *)(gre_hdr + 1), 
                    pkt_size - sizeof(gre_hdr_t));
            break;

        case ETH_TYPE_GRE:
            rc += tcp_dump_ethernet_hdr(buff + rc, 
                    (ethernet_hdr_t *)(gre_hdr + 1), 
                    pkt_size - sizeof(gre_hdr_t));
            break;

        default:
            assert(0);
    }
    return rc;
}

static int 
tcp_dump_srh_hdr(unsigned char *buffer, srh_hdr_t *srh_hdr, pkt_size_t pkt_size) {

    int rc = 0;
    char ipv6_addr_str[48];

    rc += sprintf((char *)buffer + rc,  "SRH Hdr : Nxt Hdr %s, Hdr_len %d, SL : %d\n", 
                        proto_id_str (srh_hdr->nexthdr), 
                        srh_hdr->hdrlen, 
                        srh_hdr->segments_left);

    /* Encode Segment List */
    for (int i = 0; i < srh_hdr->segments_left; i++) {

        inet_ntop(AF_INET6, srh_hdr->segments[i], ipv6_addr_str, INET6_ADDRSTRLEN);
        rc += sprintf((char *)buffer + rc, "Seg %d : %s\n", i, ipv6_addr_str);
    }

    switch (srh_hdr->nexthdr)
    {
        case IP_PROTO_IP_IN_IP:
            rc += tcp_dump_ip_hdr(buffer + rc,
                                (ip_hdr_t *)((char *)srh_hdr + srh_hdr->hdrlen),
                                pkt_size - srh_hdr->hdrlen);
            break;
        case IP_PROTO_IPv6:
            rc += tcp_dump_ip6_hdr(buffer + rc,
                                (ipv6_hdr_t *)((char *)srh_hdr + srh_hdr->hdrlen),
                                pkt_size - srh_hdr->hdrlen);
            break;
        case IP_PROTO_GRE:
            rc += tcp_dump_gre_hdr(buffer + rc,
                                (gre_hdr_t *)((char *)srh_hdr + srh_hdr->hdrlen),
                                pkt_size - srh_hdr->hdrlen);
            break;
        case ETHERNET_HEADER:
            rc += tcp_dump_ethernet_hdr (buffer + rc,
                                (ethernet_hdr_t *)((char *)srh_hdr + srh_hdr->hdrlen),
                                pkt_size - srh_hdr->hdrlen);
            break;
        case IP_PROTO_TCP:
        case IP_PROTO_UDP:
        case IP_PROTO_ICMP:
        case IP_PROTO_ICMPv6:
        case IP_PROTO_IPv6_ROUTE:
        default:
            break;
    }

    return rc;
}

/* Format: DD-MM-YYYY HH:MM:SS.uuuuuu (local time, microsecond field). */
static size_t
tcp_format_log_timestamp(char *tsbuf, size_t tsbuf_sz)
{
    struct timespec ts;
    struct tm tm_local;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        ts.tv_sec = time(NULL);
        ts.tv_nsec = 0;
    }
    if (!localtime_r(&ts.tv_sec, &tm_local))
        return 0;
    int n = snprintf(tsbuf, tsbuf_sz,
                       "%02d-%02d-%04d %02d:%02d:%02d.%06ld ",
                       tm_local.tm_mday,
                       tm_local.tm_mon + 1,
                       tm_local.tm_year + 1900,
                       tm_local.tm_hour,
                       tm_local.tm_min,
                       tm_local.tm_sec,
                       (long)(ts.tv_nsec / 1000L));
    if (n <= 0 || (size_t)n >= tsbuf_sz)
        return 0;
    return (size_t)n;
}

void
tcp_write_data(int sock_fd,
               FILE *log_file1, FILE *log_file2,
               char *out_buff, uint32_t buff_size)
{
    char ts_prefix[40];
    size_t ts_len = 0;
    int log_to_file = (log_file1 != NULL || log_file2 != NULL || (sock_fd != -1));

    assert(out_buff);

    if (log_to_file)
        ts_len = tcp_format_log_timestamp(ts_prefix, sizeof(ts_prefix));

    if (log_file1) {
        if (ts_len)
            fwrite(ts_prefix, sizeof(char), ts_len, log_file1);
        fwrite(out_buff, sizeof(char), buff_size, log_file1);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file1);
    }

    if (log_file2) {
        if (ts_len)
            fwrite(ts_prefix, sizeof(char), ts_len, log_file2);
        fwrite(out_buff, sizeof(char), buff_size, log_file2);
        /* The below fflush may impact performance as it will flush the
         * data from internal buffer memory onto the disk immediately*/
        fflush(log_file2);
    }

    if (sock_fd == -1) return;

    write(sock_fd, ts_prefix, ts_len);
    write(sock_fd, out_buff, buff_size);
}

void
tcp_dump(int sock_fd, 
         FILE *log_file1,
         FILE *log_file2,
         pkt_block_t *pkt_block,
         gen_proto_id_t hdr_type,
         c_string out_buff, 
         uint32_t write_OFFset,
         uint32_t out_buff_size){

    int rc = 0;
    uint8_t *pkt = NULL;
    pkt_size_t pkt_size;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(hdr_type){

        case ETHERNET_HEADER:
            rc = tcp_dump_ethernet_hdr(out_buff + write_OFFset, 
                (ethernet_hdr_t *)pkt, pkt_size);
            break;
        case ETH_TYPE_IPv4:
            rc = tcp_dump_ip_hdr(out_buff + write_OFFset, 
                (ip_hdr_t *)pkt, pkt_size);
            break;
        case ETH_TYPE_IPv6:
            rc = tcp_dump_ip6_hdr(out_buff + write_OFFset, 
                (ipv6_hdr_t *)pkt, pkt_size);
            break;
        case IP_PROTO_GRE:
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
tcp_ip_set_all_log_info_params(log_t *log_info, bool status){

    log_info->all    = status;
    log_info->recv   = status;
    log_info->send   = status;
    log_info->l3_fwd = status;
    /*User should explicitely enabled stdout*/
    //log_info->is_stdout = status;
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


static void
tcp_ip_print_dp_intf_log_status_header(void) {
    cprintf("\t%-18s %-6s %-5s %-5s %-5s %-7s %s\n",
        "Interface", "Status", "All", "Recv", "Send", "Stdout", "ACL Filter");
    cprintf("\t%-18s %-6s %-5s %-5s %-5s %-7s %s\n",
        "------------------", "------", "-----", "-----", "-----", "-------", "----------");
}

static void
tcp_ip_print_dp_intf_log_status(dp_intf_t *dp_intf) {

    log_t *log_info = &dp_intf->log_info;
    const char *acl = (log_info->acc_lst_filter && log_info->acc_lst_filter->name)
                      ? log_info->acc_lst_filter->name : "none";

    cprintf("\t%-18s %-6s %-5s %-5s %-5s %-7s %s\n",
        dp_intf->if_name,
        dp_intf->is_up  ? "UP"  : "DOWN",
        log_info->all        ? "ON"  : "OFF",
        log_info->recv       ? "ON"  : "OFF",
        log_info->send       ? "ON"  : "OFF",
        log_info->is_stdout  ? "ON"  : "OFF",
        acl);
}

void tcp_ip_show_log_status(node_t *node){

    dp_ctx_t *dp_ctx = node->dp_ctx;
    log_t *log_info  = &dp_ctx->log;

    printw ("\n\r");

    cprintf("Log Status : Device : %s\n", node->node_name);

    cprintf("\tall     : %s\n", log_info->all     ? "ON" : "OFF");
    cprintf("\trecv    : %s\n", log_info->recv    ? "ON" : "OFF");
    cprintf("\tsend    : %s\n", log_info->send    ? "ON" : "OFF");
    cprintf("\tstdout  : %s\n", log_info->is_stdout ? "ON" : "OFF");
    cprintf("\tl3_fwd  : %s\n", log_info->l3_fwd  ? "ON" : "OFF");
    cprintf("\taccess list filter : %s\n",
            log_info->acc_lst_filter && log_info->acc_lst_filter->name
                ? log_info->acc_lst_filter->name : "none");

    /* Interface log status — one header, one row per interface */
    cprintf("\n");
    tcp_ip_print_dp_intf_log_status_header();

    if (hashtable_count(dp_ctx->dp_intf_ht) > 0) {
        struct hashtable_itr *itr = hashtable_iterator(dp_ctx->dp_intf_ht);
        do {
            dp_intf_t *dp_intf = (dp_intf_t *)hashtable_iterator_value(itr);
            if (dp_intf) tcp_ip_print_dp_intf_log_status(dp_intf);
        } while (hashtable_iterator_advance(itr));
        free(itr);
    }

    /* Special virtual interfaces */
    if (dp_ctx->dp_rmac_intf)       tcp_ip_print_dp_intf_log_status(dp_ctx->dp_rmac_intf);
    if (dp_ctx->dp_vlan_flood_intf) tcp_ip_print_dp_intf_log_status(dp_ctx->dp_vlan_flood_intf);
    if (dp_ctx->dp_host_path_intf)  tcp_ip_print_dp_intf_log_status(dp_ctx->dp_host_path_intf);
    if (dp_ctx->dp_nve_intf)        tcp_ip_print_dp_intf_log_status(dp_ctx->dp_nve_intf);

    cprintf ("\tDebug Logging Status:\n");

    tracer_t *cptr = node->cptr;
    tracer_t *dptr = node->dp_ctx->dptr;
    
    if (tracer_is_bit_set (dptr, DARP | DARP_DET)) 
        cprintf ("\t  DARP     :     ON\n" );
    else 
        cprintf ("\t  DARP     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DL3FWD | DL3FWD_DET)) 
        cprintf ("\t  DL3FWD   :     ON\n" );
    else 
        cprintf ("\t  DL3FWD   :     OFF\n" );    

    if (tracer_is_bit_set (dptr, DL2FWD | DL2FWD_DET)) 
        cprintf ("\t  DL2FWD   :     ON\n" );
    else 
        cprintf ("\t  DL2FWD   :     OFF\n" );        
    
    if (tracer_is_bit_set (cptr, DRTM | DRTM_DET)) 
        cprintf ("\t  DRTM     :     ON\n" );
    else 
        cprintf ("\t  DRTM     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DACL | DACL_DET) ||
            tracer_is_bit_set (cptr, DACL | DACL_DET)) 
        cprintf ("\t  DACL     :     ON\n" );
    else 
        cprintf ("\t  DACL     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DIPC | DIPC_DET) ||
            tracer_is_bit_set (cptr, DIPC | DIPC_DET)) 
        cprintf ("\t  DIPC     :     ON\n" );
    else 
        cprintf ("\t  DIPC     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DINTF | DINTF_DET) ||
            tracer_is_bit_set (cptr, DINTF | DINTF_DET)) 
        cprintf ("\t  DINTF    :     ON\n" );
    else 
        cprintf ("\t  DINTF    :     OFF\n" );

    if (tracer_is_bit_set (dptr, DFLOW | DFLOW_DET)) 
        cprintf ("\t  DFLOW    :     ON\n" );
    else 
        cprintf ("\t  DFLOW    :     OFF\n" );

    if (tracer_is_bit_set (dptr, DTUNNEL | DTUNNEL_DET)) 
        cprintf ("\t  DTUN     :     ON\n" );
    else 
        cprintf ("\t  DTUN     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DL2SW | DL2SW_DET)) 
        cprintf ("\t  DL2SW    :     ON\n" );
    else 
        cprintf ("\t  DL2SW    :     OFF\n" );

    if (tracer_is_bit_set (dptr, DFIB | DFIB_DET)) 
        cprintf ("\t  DFIB     :     ON\n" );
    else 
        cprintf ("\t  DFIB    :     OFF\n" );

    if (tracer_is_bit_set (dptr, DTIMER | DTIMER_DET) ||
            tracer_is_bit_set (cptr, DTIMER | DTIMER_DET)) 
        cprintf ("\t  DTIMER   :     ON\n" );
    else 
        cprintf ("\t  DTIMER   :     OFF\n" );

    if (tracer_get_always_flush_status (dptr) || 
            tracer_get_always_flush_status (cptr))
        cprintf ("\t  DALWAYS_FLUSH: ON\n" );
    else 
        cprintf ("\t  DALWAYS_FLUSH: OFF\n" );

    if (tracer_is_bit_set (dptr, DCONF))
        cprintf ("\t  DCONF     :     ON\n" );
    else 
        cprintf ("\t  DCONF     :     OFF\n" );

    if (tracer_is_bit_set (dptr, DERR) || 
            tracer_is_bit_set (cptr, DERR)) 
        cprintf ("\t  DERR     :     ON\n" );
    else 
        cprintf ("\t  DERR     :     OFF\n" );    

    if (tracer_is_bit_set (dptr, DALL_LOGGING) ||
            tracer_is_bit_set (cptr, DALL_LOGGING))
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
            log_info = &node->dp_ctx->log;
        break;
        case CMDCODE_DEBUG_LOGGING_PER_INTF:
        {
            dp_intf_t *dp_intf;
            node =  node_get_node_by_name(topo, node_name);
            intf = node_interface_lookup_by_name(node,(const char *) if_name);
            if(!intf){
                cprintf("Error : No interface %s on Node %s\n", if_name, node_name);
                return -1;
            }
            dp_intf = dp_look_up_interface(node->dp_ctx->dp_intf_ht, intf->ifindex);
            if (!dp_intf) {
                cprintf("Error : No DP interface for %s on Node %s\n", if_name, node_name);
                return -1;
            }
            log_info = &dp_intf->log_info;
        }
        break;

        case CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME:
        node = node_get_node_by_name(topo, node_name);
        access_list = access_list_lookup_by_name(node, access_list_name);
                if (!access_list)
                {
                    cprintf("\nError : Access-list do not exist");
                    return -1;
                }
                log_info = &node->dp_ctx->log;
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
                    printw ("Error : access-list is not configured\n");
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
        {
        dp_intf_t *dp_intf_acl;
        node = node_get_node_by_name(topo, node_name);
        intf = node_interface_lookup_by_name(node, (const char *)if_name);
        if (!intf)
        {
            printw ("\nError : No interface %s on Node %s\n", if_name, node_name);
                return -1;
        }
        access_list = access_list_lookup_by_name(node, access_list_name);
        if (!access_list)
        {
                printw ("\nError : Access-list do not exist\n");
                return -1;
        }
        dp_intf_acl = dp_look_up_interface(node->dp_ctx->dp_intf_ht, intf->ifindex);
        if (!dp_intf_acl)
        {
                printw ("\nError : No DP interface for %s on Node %s\n", if_name, node_name);
                return -1;
        }
        log_info = &dp_intf_acl->log_info;
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
                    printw ("Error : access-list is not configured\n");
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
        } /* CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME_INTF */
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

                Interface *intf;
                ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

                    if(!intf) continue;
                    dp_intf_t *dp_intf_it = dp_look_up_interface(
                            node->dp_ctx->dp_intf_ht, intf->ifindex);
                    if (dp_intf_it)
                        tcp_ip_set_all_log_info_params(&dp_intf_it->log_info, false);

                }  ITERATE_NODE_INTERFACES_END(node, intf);
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
			       dp_intf_t *interface, 
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
		fwrite(interface->if_name, sizeof(char), strlen((const char *)interface->if_name), NODE_LOG_FILE(node));
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
tcp_ip_debug_handler(int cmdcode,
                     Stack_t *tlv_stack,
                     op_mode enable_or_disable)
{

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        /* Both : CP and DP */
        case DALWAYS_FLUSH:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                tracer_enable_always_flush(node->dp_ctx->dptr, true);
                tracer_enable_always_flush(node->cptr, true);
            break;
            case CONFIG_DISABLE:
                tracer_enable_always_flush(node->dp_ctx->dptr, false);   
                tracer_enable_always_flush(node->cptr, false);
            break;
        }
        break;

        case DALL_LOGGING:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                tracer_enable_all_logging(node->dp_ctx->dptr, true);
		        tracer_enable_all_logging(node->cptr, true);
            break;
            case CONFIG_DISABLE:
                tracer_enable_all_logging(node->dp_ctx->dptr, false);  
		        tracer_enable_all_logging(node->cptr, false);
            break;
        }

        /* Both : CP and DP */
        case DERR:
        case DACL:
        case DACL_DET:
        case DIPC:
        case DIPC_DET:
        case DINTF:
        case DINTF_DET:
        case DTIMER:
        case DTIMER_DET:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                tracer_log_bit_set(node->dp_ctx->dptr, cmdcode);
		        tracer_log_bit_set(node->cptr, cmdcode);
            break;
            case CONFIG_DISABLE:
                tracer_log_bit_unset(node->dp_ctx->dptr, cmdcode);
		        tracer_log_bit_unset(node->cptr, cmdcode);
            break;
        }        
        break;

        /* Only : CP */
        case DRTM:
        case DRTM_DET:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
		        tracer_log_bit_set(node->cptr, cmdcode);
            break;
            case CONFIG_DISABLE:
	    	    tracer_log_bit_unset(node->cptr, cmdcode);
            break;
        }
        break;


        /* Only : DP */
        case DARP:
        case DARP_DET:
        case DL3FWD:
        case DL3FWD_DET:
        case DL2FWD:
        case DL2FWD_DET:
        case DFLOW:
        case DFLOW_DET:
        case DTUNNEL:
        case DTUNNEL_DET:
        case DL2SW:
        case DL2SW_DET:
        case DFIB:
        case DFIB_DET:
        case DMPLS:
        case DMPLS_DET:
        case DCONF:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
		        tracer_log_bit_set(node->dp_ctx->dptr, cmdcode);
            break;
            case CONFIG_DISABLE:
	    	    tracer_log_bit_unset(node->dp_ctx->dptr, cmdcode);
            break;
        }
        break;        
    }

    return 0;
}

/* Building debug cli tree */
static void 
libcli_register_param_detail (param_t *root, cmd_callback callback, int cmdcode) {

    param_t *detail = (param_t *)calloc (1, sizeof (param_t));
    init_param(detail, CMD, "detail", callback, 0, INVALID, 0, "detail");
    libcli_register_param(root, detail);
    libcli_set_param_cmd_code(detail, cmdcode);
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
            /* config node <node-name> [no] debug fib [detail]*/
            static param_t fib;
            init_param(&fib, CMD, "fib", tcp_ip_debug_handler, 0, INVALID, 0, "Forwarding Information Base");
            libcli_register_param(&debug, &fib);
            libcli_set_param_cmd_code(&fib, DFIB);
            libcli_register_param_detail (&fib, tcp_ip_debug_handler, DFIB_DET);
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
            /* config node <node-name> [no] debug datapath-conf*/
            static param_t dp_conf;
            init_param(&dp_conf, CMD, "datapath-conf", tcp_ip_debug_handler, 0, INVALID, 0, "Enable Data-path Configuration Log");
            libcli_register_param(&debug, &dp_conf);
            libcli_set_param_cmd_code(&dp_conf, DCONF);
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
debug_infra_tracer_bits_to_str (char *buffer, uint64_t bits) {

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
    if (bits & DFIB) {
        strcat (buffer, "DFIB ");
        rc += 5;
    }
    if (bits & DL2SW_DET) {
        strcat (buffer, "DFIB_DET ");
        rc += 9;
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
    if (bits & DCONF) {
        strcat (buffer, "DCONF ");
        rc += 6;
    }
    return rc;
}
