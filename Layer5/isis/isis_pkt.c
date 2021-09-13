#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_intf.h"

bool
isis_pkt_trap_rule (char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
	
    if (eth_hdr->type == ISIS_ETH_PKT_TYPE) {
		return true;
	}
	return false;
}

void
isis_pkt_receive(void *arg, size_t arg_size) {

//    printf("%s() invoked\n", __FUNCTION__);
}

byte *
isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size) {

    byte *temp;
    isis_pkt_hdr_t *hello_pkt_hdr;

    uint32_t eth_hdr_payload_size =
        sizeof(isis_pkt_hdr_t) + 
        (TLV_OVERHEAD_SIZE * 6) +
        NODE_NAME_SIZE +
        4 +
        4 +
        4 +
        4 +
        4;

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD +
        eth_hdr_payload_size;

    ethernet_hdr_t *hello_eth_hdr = (ethernet_hdr_t *)
        tcp_ip_get_new_pkt_buffer(*hello_pkt_size);

    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    memset(hello_eth_hdr->src_mac.mac, 0, sizeof(mac_add_t));
    hello_eth_hdr->type = ISIS_ETH_PKT_TYPE;

    hello_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    hello_pkt_hdr->isis_pkt_type = ISIS_PTP_HELLO_PKT_TYPE;
    hello_pkt_hdr->seq_no = 0;  /*  Not required */
    hello_pkt_hdr->rtr_id =   tcp_ip_covert_ip_p_to_n( NODE_LO_ADDR(intf->att_node));
    hello_pkt_hdr->flags = 0;

    temp = (byte *)(hello_pkt_hdr + 1 );

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOSTNAME, NODE_NAME_SIZE,
            intf->att_node->node_name);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID, 4, 
            (byte *)&hello_pkt_hdr->rtr_id);

    uint32_t ip_addr_int = tcp_ip_covert_ip_p_to_n (IF_IP(intf));

    temp = tlv_buffer_insert_tlv (temp, ISIS_TLV_IF_IP, 4, (byte *)&ip_addr_int);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_INDEX,
            4, 
            (byte *)&IF_INDEX(intf));

    uint32_t hold_time =
        ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR;

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME,
            4,
            (byte *)&hold_time);

    uint32_t cost = ISIS_INTF_COST(intf);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL,
            4,
            (byte *)&cost);

    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_hdr_payload_size, 0);

    return (byte *)hello_eth_hdr; 
}

uint32_t
isis_print_lsp_pkt(byte *buff, 
                                  isis_pkt_hdr_t *hello_pkt_hdr,
                                  uint32_t pkt_size ) {


}

uint32_t
isis_print_hello_pkt(byte *buff, 
                                  isis_pkt_hdr_t *hello_pkt_hdr,
                                  uint32_t pkt_size ) {

    uint32_t rc = 0;
    char *ip_addr_str;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    byte *hello_tlv_buffer = (byte *)(hello_pkt_hdr + 1);
    uint32_t hello_tlv_buffer_size = pkt_size - sizeof(isis_pkt_hdr_t);

    rc = sprintf (buff, "ISIS_PTP_HELLO_PKT_TYPE : ");

    ITERATE_TLV_BEGIN(hello_tlv_buffer , tlv_type,
                        tlv_len, tlv_value, hello_tlv_buffer_size){

        switch(tlv_type){
            case ISIS_TLV_IF_INDEX:
                rc += sprintf(buff + rc, "%d %d %u :: ", 
                    tlv_type, tlv_len, *(uint32_t *)(tlv_value));
            break;
            case ISIS_TLV_HOSTNAME:
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, tlv_value);
                break;
            case ISIS_TLV_RTR_ID:
            case ISIS_TLV_IF_IP:
                ip_addr_str = tcp_ip_covert_ip_n_to_p(*(uint32_t *)tlv_value, 0);
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, ip_addr_str);
                break;
            case ISIS_TLV_HOLD_TIME:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_METRIC_VAL:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            default:    ;
        }

    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, hello_tlv_buffer_size)
    
    rc -= strlen(" :: ");
    return rc;
}

void
isis_print_pkt(void *arg, size_t arg_size) {

    pkt_info_t *pkt_info;

    pkt_info = (pkt_info_t *)arg;

    byte *buff = pkt_info->pkt_print_buffer; // sprintf
	size_t pkt_size = pkt_info->pkt_size;
    isis_pkt_hdr_t *pkt_hdr = (isis_pkt_hdr_t *)(pkt_info->pkt);
    pkt_info->bytes_written = 0;

    isis_pkt_type_t pkt_type = pkt_hdr->isis_pkt_type; 

    switch(pkt_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            pkt_info->bytes_written += isis_print_hello_pkt(buff, pkt_hdr, pkt_size);
            break;
        case ISIS_LSP_PKT_TYPE:
            pkt_info->bytes_written += isis_print_lsp_pkt(buff, pkt_hdr, pkt_size);
            break;
        default: ;
    }
}