#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_pkt.h"

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

	if (eth_hdr->type == ISIS_ETH_PKT_TYPE) {
		return true;
	}
	return false;
}

void
isis_pkt_recieve(void *arg, size_t arg_size) {

    char *pkt;
    node_t *node;
    interface_t *iif;
    uint32_t pkt_size;
	hdr_type_t hdr_code;
    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = pkt_notif_data->recv_interface;
    pkt         = pkt_notif_data->pkt;
    pkt_size    = pkt_notif_data->pkt_size;
	hdr_code    = pkt_notif_data->hdr_code;	

    if (hdr_code != ETH_HDR) return;


}

void
isis_install_lsp_pkt_in_lspdb(node_t *node, 
                              char *isis_lsp_pkt,
                              size_t lsp_pkt_size) {

}

char *
isis_generate_lsp_pkt(node_t *node, size_t *lsp_pkt_size) {

    return NULL;
}

char *
isis_get_hello_pkt(interface_t *intf, size_t *hello_pkt_size) {

    char *temp;
    node_t *node;

    uint32_t eth_hdr_playload_size =
                sizeof(uint16_t) +  /*ISIS pkt type code*/ 
                (TLV_OVERHEAD_SIZE * 4) + /*There shall be four TLVs, hence 4 TLV overheads*/
                NODE_NAME_SIZE +    /*Data length of TLV: TLV_NODE_NAME*/
                16 +                /*Data length of TLV_RTR_NAME which is 16*/
                16 +                /*Data length of TLV_IF_IP which is 16*/
                6;                  /*Data length of TLV_IF_MAC which is 6*/

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + /*Dst Mac + Src mac + type field + FCS field*/
                      eth_hdr_playload_size;

    ethernet_hdr_t *hello_eth_hdr = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*hello_pkt_size);

    memcpy(hello_eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    hello_eth_hdr->type = ISIS_ETH_PKT_TYPE;
    node = intf->att_node;
    temp = (char *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    uint16_t *isis_pkt_code = (uint16_t *)temp;
    *isis_pkt_code = ISIS_PTP_HELLO_PKT_TYPE;
    
    temp = (char *)(isis_pkt_code + 1);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_NODE_NAME, NODE_NAME_SIZE, node->node_name);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID, 16, NODE_LO_ADDR(node));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP,  16, IF_IP(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_MAC, 6,  IF_MAC(intf));
    ETH_FCS(hello_eth_hdr, eth_hdr_playload_size) = 0;
    return (char *)hello_eth_hdr;  
}

void
isis_print_hello_pkt(void *arg, size_t arg_size) {

    int rc = 0;
	char *buff;
	uint32_t pkt_size;

    unsigned char tlv_type, tlv_len, *tlv_value = NULL;

	pkt_info_t *pkt_info = (pkt_info_t *)arg;

	buff = pkt_info->pkt_print_buffer;
	pkt_size = pkt_info->pkt_size;

    char* hpkt = (char *)(pkt_info->pkt);

	assert(pkt_info->protocol_no == ISIS_ETH_PKT_TYPE);

    rc = sprintf(buff, "ISIS_PTP_HELLO_PKT_TYPE : ");

    ITERATE_TLV_BEGIN(((char *)hpkt + sizeof(uint16_t)), tlv_type,
                        tlv_len, tlv_value, pkt_size){

        switch(tlv_type){
            case ISIS_TLV_IF_MAC:
                rc += sprintf(buff + rc, "%d %d %02x:%02x:%02x:%02x:%02x:%02x :: ", 
                    tlv_type, tlv_len, 
                    tlv_value[0], tlv_value[1], tlv_value[2],
                    tlv_value[3], tlv_value[4], tlv_value[5]);
            break;
            case ISIS_TLV_NODE_NAME:
            case ISIS_TLV_RTR_ID:
            case ISIS_TLV_IF_IP:
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, tlv_value);
                break;
            default:    ;
        }

    } ITERATE_TLV_END(((char *)hpkt + sizeof(uint16_t)), tlv_type,
                        tlv_len, tlv_value, pkt_size)
    
    rc -= strlen(" :: ");
    pkt_info->bytes_written = rc;
}