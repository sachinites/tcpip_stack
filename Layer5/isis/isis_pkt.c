#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_events.h"
#include "isis_flood.h"


bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

	if (eth_hdr->type == ISIS_ETH_PKT_TYPE) {
		return true;
	}
	return false;
}

static void
isis_process_hello_pkt(node_t *node,
                       interface_t *iif,
                       ethernet_hdr_t *hello_eth_hdr,
                       size_t pkt_size) {

    uint8_t intf_ip_len;
        
    if (!isis_node_intf_is_enable(iif)) return;
    
    /*Reject the pkt if dst mac is not Brodcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        goto bad_hello;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * reciepient interface*/

    unsigned char *hello_pkt = (unsigned char *)
        GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    
    unsigned char *hello_tlv_buffer =
        hello_pkt + sizeof(isis_pkt_type_t);
    
    size_t tlv_buff_size = pkt_size - \
                           ETH_HDR_SIZE_EXCL_PAYLOAD - \
                           sizeof(isis_pkt_type_t); 

    /*Fetch the IF IP Address Value from TLV buffer*/
    char *if_ip_addr = tlv_buffer_get_particular_tlv(
                        hello_tlv_buffer, 
                        tlv_buff_size, 
                        ISIS_TLV_IF_IP, 
                        &intf_ip_len);

    /*If no Intf IP, then it is a bad hello*/
    if(!if_ip_addr) goto bad_hello;

    if(!is_same_subnet(IF_IP(iif), 
                       iif->intf_nw_props.mask, 
                       if_ip_addr)){
        goto bad_hello;
    }
    isis_update_interface_adjacency_from_hello(iif, hello_tlv_buffer, tlv_buff_size);
    return ;

    bad_hello:
    ISIS_INCREMENT_STATS(iif, bad_hello_pkt_recvd);
}

static void
isis_process_lsp_pkt(node_t *node,
                     interface_t *iif,
                     ethernet_hdr_t *lsp_eth_hdr,
                     size_t pkt_size) {


}

void
isis_pkt_recieve(void *arg, size_t arg_size) {

    node_t *node;
    interface_t *iif;
    uint32_t pkt_size;
    hdr_type_t hdr_code;
    ethernet_hdr_t *eth_hdr;
    pkt_notif_data_t *pkt_notif_data;
    isis_node_info_t *isis_node_info;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = pkt_notif_data->recv_interface;
    eth_hdr     = (ethernet_hdr_t *) pkt_notif_data->pkt;
    pkt_size    = pkt_notif_data->pkt_size;
	hdr_code    = pkt_notif_data->hdr_code;	

    if (hdr_code != ETH_HDR) return;
    
    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    char *isis_pkt_payload = (char *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    isis_pkt_type_t isis_pkt_type = ISIS_PKT_TYPE(isis_pkt_payload);

    switch(isis_pkt_type) {

        case ISIS_PTP_HELLO_PKT_TYPE:
            isis_process_hello_pkt(node, iif, eth_hdr, pkt_size); 
        break;
        case ISIS_LSP_PKT_TYPE:
            isis_process_lsp_pkt(node, iif, eth_hdr, pkt_size);
        break;
        default:; 
    }
}

static void
isis_install_lsp_pkt_in_lspdb(node_t *node, 
                              isis_pkt_t *isis_lsp_pkt) {

}

static void
isis_create_fresh_lsp_pkt(node_t *node) {

    unsigned char *eth_payload;
    size_t lsp_pkt_size_estimate = 0;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    /* Dont use the fn isis_is_protocol_enable_on_node( ) because
       we want to generate purge LSP when protocol is shutting down
    */
    if (!isis_node_info) return;

    /* Get rid of out-dated self lsp pkt */
    if (isis_node_info->isis_self_lsp_pkt) {
        /* Debar this pkt from going out of the box*/
        isis_node_info->isis_self_lsp_pkt->flood_eligibility = false;
        isis_deref_isis_pkt(isis_node_info->isis_self_lsp_pkt);
        isis_node_info->isis_self_lsp_pkt = NULL;
    }

    isis_node_info->seq_no++;

    /* Now estimate the size of lsp pkt */
    lsp_pkt_size_estimate += ETH_HDR_SIZE_EXCL_PAYLOAD;
    lsp_pkt_size_estimate += sizeof(isis_pkt_type_t);
    lsp_pkt_size_estimate += sizeof(uint32_t); /* seq no */
    lsp_pkt_size_estimate += sizeof(uint32_t); /* 4B rtr id in integer format*/
    /* TLVs */
    lsp_pkt_size_estimate += TLV_OVERHEAD_SIZE + NODE_NAME_SIZE; /* Device name */

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)
                                tcp_ip_get_new_pkt_buffer(lsp_pkt_size_estimate);
    
    //memcpy(eth_hdr->src_mac.mac, 0, sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(eth_hdr->dst_mac.mac);
    eth_hdr->type = ISIS_ETH_PKT_TYPE;

    eth_payload = (unsigned char *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    /* pkt type */
    ISIS_PKT_TYPE(eth_payload) = ISIS_LSP_PKT_TYPE;
    eth_payload = (eth_payload + sizeof(isis_pkt_type_t));

    /* Seq no */
    memcpy(eth_payload, &isis_node_info->seq_no, sizeof(uint32_t));
    eth_payload = (eth_payload + sizeof(uint32_t));

    /* 4B rtr ID*/
    uint32_t rtr_id = tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node));
    memcpy(eth_payload, &rtr_id, sizeof(uint32_t));
    eth_payload = (eth_payload + sizeof(uint32_t));

    /* Now TLV */
    eth_payload = tlv_buffer_insert_tlv(eth_payload, ISIS_TLV_NODE_NAME,
                                        NODE_NAME_SIZE, node->node_name);
    
    ETH_FCS(eth_hdr, lsp_pkt_size_estimate) = 0;

    isis_node_info->isis_self_lsp_pkt = calloc(1, sizeof(isis_pkt_t));
    isis_node_info->isis_self_lsp_pkt->flood_eligibility = true;
    isis_node_info->isis_self_lsp_pkt->isis_pkt_type = ISIS_LSP_PKT_TYPE;
    isis_node_info->isis_self_lsp_pkt->pkt = (char *)eth_hdr;
    isis_node_info->isis_self_lsp_pkt->pkt_size = lsp_pkt_size_estimate;
    isis_node_info->isis_self_lsp_pkt->ref_count = 1;
}

void
isis_generate_lsp_pkt(void *arg, uint32_t arg_size_unused) {

    node_t *node = (node_t *)arg;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    isis_node_info->isis_lsp_pkt_gen_task = NULL;

    printf("Node : %s : LSP Generation task triggered\n", node->node_name);

    /* Now generate LSP pkt */
    isis_create_fresh_lsp_pkt(node);
    
    isis_update_lsp_flood_timer_with_new_lsp_pkt(node,
        isis_node_info->isis_self_lsp_pkt);
        
    isis_flood_lsp(node, isis_node_info->isis_self_lsp_pkt);
}

void
isis_schedule_lsp_pkt_generation(node_t *node, isis_events_t event_type) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_node_info) return;

    if (isis_node_info->isis_lsp_pkt_gen_task) {
        printf("Node %s : LSP generation Already scheduled, reason : %s\n",
            node->node_name, isis_event(event_type));
        return;
    }

    printf("Node %s : LSP generation scheduled, reason : %s\n",
            node->node_name, isis_event(event_type));

    isis_node_info->isis_lsp_pkt_gen_task =
        task_create_new_job(node, isis_generate_lsp_pkt, TASK_ONE_SHOT);
}

char *
isis_get_hello_pkt(interface_t *intf, size_t *hello_pkt_size) {

    char *temp;
    node_t *node;
    uint32_t four_byte_data;

    uint32_t eth_hdr_playload_size =
                sizeof(isis_pkt_type_t) +  /*ISIS pkt type code*/ 
                (TLV_OVERHEAD_SIZE * 6) + /*There shall be Six TLVs, hence 4 TLV overheads*/
                NODE_NAME_SIZE +    /*Data length of TLV: TLV_NODE_NAME*/
                16 +                /*Data length of TLV_RTR_NAME which is 16*/
                16 +                /*Data length of TLV_IF_IP which is 16*/
                6  +                /*Data length of TLV_IF_MAC which is 6*/
                4 +                 /* Data length for ISIS_TLV_HOLD_TIME */
                4;                  /* Data length for ISIS_TLV_METRIC_VAL */

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + /*Dst Mac + Src mac + type field + FCS field*/
                      eth_hdr_playload_size;

    ethernet_hdr_t *hello_eth_hdr =
        (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*hello_pkt_size);

    memcpy(hello_eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    hello_eth_hdr->type = ISIS_ETH_PKT_TYPE;

    node = intf->att_node;
    temp = (char *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    ISIS_PKT_TYPE(temp) = ISIS_PTP_HELLO_PKT_TYPE;
    
    temp = (temp + sizeof(isis_pkt_type_t));

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_NODE_NAME, 
                                NODE_NAME_SIZE, node->node_name);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID,
                                16, NODE_LO_ADDR(node));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP, 
                                16, IF_IP(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_MAC,
                                 6,  IF_MAC(intf));

    four_byte_data = ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR;

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME,
                                 4, (char *)&four_byte_data);

    four_byte_data = ISIS_INTF_COST(intf);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL,
                                 4, (char *)&four_byte_data);

    ETH_FCS(hello_eth_hdr, eth_hdr_playload_size) = 0;
    return (char *)hello_eth_hdr;  
}

static void
isis_print_lsp_pkt(pkt_info_t *pkt_info ) {

    int rc = 0;
	char *buff;
	uint32_t pkt_size;

    unsigned char tlv_type, tlv_len, *tlv_value = NULL;

	buff = pkt_info->pkt_print_buffer;
	pkt_size = pkt_info->pkt_size;

    unsigned char* lsp_pkt = (unsigned char *)(pkt_info->pkt);

	assert(pkt_info->protocol_no == ISIS_ETH_PKT_TYPE);

    rc = sprintf(buff, "ISIS_LSP_PKT_TYPE : ");

    pkt_info->bytes_written = rc;
}

static void
isis_print_hello_pkt(pkt_info_t *pkt_info ) {

    int rc = 0;
	char *buff;
	uint32_t pkt_size;

    unsigned char tlv_type, tlv_len, *tlv_value = NULL;

	buff = pkt_info->pkt_print_buffer;
	pkt_size = pkt_info->pkt_size;

    char* hpkt = (char *)(pkt_info->pkt);

	assert(pkt_info->protocol_no == ISIS_ETH_PKT_TYPE);

    rc = sprintf(buff, "ISIS_PTP_HELLO_PKT_TYPE : ");

    ITERATE_TLV_BEGIN(((char *)hpkt + sizeof(isis_pkt_type_t)), tlv_type,
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
            case ISIS_TLV_HOLD_TIME:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_METRIC_VAL:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            default:    ;
        }

    } ITERATE_TLV_END(((char *)hpkt + sizeof(uint16_t)), tlv_type,
                        tlv_len, tlv_value, pkt_size)
    
    rc -= strlen(" :: ");
    pkt_info->bytes_written = rc;
}


void
isis_print_pkt(void *arg, size_t arg_size) {

    pkt_info_t *pkt_info = (pkt_info_t *)arg;

	unsigned char *buff = pkt_info->pkt_print_buffer;
	size_t pkt_size = pkt_info->pkt_size;

    unsigned char* pkt = (char *)(pkt_info->pkt);

	assert(pkt_info->protocol_no == ISIS_ETH_PKT_TYPE);

    isis_pkt_type_t pkt_type = ISIS_PKT_TYPE(pkt);

    switch(pkt_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            isis_print_hello_pkt(pkt_info);
            break;
        case ISIS_LSP_PKT_TYPE:
            isis_print_lsp_pkt(pkt_info);
            break;
        default: ;
    }
}

void
isis_cancel_lsp_pkt_generation_task(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    
    if (!isis_node_info ||
         !isis_node_info->isis_lsp_pkt_gen_task) {

        return;
    }

    task_cancel_job(isis_node_info->isis_lsp_pkt_gen_task);
    isis_node_info->isis_lsp_pkt_gen_task = NULL;    
}

