#include "../../tcp_public.h"
#include "../../vrf/vrf.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_lspdb.h"
#include "isis_spf.h"
#include "isis_policy.h"
#include "isis_ted.h"
#include "isis_tlv_struct.h"
#include "isis_utils.h"

bool
isis_hello_pkt_trap_rule(char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

	if (eth_hdr->type == htons(ISIS_HELLO_ETH_PKT_TYPE)) {
		return true;
	}

	return false;
}

bool
isis_lsp_pkt_trap_rule(char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

	if (eth_hdr->type == htons(ISIS_LSP_ETH_PKT_TYPE)) {
		return true;
	}

	return false;
}

static void
isis_process_hello_pkt(isis_node_info_t *node_info,
                       Interface *iif,
                       ethernet_hdr_t *hello_eth_hdr,
                       size_t pkt_size) {

    char adj_name[128];
    uint32_t rcvd_if_ip;
    uint8_t intf_ip_len;
    pkt_size_t tlv_buff_size;
    uint32_t *if_ip_addr_int;
    isis_common_hdr_t  *cmn_hdr;
    byte *hello_tlv_buffer = NULL;
    isis_intf_info_t *intf_info = NULL;
    isis_adjacency_t *adjacency = NULL;    

    if (!isis_is_protocol_enable_on_intf(iif)) return;

    intf_info = ISIS_INTF_INFO (iif);

    /* Use the same fn for recv qualification as well */
    if (!isis_interface_qualify_to_send_hellos(iif)) {
        return;
    }
    
    /*Reject the pkt if dst mac is not Broadcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        
        tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
            "Interface %s recvd Bad Hello Packet - Malformed MAC\n", iif->if_name.c_str());
        goto bad_hello;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * recipient interface*/
   cmn_hdr = (isis_common_hdr_t  *)
        GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    
    hello_tlv_buffer = isis_get_pkt_tlv_buffer (cmn_hdr, &tlv_buff_size);
    
    /* Check for corrupted packet */
    if (!hello_tlv_buffer) {
        tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
            "Interface %s recvd Bad Hello Packet - no TLV Buffer in pkt\n", iif->if_name.c_str());        
        goto bad_hello;
    }

    /* Reject the hello pkt if it is not compatibe with reciepient interface type*/
    if (intf_info->intf_type == isis_intf_type_p2p) {

        if (cmn_hdr->pdu_type != ISIS_PTP_HELLO_PKT_TYPE) {
            
            tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
            "Interface %s recvd Bad Hello Packet - Incompatible Hello Packet\n", iif->if_name.c_str());   
            goto bad_hello;
        }
    }
    else {

        if (cmn_hdr->pdu_type != ISIS_LAN_L1_HELLO_PKT_TYPE &&
                cmn_hdr->pdu_type != ISIS_LAN_L2_HELLO_PKT_TYPE) {
            
            tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
                "Interface %s recvd Bad Hello Packet - Incompatible Hello Packet\n", iif->if_name.c_str());  

            goto bad_hello;
        }
    }

    /*Fetch the IF IP Address Value from TLV buffer*/
    if_ip_addr_int = (uint32_t *)tlv_buffer_get_particular_tlv(
                        hello_tlv_buffer,
                        tlv_buff_size,
                        ISIS_TLV_IF_IP,
                        &intf_ip_len);

    /*If no Intf IP, then it is a bad hello*/
    if (!if_ip_addr_int) {
    
        tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
            "Interface %s recvd Bad Hello Packet - No Intf IP address found\n", iif->if_name.c_str());  
            goto bad_hello;
    }

    /* Use a local variable to avoid modifying the cached packet buffer in-place.
     * The hello pkt_block is reused across hello intervals; writing back via
     * if_ip_addr_int would corrupt it so every alternate hello arrives with a
     * byte-reversed IP, causing permanent subnet-mismatch failures. */
    rcvd_if_ip = ntohl(*if_ip_addr_int);

    if (!iif->IsSameSubnet(rcvd_if_ip)) {

       adjacency = isis_find_adjacency_on_interface(iif, 0);

        if (adjacency) {

            tracer(ISIS_TR(ISIS_CTX_INTF(iif)), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
                "%s : Adjacency %s will be brought down, bad hello recvd\n",
                ISIS_ERROR, isis_adjacency_name(adj_name, sizeof(adj_name), adjacency));
            isis_change_adjacency_state(adjacency, ISIS_ADJ_STATE_DOWN);
        }

        tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
            "Interface %s recvd Bad Hello Packet - Mismatch Subnet\n", iif->if_name.c_str());  

        {
            /* Log ... */
            uint32_t intf_ip_addr; uint8_t mask;
            iif->InterfaceGetIpAddressMask(&intf_ip_addr, &mask);
            char intf_ip_addr_str[16];
            char hello_ip_addr_str[16];
            tcp_ip_covert_ip_n_to_p (intf_ip_addr, intf_ip_addr_str);
            tcp_ip_covert_ip_n_to_p (rcvd_if_ip, hello_ip_addr_str);

            tracer(ISIS_TR(node_info), TR_ISIS_PKT_HELLO | TR_ISIS_ERRORS,
                "Interface %s : %s/%d , hello IP addr rcvd : %s\n", 
                iif->if_name.c_str(), intf_ip_addr_str, mask, hello_ip_addr_str);
        }

        goto bad_hello;
    }

    isis_update_interface_adjacency_from_hello (
        iif, cmn_hdr, 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD);

    return ;

    bad_hello:
    ISIS_INTF_INCREMENT_STATS(iif, bad_hello_pkt_recvd);
}


static void
isis_process_lsp_pkt(isis_node_info_t *node_info,
                     Interface *iif,
                     ethernet_hdr_t *lsp_eth_hdr,
                     size_t pkt_size) {

    uint32_t *seq_no;
    isis_lsp_pkt_t *new_lsp_pkt;
    isis_intf_info_t *intf_info;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    
    if (!isis_is_protocol_enable_on_intf(iif)) return;
    if (!isis_any_adjacency_up_on_interface(iif)) return;
    if (isis_is_protocol_shutdown_in_progress(node_info)) return;
    intf_info = ISIS_INTF_INFO(iif);

    ISIS_INTF_INCREMENT_STATS(iif, good_lsps_pkt_recvd);

    new_lsp_pkt = XCALLOC2(0, 1, isis_lsp_pkt_t);
    new_lsp_pkt->flood_eligibility = true;
    new_lsp_pkt->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
    memcpy(new_lsp_pkt->pkt, (byte *)lsp_eth_hdr, pkt_size);
    new_lsp_pkt->pkt_size = pkt_size;
    new_lsp_pkt->alloc_size = pkt_size;

    isis_ref_isis_pkt(new_lsp_pkt);

    tracer (ISIS_TR (node_info), TR_ISIS_PKT_LSP | TR_ISIS_EVENTS,
        "%s : lsp %s recvd on intf %s\n",
       ISIS_PKT, isis_print_lsp_id(new_lsp_pkt, lsp_id_str), iif ? iif->if_name.c_str() : 0);

    isis_install_lsp(node_info, iif, new_lsp_pkt);
    isis_deref_isis_pkt(node_info, new_lsp_pkt);
}

void
isis_lsp_pkt_recieve_cbk (event_dispatcher_t *ev_dis, void *arg, size_t arg_size) {

    isis_node_info_t *node_info;
    node_t *node;
    Interface *iif;
    pkt_size_t pkt_size;
    hdr_type_t hdr_code;
    ethernet_hdr_t *eth_hdr;
    isis_pkt_hdr_t *pkt_hdr;
    pkt_block_t *pkt_block;
    isis_pkt_type_t isis_pkt_type;
    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = node_get_intf_by_ifindex (node, pkt_notif_data->recv_intf_index);
    node_info   = iif->vrf->isis_node_info;
    pkt_block = pkt_notif_data->pkt_block;
    eth_hdr     = (ethernet_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
	hdr_code    = pkt_notif_data->hdr_code;	
    
    if (hdr_code != ETH_HDR) goto done;
    
    if (!node_info || !isis_is_protocol_enable_on_node(iif->vrf)) {
        goto done;
    }

    pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    isis_pkt_type = pkt_hdr->isis_pkt_type;

    switch(isis_pkt_type) {

        case ISIS_PTP_HELLO_PKT_TYPE:
        case ISIS_LAN_L1_HELLO_PKT_TYPE:
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            isis_process_hello_pkt(node_info, iif, eth_hdr, pkt_size); 
        break;
        case ISIS_L1_LSP_PKT_TYPE:
            isis_process_lsp_pkt(node_info, iif, eth_hdr, pkt_size);
        break;
        default:; 
    }
    done:
    /* Free the pkt resources */
    pkt_block_dereference(pkt_notif_data->pkt_block);
    pkt_notif_data->pkt_block = NULL;
    XFREE(pkt_notif_data);    
}

void
isis_hello_pkt_recieve_cbk (event_dispatcher_t *ev_dis, void *arg, size_t arg_size) {

    isis_node_info_t *node_info;
    node_t *node;
    Interface *iif;
    pkt_size_t pkt_size;
    hdr_type_t hdr_code;
    ethernet_hdr_t *eth_hdr;
    pkt_block_t *pkt_block;
    isis_common_hdr_t *cmn_hdr;
    isis_pkt_type_t isis_pkt_type;
    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = node_get_intf_by_ifindex(node, pkt_notif_data->recv_intf_index);
    node_info   = iif->vrf->isis_node_info;
    pkt_block = pkt_notif_data->pkt_block;
    eth_hdr     = (ethernet_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
	hdr_code    = pkt_notif_data->hdr_code;	
   
    if (hdr_code != ETH_HDR) goto done;
    
    if (!node_info || !isis_is_protocol_enable_on_node(iif->vrf)) {
        goto done;
    }

    cmn_hdr = (isis_common_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    isis_pkt_type = cmn_hdr->pdu_type;

    switch(isis_pkt_type) {

        case ISIS_PTP_HELLO_PKT_TYPE:
        case ISIS_LAN_L1_HELLO_PKT_TYPE:
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            isis_process_hello_pkt(node_info, iif, eth_hdr, pkt_size); 
        break;
        case ISIS_L1_LSP_PKT_TYPE:
        case ISIS_L2_LSP_PKT_TYPE:
            isis_process_lsp_pkt(node_info, iif, eth_hdr, pkt_size);
        break;
        default:; 
    }
    done:
    /* Free the pkt resources */
    pkt_block_dereference(pkt_notif_data->pkt_block);
    pkt_notif_data->pkt_block = NULL;
    XFREE(pkt_notif_data);    
}

byte *
isis_prepare_hello_pkt(Interface *intf, pkt_size_t *hello_pkt_size) {

    byte *temp;
    isis_node_info_t *node_info;
    uint32_t rtr_id;
    uint8_t pdu_type ;
    uint32_t int_ip_addr;
    isis_intf_info_t *intf_info;
    uint8_t combined_hdr_size;
    isis_common_hdr_t *cmn_hdr;
    isis_lan_hello_pkt_hdr_t *lan_hdr;
    isis_p2p_hello_pkt_hdr_t *p2p_hdr;

    intf_info = ISIS_INTF_INFO(intf);

    combined_hdr_size = sizeof(isis_common_hdr_t) ;

    if (intf_info->intf_type == isis_intf_type_p2p) {
        pdu_type = ISIS_PTP_HELLO_PKT_TYPE;
        combined_hdr_size += sizeof(isis_p2p_hello_pkt_hdr_t);
    }
    else {
        pdu_type = (intf_info->level == isis_level_1) ? \
            ISIS_LAN_L1_HELLO_PKT_TYPE : ISIS_LAN_L2_HELLO_PKT_TYPE;
        combined_hdr_size += sizeof(isis_lan_hello_pkt_hdr_t);
    }

    uint32_t eth_hdr_playload_size = 
                combined_hdr_size + 
                (TLV_OVERHEAD_SIZE * 7) +   /*There shall be Seven TLVs, hence 7 TLV overheads*/
                NODE_NAME_SIZE +                  /* Data length of TLV: ISIS_TLV_NODE_NAME*/
                4  +                 /* Data length of ISIS_TLV_RTR_ID which is 4*/
                4   +                /* Data length of ISIS_TLV_IF_IP which is 16*/
                4   +                /* Data length of ISIS_TLV_IF_INDEX which is 4*/
                4   +                /* Data length for ISIS_ISIS_TLV_HOLD_TIME */
                4   +                /* Data length for ISIS_ISIS_TLV_METRIC_VAL */
                6;                    /* MAc Address */

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + /*Dst Mac + Src mac + type field + FCS field*/
                                  eth_hdr_playload_size;

    ethernet_hdr_t *hello_eth_hdr =
        (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*hello_pkt_size);

    memset(hello_eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    hello_eth_hdr->type = htons(ISIS_HELLO_ETH_PKT_TYPE);

    node_info = ISIS_CTX_INTF(intf);
    cmn_hdr = (isis_common_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    isis_init_common_hdr (cmn_hdr, pdu_type);

    switch (pdu_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            p2p_hdr = (isis_p2p_hello_pkt_hdr_t *)(cmn_hdr + 1);
            isis_init_p2p_hello_pkt_hdr (p2p_hdr, intf);
            p2p_hdr->pdu_len = htons(eth_hdr_playload_size);
        break;
        case ISIS_LAN_L1_HELLO_PKT_TYPE:
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            lan_hdr = (isis_lan_hello_pkt_hdr_t *)(cmn_hdr + 1);
            isis_init_lan_hello_pkt_hdr (lan_hdr, intf);
            lan_hdr->pdu_len = htons(eth_hdr_playload_size);
        break;
        default: ;
    }

    temp = (byte *)(cmn_hdr) + combined_hdr_size;

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOSTNAME, 
                                                  NODE_NAME_SIZE,
                                                  node_info->vrf->node->node_name);

    rtr_id = htonl(tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node_info->vrf->node)));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID,
                                                   4, 
                                                   (byte *)(&rtr_id));

    int_ip_addr = htonl(IF_IP(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP, 
                                                  4, 
                                                  (byte *)&int_ip_addr);

    uint32_t ifindex = htonl(intf->ifindex);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_INDEX,
                                                    4, 
                                                    (byte *)&ifindex);

    uint32_t hold_time =
        htonl(ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME,
                                                    4,
                                                    (byte *)&hold_time);

    uint32_t cost = htonl(ISIS_INTF_COST(intf));

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL,
                                                 4,
                                                 (byte *)&cost);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_MAC,
                                                    6,
                                                    IF_MAC(intf) );

    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_hdr_playload_size, 0);
    return (byte *)hello_eth_hdr;  
}

static uint32_t
isis_print_lsp_pkt(byte *buff, 
                              isis_pkt_hdr_t *lsp_pkt_hdr,
                              uint32_t pkt_size ) {

    uint32_t rc = 0;
    char ip_addr[IPV4_ADDR_LEN_STR];

    byte tlv_type, tlv_len, *tlv_value = NULL;

    rc = sprintf((char *)(buff + rc), "ISIS_L1_LSP_PKT_TYPE : ");

    uint32_t seq_no = lsp_pkt_hdr->seq_no;
    uint32_t rtr_id = lsp_pkt_hdr->rtr_id;
    tcp_ip_covert_ip_n_to_p(rtr_id, ip_addr);

    rc += sprintf((char *)(buff + rc), "LSP pkt : %s-%hu-%hu[%u]   , pkt size = %hu\n",
                    ip_addr, lsp_pkt_hdr->pn_no,  lsp_pkt_hdr->fr_no, seq_no, (pkt_size_t)pkt_size);

    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);
    pkt_size_t lsp_tlv_buffer_size = (pkt_size_t)(pkt_size - sizeof(isis_pkt_hdr_t));

    ITERATE_TLV_BEGIN(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size) {

        switch(tlv_type) {
            case ISIS_TLV_HOSTNAME:
                rc += sprintf((char *)(buff + rc), "\tTLV%d Host-Name : %s\n",
                        tlv_type, tlv_value);
                break;
            case ISIS_IS_REACH_TLV:
                rc += isis_format_nbr_tlv22 (buff + rc,
                            tlv_value - TLV_OVERHEAD_SIZE,
                            tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_IP_REACH:
                rc += isis_print_formatted_tlv130(buff + rc, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_IPV6_REACH:
                rc += isis_print_formatted_tlv236(buff + rc, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_LOCATOR:
                rc += isis_print_formatted_tlv27(buff + rc, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            default: ;
        }
    } ITERATE_TLV_END(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size);
    return rc;
}

const c_string 
isis_pkt_type_str (isis_pkt_type_t pkt_type) {

    switch (pkt_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            return "ISIS_PTP_HELLO_PKT_TYPE";
        case ISIS_LAN_L1_HELLO_PKT_TYPE:
            return "ISIS_LAN_L1_HELLO_PKT_TYPE";
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            return "ISIS_LAN_L2_HELLO_PKT_TYPE"; 
        case ISIS_L1_LSP_PKT_TYPE:
            return "ISIS_L1_LSP_PKT_TYPE";
        default: ;
    }
    return NULL;
}

static uint32_t
isis_print_hello_pkt(byte *buff, 
                                  isis_common_hdr_t *cmn_hdr,
                                  pkt_size_t pkt_size ) {

    uint32_t rc = 0;
    byte ip_addr_str[IPV4_ADDR_LEN_STR];
    byte system_lan_id_str[2][32];
    isis_lan_hello_pkt_hdr_t *lan_hdr;
    isis_p2p_hello_pkt_hdr_t *p2p_hdr;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    rc = sprintf((char *)(buff + rc), "  cmn hdr : %d %d %d %d %s %d %d %d\n",
            cmn_hdr->desc,
            cmn_hdr->length_indicator,
            cmn_hdr->protocol,
            cmn_hdr->id_len,
            isis_pkt_type_str(cmn_hdr->pdu_type),
            cmn_hdr->version,
            cmn_hdr->reserved,
            cmn_hdr->max_area_addr);

    switch (cmn_hdr->pdu_type) {

        case ISIS_PTP_HELLO_PKT_TYPE:
            p2p_hdr = (isis_p2p_hello_pkt_hdr_t *)(cmn_hdr + 1);
            rc += sprintf((char *)(buff + rc), "    p2p hdr : ctype %d srcid %s ht %d len %d cid %d\n",
                p2p_hdr->circuit_type,
                isis_system_id_tostring(&p2p_hdr->source_id, system_lan_id_str[0]),
                p2p_hdr->hold_time,
                p2p_hdr->pdu_len,
                p2p_hdr->local_circuit_id);
            break;
        case ISIS_LAN_L1_HELLO_PKT_TYPE:
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            lan_hdr = (isis_lan_hello_pkt_hdr_t *)(cmn_hdr + 1);
            rc += sprintf((char *)(buff + rc), "    lan hdr : ctype %d srcid %s ht %d len %d pr %d lan-id %s\n",
                lan_hdr->circuit_type,
                isis_system_id_tostring(&lan_hdr->source_id, system_lan_id_str[0]),
                lan_hdr->hold_time,
                lan_hdr->pdu_len,
                lan_hdr->priority,
                isis_lan_id_tostring(&lan_hdr->lan_id, system_lan_id_str[1]));
        break;
    }

    rc += sprintf((char *)(buff + rc), "      ");

    pkt_size_t hello_tlv_buffer_size;
    byte *hello_tlv_buffer = isis_get_pkt_tlv_buffer (cmn_hdr, &hello_tlv_buffer_size);

    ITERATE_TLV_BEGIN(hello_tlv_buffer , tlv_type,
                        tlv_len, tlv_value, hello_tlv_buffer_size){

        switch(tlv_type){
            case ISIS_TLV_IF_INDEX:
                rc += sprintf((char *)(buff + rc), "%d %d %u :: ",
                    tlv_type, tlv_len, *(uint32_t *)(tlv_value));
            break;
            case ISIS_TLV_HOSTNAME:
                rc += sprintf((char *)(buff + rc), "%d %d %s :: ", tlv_type, tlv_len, tlv_value);
                break;
            case ISIS_TLV_RTR_ID:
            case ISIS_TLV_IF_IP:
                tcp_ip_covert_ip_n_to_p(htonl(*(uint32_t *)tlv_value), ip_addr_str);
                rc += sprintf((char *)(buff + rc), "%d %d %s :: ", tlv_type, tlv_len, ip_addr_str);
                break;
            case ISIS_TLV_HOLD_TIME:
                rc += sprintf((char *)(buff + rc), "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_METRIC_VAL:
                rc += sprintf((char *)(buff + rc), "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_IF_MAC:
                rc += sprintf((char *)(buff + rc), "%d %d %02x:%02x:%02x:%02x:%02x:%02x :: ",
                     tlv_type, tlv_len, tlv_value[0], tlv_value[1], tlv_value[2],
                     tlv_value[3], tlv_value[4], tlv_value[5]);
                break;    
            default:    ;
        }
    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, hello_tlv_buffer_size)
    
    rc -= strlen(" :: ");
    return rc;
}

void
isis_print_lsp_pkt_cbk (event_dispatcher_t*ev_dis, void *arg, size_t arg_size) {

    byte *buff;
    pkt_size_t pkt_size;
    pkt_info_t *pkt_info;
    isis_pkt_hdr_t *pkt_hdr;
    pkt_block_t *pkt_block;

    pkt_info = (pkt_info_t *)arg;
	buff = pkt_info->pkt_print_buffer;
    pkt_block = pkt_info->pkt_block;
    pkt_hdr = (isis_pkt_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size); 

    pkt_info->bytes_written = 0;
	assert(pkt_info->protocol_no == ISIS_LSP_ETH_PKT_TYPE);
    pkt_info->bytes_written += isis_print_lsp_pkt(buff, pkt_hdr, pkt_size);
}

void
isis_print_hello_pkt_cbk (event_dispatcher_t*ev_dis, void *arg, unsigned int arg_size) {

    byte *buff;
    pkt_size_t pkt_size;
    pkt_info_t *pkt_info;
    pkt_block_t *pkt_block;
    isis_common_hdr_t *cmn_hdr;

    pkt_info = (pkt_info_t *)arg;
	buff = pkt_info->pkt_print_buffer;
    pkt_block = pkt_info->pkt_block;
    cmn_hdr = (isis_common_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size); 

    pkt_info->bytes_written = 0;
	assert(pkt_info->protocol_no == ISIS_HELLO_ETH_PKT_TYPE);
    pkt_info->bytes_written += isis_print_hello_pkt(buff, cmn_hdr, pkt_size);
}

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return &lsp_hdr->rtr_id;
}

pn_id_t
isis_get_lsp_pkt_pn_id (isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return lsp_hdr->pn_no;
}

isis_pkt_type_t
isis_get_pdu_type (isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return lsp_hdr->isis_pkt_type;
}

uint8_t
isis_get_lsp_pkt_fr_no (isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return lsp_hdr->fr_no;
}

uint32_t *
isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return &lsp_hdr->seq_no;
}

static void
lsp_pkt_flood_timer_cbk (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    uint32_t *seq_no;
    ted_node_t *ted_node;
    isis_lsp_pkt_t *lsp_pkt;
    isis_node_info_t *node_info;
    
    isis_timer_data_t *timer_data = (isis_timer_data_t *)arg;
    
    lsp_pkt = (isis_lsp_pkt_t *)timer_data->data;
    node_info = timer_data->node_info;

    seq_no = isis_get_lsp_pkt_seq_no (lsp_pkt);
    (*seq_no)++;
    lsp_pkt->fragment->seq_no = *seq_no;
    isis_ted_update_or_install_lsp (node_info, node_info->ted_db, lsp_pkt);
    isis_ips_send_lsp_seqno_update (node_info, lsp_pkt);
    isis_schedule_lsp_flood (node_info, lsp_pkt, NULL);
}

void
isis_lsp_pkt_flood_timer_start (isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt) {

    if (lsp_pkt->periodic_lsp_flood_timer) return;

    isis_timer_data_t *timer_data = (isis_timer_data_t *)XCALLOC2(0, 1, isis_timer_data_t);
    timer_data->node_info = node_info;
    timer_data->data = (void *)lsp_pkt;
    timer_data->data_size = sizeof(void *);
    isis_ref_isis_pkt(lsp_pkt);

    lsp_pkt->periodic_lsp_flood_timer = timer_register_app_event (CP_TIMER(node_info->vrf->node),
                                                                    lsp_pkt_flood_timer_cbk,
                                                                    timer_data, sizeof(*timer_data), 
                                                                    node_info->lsp_flood_interval * 1000,
                                                                    1);
}

void
isis_lsp_pkt_flood_timer_stop (isis_lsp_pkt_t *lsp_pkt) {

     if (!lsp_pkt->periodic_lsp_flood_timer) return;

     isis_timer_data_t *timer_data = (isis_timer_data_t *)
                                wt_elem_get_and_set_app_data(
                                lsp_pkt->periodic_lsp_flood_timer, 0);

     timer_de_register_app_event (lsp_pkt->periodic_lsp_flood_timer);
     lsp_pkt->periodic_lsp_flood_timer = NULL;

     isis_deref_isis_pkt(timer_data->node_info, (isis_lsp_pkt_t *)timer_data->data);
     timer_data->data = NULL;
     XFREE(timer_data);
}

void
isis_lsp_pkt_flood_timer_restart (isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt) {

    if (!lsp_pkt->periodic_lsp_flood_timer) return;
    isis_lsp_pkt_prevent_premature_deletion(lsp_pkt);
    isis_lsp_pkt_flood_timer_stop (lsp_pkt);
    isis_lsp_pkt_flood_timer_start (node_info, lsp_pkt);
    isis_lsp_pkt_relieve_premature_deletion(node_info, lsp_pkt);
}

uint32_t
isis_deref_isis_pkt(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt) {

    uint32_t rc;

    assert(lsp_pkt->ref_count);

    lsp_pkt->ref_count--;
    rc = lsp_pkt->ref_count;

    if ( rc ) return rc;

    /* Check other objects must not hold a reference to it*/
    assert(!lsp_pkt->installed_in_db);
    
    if (lsp_pkt->fragment) {
        assert (lsp_pkt->fragment->lsp_pkt != lsp_pkt);
    }

    /* release the resources held by this pkt buffer */
    tcp_ip_free_pkt_buffer(lsp_pkt->pkt, lsp_pkt->alloc_size);
    /* Stop the associated timers */
    isis_lsp_pkt_flood_timer_stop(lsp_pkt);

    if (lsp_pkt->expiry_timer) {

        isis_timer_data_t *timer_data = (isis_timer_data_t *)
            wt_elem_get_and_set_app_data(lsp_pkt->expiry_timer, 0);
        XFREE(timer_data);
        timer_de_register_app_event(lsp_pkt->expiry_timer);
        lsp_pkt->expiry_timer = NULL;
    }

    /* dissociate the fragment*/
    if (lsp_pkt->fragment) {

        isis_fragment_unlock(node_info, lsp_pkt->fragment);
        lsp_pkt->fragment = NULL;
    }
    XFREE(lsp_pkt);

    /* Caller may use the return value as zero to know that lsp
        pkt is actually freed */
    return rc;
}

void
isis_ref_isis_pkt(isis_lsp_pkt_t *isis_pkt) {

    isis_pkt->ref_count++;
}

isis_pkt_hdr_flags_t
isis_lsp_pkt_get_flags(isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    return lsp_hdr->flags;
}

uint16_t
isis_count_tlv_occurrences (byte *tlv_buffer,
                                              pkt_size_t tlv_buff_size, uint8_t tlv_no) {

    uint16_t rc = 0;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(tlv_buffer , tlv_type,
                        tlv_len, tlv_value, tlv_buff_size){

        if (tlv_type == tlv_no) rc++;

    } ITERATE_TLV_END(tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buff_size);
    return rc;
}

isis_common_hdr_t *
isis_init_common_hdr (isis_common_hdr_t *hdr, uint8_t pdu_type) {

    hdr->desc = 0x83;
    hdr->length_indicator = sizeof (isis_common_hdr_t ) + 
                                            (pdu_type == ISIS_PTP_HELLO_PKT_TYPE) ?     \
                                            sizeof(isis_p2p_hello_pkt_hdr_t) : sizeof (isis_lan_hello_pkt_hdr_t);
    hdr->protocol = 1;
    hdr->id_len = sizeof(isis_system_id_t);
    hdr->pdu_type = pdu_type;
    hdr->version = 1;
    hdr->reserved = 0;
    hdr->max_area_addr = 3;
    return hdr;
}

isis_p2p_hello_pkt_hdr_t *
isis_init_p2p_hello_pkt_hdr (isis_p2p_hello_pkt_hdr_t *hdr, Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);
    isis_node_info_t *node_info = ISIS_CTX_INTF(intf);
    hdr->circuit_type = intf_info->level; 
    hdr->source_id = node_info->sys_id;
    hdr->hold_time = htons(intf_info->hello_interval * ISIS_HOLD_TIME_FACTOR);
    hdr->pdu_len = 0; /* Total len of pdu in bytes*/
    hdr->local_circuit_id = intf->ifindex;
    return hdr;
}

isis_lan_hello_pkt_hdr_t *
isis_init_lan_hello_pkt_hdr (isis_lan_hello_pkt_hdr_t *hdr, Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);
    isis_node_info_t *node_info = ISIS_CTX_INTF(intf);
    hdr->circuit_type =  intf_info->level;  
    hdr->source_id = node_info->sys_id;
    hdr->source_id.rtr_id = tcp_ip_convert_ip_p_to_n (NODE_RTRID_ADDR(node_info->vrf->node));
    hdr->hold_time = htons(intf_info->hello_interval * ISIS_HOLD_TIME_FACTOR);
    hdr->pdu_len = 0; /* Total len of pdu in bytes*/
    hdr->priority = intf_info->priority;
    memcpy (&hdr->lan_id, &intf_info->lan_id, sizeof(isis_lan_id_t));
    return hdr;
}

byte *
isis_get_pkt_tlv_buffer (isis_common_hdr_t *cmn_hdr, pkt_size_t *tlv_size) {

    isis_p2p_hello_pkt_hdr_t *p2p_hdr;
    isis_lan_hello_pkt_hdr_t *lan_hdr;
    uint16_t calculated_tlv_size;
    uint16_t pdu_len;

    *tlv_size = 0;

    switch (cmn_hdr->pdu_type) {

        case ISIS_PTP_HELLO_PKT_TYPE:
            p2p_hdr = (isis_p2p_hello_pkt_hdr_t *)(cmn_hdr + 1);
            pdu_len = htons(p2p_hdr->pdu_len);
            
            /* Validate pdu_len to prevent buffer overrun */
            if (pdu_len < (sizeof(isis_common_hdr_t) + sizeof(isis_p2p_hello_pkt_hdr_t))) {
                /* Invalid pdu_len, too small */
                return NULL;
            }
            
            calculated_tlv_size = pdu_len - sizeof(isis_common_hdr_t ) - sizeof(isis_p2p_hello_pkt_hdr_t);
            
            /* Sanity check: TLV size should not exceed reasonable limits */
            if (calculated_tlv_size > MAX_PACKET_BUFFER_SIZE - sizeof(isis_common_hdr_t) - sizeof(isis_p2p_hello_pkt_hdr_t)) {
                /* Corrupted pdu_len */
                return NULL;
            }
            
            *tlv_size = calculated_tlv_size;
            return (byte *)(cmn_hdr) + sizeof(isis_common_hdr_t ) + sizeof(isis_p2p_hello_pkt_hdr_t);

        case ISIS_LAN_L1_HELLO_PKT_TYPE:
        case ISIS_LAN_L2_HELLO_PKT_TYPE:
            lan_hdr =  (isis_lan_hello_pkt_hdr_t *)(cmn_hdr + 1);
            pdu_len = htons(lan_hdr->pdu_len);
            
            /* Validate pdu_len to prevent buffer overrun */
            if (pdu_len < (sizeof(isis_common_hdr_t) + sizeof(isis_lan_hello_pkt_hdr_t))) {
                /* Invalid pdu_len, too small */
                return NULL;
            }
            
            calculated_tlv_size = pdu_len - sizeof(isis_common_hdr_t ) - sizeof(isis_lan_hello_pkt_hdr_t);
            
            /* Sanity check: TLV size should not exceed reasonable limits */
            if (calculated_tlv_size > MAX_PACKET_BUFFER_SIZE - sizeof(isis_common_hdr_t) - sizeof(isis_lan_hello_pkt_hdr_t)) {
                /* Corrupted pdu_len */
                return NULL;
            }
            
            *tlv_size = calculated_tlv_size;
            return (byte *)(cmn_hdr) + sizeof(isis_common_hdr_t ) + sizeof(isis_lan_hello_pkt_hdr_t);

        case ISIS_L1_LSP_PKT_TYPE:
        case ISIS_L2_LSP_PKT_TYPE:
        break;
    }
    return NULL;
}
