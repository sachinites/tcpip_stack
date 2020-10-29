#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <stdint.h>
#include "nbrship_mgmt.h"

#define ADJ_DEF_EXPIRY_TIMER    10

typedef struct pkt_meta_data_{

    interface_t *intf;
    char *pkt;
    uint32_t pkt_size;
} pkt_meta_data_t;

static void
nmp_print_hello_pkt(void *arg, size_t arg_size){

    int rc = 0;
	char *buff;
	uint32_t pkt_size;

    unsigned char tlv_type, tlv_len, *tlv_value = NULL;

	pkt_info_t *pkt_info = (pkt_info_t *)arg;

	buff = pkt_info->pkt_print_buffer;
	pkt_size = pkt_info->pkt_size;

    hello_t *hpkt = (hello_t *)(pkt_info->pkt);

	assert(pkt_info->protocol_no == NMP_HELLO_MSG_CODE);

    rc = sprintf(buff, "NMP_HELLO_MSG_CODE : ");

    ITERATE_TLV_BEGIN(hpkt->tlv_buff, tlv_type, tlv_len, tlv_value, pkt_size){

        switch(tlv_type){
            case TLV_IF_MAC:
                rc += sprintf(buff + rc, "%d %d %02x:%02x:%02x:%02x:%02x:%02x :: ", 
                    tlv_type, tlv_len, 
                    tlv_value[0], tlv_value[1], tlv_value[2],
                    tlv_value[3], tlv_value[4], tlv_value[5]);
            break;
            case TLV_NODE_NAME:
            case TLV_RTR_ID:
            case TLV_IF_IP:
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, tlv_value);
                break;
            default:    ;
        }

    } ITERATE_TLV_END(hpkt->tlv_buff, tlv_type, tlv_len, tlv_value, pkt_size);
    
    rc -= strlen(" :: ");
    pkt_info->bytes_written = rc;
}

static void 
transmit_hellos(void *arg, uint32_t sizeof_arg){

    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)arg;
    send_pkt_out(pkt_meta_data->pkt, pkt_meta_data->pkt_size,
            pkt_meta_data->intf);
    intf_nmp_t *intf_nmp = NMP_GET_INTF_NMPDS(pkt_meta_data->intf);
    assert(intf_nmp);
    intf_nmp->sent++;
}

ethernet_hdr_t *
get_new_hello_pkt(node_t *node,
               	 interface_t *interface,
        		 uint32_t *pkt_size){

    char *temp = NULL;
    uint32_t eth_hdr_playload_size = 
                (TLV_OVERHEAD_SIZE * 4) + /*There shall be four TLVs, hence 4 TLV overheads*/
                NODE_NAME_SIZE +    /*Data length of TLV: TLV_NODE_NAME*/
                16 +                /*Data length of TLV_RTR_NAME which is 16*/
                16 +                /*Data length of TLV_IF_IP which is 16*/
                6;                  /*Data length of TLV_IF_MAC which is 6*/

    *pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + /*Dst Mac + Src mac + type field + FCS field*/
                eth_hdr_playload_size;

    ethernet_hdr_t *hello_eth_hdr = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*pkt_size);

    memcpy(hello_eth_hdr->src_mac.mac, IF_MAC(interface), sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac);
    hello_eth_hdr->type = NMP_HELLO_MSG_CODE;
    
    hello_t *hello_payload = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    temp = hello_payload->tlv_buff;
    temp = tlv_buffer_insert_tlv(temp, TLV_NODE_NAME, NODE_NAME_SIZE, node->node_name);
    temp = tlv_buffer_insert_tlv(temp, TLV_RTR_ID, 16, NODE_LO_ADDR(node));
    temp = tlv_buffer_insert_tlv(temp, TLV_IF_IP,  16, IF_IP(interface));
    temp = tlv_buffer_insert_tlv(temp, TLV_IF_MAC, 6,  IF_MAC(interface));
    ETH_FCS(hello_eth_hdr, eth_hdr_playload_size) = 0;
    return hello_eth_hdr;
}

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, bool_t is_repeat){

    uint32_t pkt_size = 0;

    if(is_hellos_scheduled_on_intf(intf))
        return FALSE;

    if(!NMP_SHOULD_SCHEDULE_HELLO_ON_INTF(intf))
        return FALSE;

    node_t *node = intf->att_node;
   
    ethernet_hdr_t *hello_pkt = get_new_hello_pkt(node, intf, &pkt_size); 
    
    pkt_meta_data_t *pkt_meta_data = calloc(1, sizeof(pkt_meta_data_t));
    pkt_meta_data->intf = intf;
    pkt_meta_data->pkt = (char *)hello_pkt;
    pkt_meta_data->pkt_size = pkt_size;

    wheel_timer_elem_t *wt_elem = register_app_event(node_get_timer_instance(intf->att_node),
                                                     transmit_hellos,
                                                     (void *)pkt_meta_data,
                                                     sizeof(pkt_meta_data_t),
                                                     interval_sec,
                                                     is_repeat ? 1 : 0);
    intf->intf_nw_props.nmp->hellos = wt_elem;

    if(is_hellos_scheduled_on_intf(intf))
        return TRUE;

    return FALSE;
}

void
stop_interface_hellos(interface_t *interface){

    if(!is_hellos_scheduled_on_intf(interface))
        return;

    wheel_timer_elem_t *wt_elem = interface->intf_nw_props.nmp->hellos;
    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)wt_elem->arg;
    tcp_ip_free_pkt_buffer(pkt_meta_data->pkt, pkt_meta_data->pkt_size); 
	free(pkt_meta_data);
    de_register_app_event(wt_elem);
    interface->intf_nw_props.nmp->hellos = NULL;
}

static void
update_interface_adjacency_from_hello(interface_t *interface,
                                      hello_t *hello, 
                                      uint32_t tlv_buff_size){

    char *router_id;
    uint8_t tlv_data_len;
    bool_t new_adj = FALSE;
    adjacency_t *adjacency = NULL;

    router_id = tlv_buffer_get_particular_tlv(
                    hello->tlv_buff, 
                    tlv_buff_size,
                    TLV_RTR_ID, 
                    &tlv_data_len);

    adjacency = find_adjacency_on_interface(interface, router_id);

    if(!adjacency){
        adjacency = (adjacency_t *)calloc(1, sizeof(adjacency_t));
        init_glthread(&adjacency->glue);
        time(&adjacency->uptime);
        glthread_add_next(NMP_GET_INTF_ADJ_LIST(interface), &adjacency->glue);
        new_adj = TRUE;
    }

    char tlv_type, tlv_len, *tlv_value = NULL;
    ITERATE_TLV_BEGIN(hello->tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size){
        
        switch(tlv_type){
            case TLV_NODE_NAME:
                memcpy(adjacency->router_name, tlv_value, tlv_len);
            break;
            case TLV_RTR_ID:
                memcpy(adjacency->router_id, tlv_value, tlv_len);
            break;    
            case TLV_IF_IP:
                memcpy(adjacency->nbr_ip, tlv_value, tlv_len);
            break;
            case TLV_IF_MAC:
                memcpy(adjacency->nbr_mac.mac, tlv_value, tlv_len);
            break;
            default: ;
        }
    } ITERATE_TLV_END(tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    if(new_adj)
        adjacency_start_expiry_timer(interface, adjacency);
    else
        adjacency_refresh_expiry_timer(interface, adjacency);
    interface->intf_nw_props.nmp->recvd++;
}

static void
process_hello_msg(void *arg, size_t arg_size){

	char *pkt;
	node_t *node;
	uint32_t flags;
	interface_t *iif;
	uint32_t pkt_size;
	uint32_t protocol_no;

	pkt_notif_data_t *pkt_notif_data;

	pkt_notif_data = (pkt_notif_data_t *)arg;

	node 	 	= pkt_notif_data->recv_node;
	iif  	 	= pkt_notif_data->recv_interface;
	pkt  	 	= pkt_notif_data->pkt;
	flags 	 	= pkt_notif_data->flags;
	pkt_size 	= pkt_notif_data->pkt_size; 
	protocol_no = pkt_notif_data->protocol_no;

    uint8_t intf_ip_len;
    intf_nmp_t *nmp  = NMP_GET_INTF_NMPDS(iif);
    
    if(!nmp || !nmp->is_enabled) return;

    ethernet_hdr_t *hello_eth_hdr = (ethernet_hdr_t *)pkt;

	/*Reject the pkt if dst mac is not Brodcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        goto bad_hello;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * reciepient interface*/

    hello_t *hello = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    uint32_t tlv_buff_size = pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD; 

    /*Fetch the IF IP Address Value from TLV buffer*/
    char *if_ip_addr = tlv_buffer_get_particular_tlv(
                        hello->tlv_buff, 
                        tlv_buff_size, 
                        TLV_IF_IP, 
                        &intf_ip_len);

    /*If no Intf IP, then it is a bad hello*/
    if(!if_ip_addr) goto bad_hello;

    if(!is_same_subnet(IF_IP(iif), 
                       iif->intf_nw_props.mask, 
                       if_ip_addr)){
        goto bad_hello;
    }
    update_interface_adjacency_from_hello(iif, hello, tlv_buff_size);
    return ;

    bad_hello:
    iif->intf_nw_props.nmp->bad_hellos++;
}

void
dump_interface_adjacencies(interface_t *interface){

    glthread_t *curr;
    adjacency_t *adjacency;
    time_t curr_time;
    intf_nmp_t *nmp;

    nmp = NMP_GET_INTF_NMPDS(interface);
    
    if(!nmp) return ;
    
    curr_time = time(NULL);

    ITERATE_GLTHREAD_BEGIN(NMP_GET_INTF_ADJ_LIST(interface), curr){
        
        adjacency = glthread_to_adjacency(curr);
        printf("\t Adjacency : Nbr Name : %s, Router id : %s,"
               " nbr ip : %s,\n\t\t nbr mac : %02x:%02x:%02x:%02x:%02x:%02x, Expires in : %d sec, uptime = %s\n",
                adjacency->router_name, 
                adjacency->router_id, 
                adjacency->nbr_ip, 
                adjacency->nbr_mac.mac[0],
                adjacency->nbr_mac.mac[1],
                adjacency->nbr_mac.mac[2],
                adjacency->nbr_mac.mac[3],
                adjacency->nbr_mac.mac[4],
                adjacency->nbr_mac.mac[5],
                wt_get_remaining_time(adjacency->expiry_timer),
                hrs_min_sec_format(
                    (uint32_t)difftime(curr_time, adjacency->uptime)));
    } ITERATE_GLTHREAD_END(NMP_GET_INTF_ADJ_LIST(interface), curr);    
}

/* Delete all interface adj if router_id is NULL, else
 * delete only particular adj*/
void
delete_interface_adjacency(interface_t *interface, 
                            char *router_id){
                            

    adjacency_t *adjacency = NULL;
    
    if(router_id){

        adjacency = find_adjacency_on_interface(interface, router_id);
        if(!adjacency) return;
        remove_glthread(&adjacency->glue);
        adjacency_delete_expiry_timer(interface, adjacency);
        free(adjacency);
        return;
    }

    glthread_t *curr;
    intf_nmp_t *nmp = NMP_GET_INTF_NMPDS(interface);
    if(!nmp) return;

    ITERATE_GLTHREAD_BEGIN(NMP_GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);  
        remove_glthread(&adjacency->glue);
        adjacency_delete_expiry_timer(interface, adjacency);
        free(adjacency);
    }ITERATE_GLTHREAD_END(NMP_GET_INTF_ADJ_LIST(interface), curr);
}

adjacency_t *
find_adjacency_on_interface(interface_t *interface, char *router_id){

    glthread_t *curr;
    adjacency_t *adjacency;
    intf_nmp_t *nmp;

    nmp = NMP_GET_INTF_NMPDS(interface);
    if(!nmp) return NULL;

    ITERATE_GLTHREAD_BEGIN(NMP_GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);
        if(strncmp(adjacency->router_id, router_id, 16) == 0)
            return adjacency;
    } ITERATE_GLTHREAD_END(NMP_GET_INTF_ADJ_LIST(interface), curr);
    return NULL;
}

/*Adjacency Timers*/

typedef struct adj_key_{

    interface_t *interface;
    char nbr_rtr_id[16];
} adj_key_t;

static void
set_adjacency_key(interface_t *interface, 
                  adjacency_t *adjacency, 
                  adj_key_t *adj_key){

    memset(adj_key, 0, sizeof(adj_key_t));
    adj_key->interface = interface;
    memcpy(adj_key->nbr_rtr_id, adjacency->router_id, 16);
}


void
adjacency_delete_expiry_timer(interface_t *interface,
							  adjacency_t *adjacency){

    assert(adjacency->expiry_timer);
    de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

void
adjacency_refresh_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    wheel_timer_elem_t *wt_elem = 
        adjacency->expiry_timer;
    
    assert(wt_elem);

    wt_elem_reschedule(wt_elem, ADJ_DEF_EXPIRY_TIMER);
}

static void
timer_expire_delete_adjacency_cb(void *arg, uint32_t sizeof_arg){

    adj_key_t *adj_key = (adj_key_t *)arg;
    delete_interface_adjacency(adj_key->interface, 
                               adj_key->nbr_rtr_id); 
	free(adj_key);
}


void
adjacency_start_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    if(adjacency->expiry_timer){
        adjacency_delete_expiry_timer(interface, adjacency);
    }

    adj_key_t *adj_key = calloc(1, sizeof(adj_key_t));
    set_adjacency_key(interface, adjacency, adj_key);

    adjacency->expiry_timer = register_app_event(node_get_timer_instance(interface->att_node),
                                    timer_expire_delete_adjacency_cb,
                                    (void *)adj_key, sizeof(adj_key_t),
                                    ADJ_DEF_EXPIRY_TIMER,
                                    0);
    if(!adjacency->expiry_timer){
        printf("Error : Expiry timer for Adjacency : %s, %s, %s could not be started\n",
            interface->att_node->node_name, interface->if_name, adjacency->router_name);
    }
}

static void
nbrship_print_hello_stats(node_t *node){

    int i = 0;
    int count = 0;
    intf_nmp_t *intf_nmp;
    interface_t *interface;

    ITERATE_NODE_INTERFACES_BEGIN(node, interface){
        
        if(!interface || !NMP_GET_INTF_NMPDS(interface)) continue;

        intf_nmp = NMP_GET_INTF_NMPDS(interface);

        count++;

        if(count == 1){
            printf("\t|====intf=====|==Hello-RX==|==Hello-TX==|==Bad-Hello-RX==|\n");
        }
        else{
            printf("\t|=============|============|============|=================|\n");
        }

        printf("\t| %-12s|   %-6u   |    %-6u  |    %-6u      |\n",
            interface->if_name, intf_nmp->recvd, intf_nmp->sent, intf_nmp->bad_hellos);

    } ITERATE_NODE_INTERFACES_END(node, interface);
    if(count){
        printf("\t|=============|============|============|================|\n");
    }
}

static void
nbrship_mgmt_activate_nmp_on_interface(interface_t *intf){

    nmp_t *nmp;
    node_t *node;
    
    intf_nmp_t *intf_nmp = NMP_GET_INTF_NMPDS(intf);
    
    if(!intf_nmp) return;

    node = intf->att_node;
    nmp = NMP_GET_NODE_NMPDS(node);

    if(!nmp || !nmp->is_enabled){
        assert(!intf_nmp->is_enabled);
        return;
    }

    if(nmp && nmp->is_enabled){
        intf_nmp->is_enabled = TRUE;
        schedule_hello_on_interface(intf, 5, TRUE); 
    }
}

static void
nbrship_mgmt_deactivate_nmp_on_interface(interface_t *intf){

    intf_nmp_t *intf_nmp = NMP_GET_INTF_NMPDS(intf);
    if(!intf_nmp) return;

    if(!intf_nmp->is_enabled) return;

    intf_nmp->is_enabled = FALSE;
    stop_interface_hellos(intf);
}

static void
nbrship_mgmt_enable_disable_intf_nbrship_protocol(
            interface_t *interface, 
            bool_t is_enabled){

    intf_nmp_t *intf_nmp;
    intf_nmp = NMP_GET_INTF_NMPDS(interface);
    switch(is_enabled){
        case TRUE:
            if(!intf_nmp){
                intf_nmp = calloc(1, sizeof(intf_nmp_t));
                init_glthread(&intf_nmp->adjacency_list);
                NMP_GET_INTF_NMPDS(interface) = intf_nmp;
            }
            nbrship_mgmt_activate_nmp_on_interface(interface);
        break;
        case FALSE:
            if(!intf_nmp) return;
            nbrship_mgmt_deactivate_nmp_on_interface(interface);
            delete_interface_adjacency(interface, NULL);
            free(intf_nmp);
            NMP_GET_INTF_NMPDS(interface) = NULL;
        break;
        default: ;
    }
}

static void
nbrship_mgmt_enable_disable_all_intf_nbrship_protocol(
            node_t *node, 
            bool_t is_enabled){

    int i = 0;
    interface_t *interface;

    for( ; i < MAX_INTF_PER_NODE; i++){
        interface = node->intf[i];
        if(!interface) continue;
        nbrship_mgmt_enable_disable_intf_nbrship_protocol(interface, is_enabled);
    }
}

static void
nbrship_mgmt_enable_disable_device_level(node_t *node, bool_t is_enabled){

    int i = 0;
    interface_t *intf;
    nmp_t *nmp = node->node_nw_prop.nmp;

    if(!nmp && !is_enabled) return;
    if(nmp && nmp->is_enabled && is_enabled) return;

    if((!nmp || !nmp->is_enabled) && is_enabled){
        
        if(!nmp){
             nmp = calloc(1, sizeof(nmp_t));
        }

        node->node_nw_prop.nmp = nmp;
        nmp->is_enabled = TRUE;

        for(; i < MAX_INTF_PER_NODE; i++){ 
            intf = node->intf[i];
            if(!intf) continue;
            nbrship_mgmt_activate_nmp_on_interface(intf);
        }
        return;
    }

    if(nmp && !is_enabled){

        if(!nmp->is_enabled) return;

        free(nmp);
        node->node_nw_prop.nmp = NULL;
        for(; i < MAX_INTF_PER_NODE; i++){
            intf = node->intf[i];
            if(!intf) continue;
            nbrship_mgmt_deactivate_nmp_on_interface(intf);
        }
        return;
    }
}

static void
nbrship_mgmt_show_nmp_state(node_t *node){

    interface_t *intf;
    intf_nmp_t *intf_nmp;
    nmp_t *nmp = NMP_GET_NODE_NMPDS(node);
    
    printf("Global NMP : %s\n", 
        (nmp && nmp->is_enabled) ? "Enabled" : "Disabled");
 
    ITERATE_NODE_INTERFACES_BEGIN(node, intf){

        intf_nmp = NMP_GET_INTF_NMPDS(intf);
        if(!intf_nmp) continue;
        printf("  %s : %s\n", intf->if_name, nmp_get_interface_state(intf));
    } ITERATE_NODE_INTERFACES_END(node, intf)
}


int 
nbrship_mgmt_handler(param_t *param, ser_buff_t *tlv_buf,
                op_mode enable_or_disable){

    node_t *node;
    char *node_name;
    char *if_name;
    interface_t *intf;

    int CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "if-name", strlen("if-name")) ==0)
            if_name = tlv->value;
        else
            assert(0);
    } TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    intf = get_node_if_by_name(node, if_name);

    switch(CMDCODE){
        case CMDCODE_SHOW_NODE_NBRSHIP:
        {
            int i = 0;
            for(; i < MAX_INTF_PER_NODE; i++){
                intf = node->intf[i];
                if(!intf) continue;
                dump_interface_adjacencies(intf);
            }
        } 
        break;
        case CMDCODE_CONF_NODE_INTF_NBRSHIP_ENABLE:

            if(!intf){
                printf("Error : Interface %s do not exist\n", intf->if_name);
                return -1;
            } 

            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    nbrship_mgmt_enable_disable_intf_nbrship_protocol(intf, TRUE);
                break;
                case CONFIG_DISABLE:
                    nbrship_mgmt_enable_disable_intf_nbrship_protocol(intf, FALSE);
                break;
                default : ;
            }
        break;
        case CMDCODE_CONF_NODE_INTF_ALL_NBRSHIP_ENABLE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    nbrship_mgmt_enable_disable_all_intf_nbrship_protocol(node, TRUE);
                break;
                case CONFIG_DISABLE:
                    nbrship_mgmt_enable_disable_all_intf_nbrship_protocol(node, FALSE);
                break;
                default : ;
            }
        break;
        case CMDCODE_SHOW_NODE_NMP_PROTOCOL_ALL_INTF_STATS:
            nbrship_print_hello_stats(node);
        break;
        case CMDCODE_CONF_NODE_NBRSHIP_ENABLE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    nbrship_mgmt_enable_disable_device_level(node, TRUE);
                break;
                case CONFIG_DISABLE:
                    nbrship_mgmt_enable_disable_device_level(node, FALSE);
                break;
                default:    ;
            }
        break;
        case CMDCODE_SHOW_NODE_NMP_STATE:
            nbrship_mgmt_show_nmp_state(node);
        break;
        default :
            assert(0);

    }
    return 0;
}


static void
nmp_interface_update(void *arg, size_t arg_size){

#if 0
    printf("%s called for interface %s, flags = 0x%x\n", __FUNCTION__,
            intf->if_name, flags);
#endif
}

void
init_nbrship_mgmt(){

    tcp_app_register_l2_protocol_interest(NMP_HELLO_MSG_CODE, 
        process_hello_msg);

    tcp_ip_stack_register_l2_proto_for_l2_hdr_inclusion(NMP_HELLO_MSG_CODE);

	nfc_register_for_pkt_tracing(NMP_HELLO_MSG_CODE,
		nmp_print_hello_pkt);

	nfc_intf_register_for_events(nmp_interface_update);
}

