#include <stdio.h>
#include "nbrship_mgmt.h"
#include "../../tcp_public.h"

#define ADJ_DEF_EXPIRY_TIMER    10

typedef struct pkt_meta_data_{

    interface_t *intf;
    char *pkt;
    uint32_t pkt_size;
} pkt_meta_data_t;

static void 
transmit_hellos(void *arg, int sizeof_arg){

    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)arg;
    send_pkt_out(pkt_meta_data->pkt, pkt_meta_data->pkt_size,
            pkt_meta_data->intf);
#if 0
    printf("Hello sent out of interface : (%s)%s\n", 
            pkt_meta_data->intf->att_node->node_name, 
            pkt_meta_data->intf->if_name);
#endif
    //pkt_meta_data->intf->intf_nw_props.hellos_sent++;
}

ethernet_hdr_t *
get_new_hello_pkt(node_t *node,
               	 interface_t *interface,
        		 uint32_t *pkt_size){

    *pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(hello_t) + ETH_FCS_SIZE;

    ethernet_hdr_t *hello = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(*pkt_size);

    memcpy(hello->src_mac.mac, IF_MAC(interface), sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(hello->dst_mac.mac);
    hello->type = HELLO_MSG_CODE;
    
    hello_t *hello_payload = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello);
    memcpy(hello_payload->router_name, node->node_name, NODE_NAME_SIZE);
    memcpy(hello_payload->router_id, NODE_LO_ADDR(node), 16);
    memcpy(hello_payload->intf_ip, IF_IP(interface), 16);
    ETH_FCS(hello, sizeof(hello_t)) = 0;

    return hello;
}

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, bool_t is_repeat){

    uint32_t pkt_size = 0;

    if(is_hellos_scheduled_on_intf(intf))
        return FALSE;

    node_t *node = intf->att_node;
   
    ethernet_hdr_t *hello_pkt = get_new_hello_pkt(node, intf, &pkt_size); 
    
    pkt_meta_data_t pkt_meta_data;
    pkt_meta_data.intf = intf;
    pkt_meta_data.pkt = (char *)hello_pkt;
    pkt_meta_data.pkt_size = pkt_size;

    wheel_timer_elem_t *wt_elem = register_app_event(GET_NODE_TIMER_INSTANCE(intf->att_node),
                                                     transmit_hellos,
                                                     (void *)&pkt_meta_data,
                                                     sizeof(pkt_meta_data_t),
                                                     interval_sec,
                                                     is_repeat ? 1 : 0);
    intf->intf_nw_props.hellos = wt_elem;

    if(is_hellos_scheduled_on_intf(intf))
        return TRUE;

    return FALSE;
}

void
stop_interface_hellos(interface_t *interface){

    if(!is_hellos_scheduled_on_intf(interface))
        return;

    wheel_timer_elem_t *wt_elem = interface->intf_nw_props.hellos;
    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)wt_elem->arg;
    tcp_ip_free_pkt_buffer(pkt_meta_data->pkt, pkt_meta_data->pkt_size);    
    de_register_app_event(GET_NODE_TIMER_INSTANCE(interface->att_node), wt_elem);
    interface->intf_nw_props.hellos = NULL;
}

static void
update_interface_adjacency_from_hello(interface_t *interface,
                                      hello_t *hello){

    bool_t new_adj = FALSE;
    adjacency_t *adjacency = NULL;

    adjacency = find_adjacency_on_interface(interface, hello->router_id);

    if(!adjacency){
        adjacency = (adjacency_t *)calloc(1, sizeof(adjacency_t));
        init_glthread(&adjacency->glue);
        time(&adjacency->uptime);
        glthread_add_next(GET_INTF_ADJ_LIST(interface), &adjacency->glue);
        new_adj = TRUE;
    }
    memcpy(adjacency->router_name, hello->router_name, NODE_NAME_SIZE);
    memcpy(adjacency->router_id, hello->router_id, 16);
    memcpy(adjacency->nbr_ip, hello->intf_ip, 16);
    if(new_adj)
        adjacency_start_expiry_timer(interface, adjacency);
    else
        adjacency_refresh_expiry_timer(interface, adjacency);
    //interface->intf_nw_props.hellos_recv++;
}

void
process_hello_msg(node_t *node, interface_t *iif, 
            char *pkt, uint32_t pkt_size,
            uint32_t flags){

    ethernet_hdr_t *hello_eth_hdr = (ethernet_hdr_t *)pkt;

	/*Reject the pkt if dst mac is not Brodcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        goto bad_hello;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * reciepient interface*/
    hello_t *hello = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    if(!is_same_subnet(IF_IP(iif), 
                       iif->intf_nw_props.mask, 
                       hello->intf_ip)){
        goto bad_hello;
    }

    update_interface_adjacency_from_hello(iif, hello);
    return ;

    bad_hello:
        //iif->intf_nw_props.bad_hellos_recv++;
        ;
}

void
dump_interface_adjacencies(interface_t *interface){

    glthread_t *curr;
    adjacency_t *adjacency;
    time_t curr_time;

    curr_time = time(NULL);
    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){
        
        adjacency = glthread_to_adjacency(curr);
        printf("\t Adjacency : Nbr Name : %s, Router id : %s,"
               " nbr ip : %s, Expires in : %d sec, uptime = %s\n",
                adjacency->router_name, 
                adjacency->router_id, 
                adjacency->nbr_ip, 
                wt_get_remaining_time(GET_NODE_TIMER_INSTANCE(interface->att_node),
                adjacency->expiry_timer),
                hrs_min_sec_format(
                    (uint32_t)difftime(curr_time, adjacency->uptime)));
    } ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);    
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
    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);  
        remove_glthread(&adjacency->glue);
        adjacency_delete_expiry_timer(interface, adjacency);
        free(adjacency);
    }ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);
}

adjacency_t *
find_adjacency_on_interface(interface_t *interface, char *router_id){

    glthread_t *curr;
    adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);
        if(strncmp(adjacency->router_id, router_id, 16) == 0)
            return adjacency;
    } ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);
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
adjacency_delete_expiry_timer(interface_t *interface, adjacency_t *adjacency){

    assert(adjacency->expiry_timer);
    de_register_app_event(GET_NODE_TIMER_INSTANCE(interface->att_node), 
                    adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

void
adjacency_refresh_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    wheel_timer_elem_t *wt_elem = 
        adjacency->expiry_timer;
    
    assert(wt_elem);

    wt_elem_reschedule(GET_NODE_TIMER_INSTANCE(interface->att_node),
                        wt_elem, ADJ_DEF_EXPIRY_TIMER);
}

static void
timer_expire_delete_adjacency_cb(void *arg, int sizeof_arg){

    adj_key_t *adj_key = (adj_key_t *)arg;
    delete_interface_adjacency(adj_key->interface, 
                               adj_key->nbr_rtr_id); 
}


void
adjacency_start_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    if(adjacency->expiry_timer){
        adjacency_delete_expiry_timer(interface, adjacency);
    }

    adj_key_t adj_key;
    set_adjacency_key(interface, adjacency, &adj_key);

    adjacency->expiry_timer = register_app_event(GET_NODE_TIMER_INSTANCE(interface->att_node),
                                    timer_expire_delete_adjacency_cb,
                                    (void *)&adj_key, sizeof(adj_key_t),
                                    ADJ_DEF_EXPIRY_TIMER,
                                    0);
    if(!adjacency->expiry_timer){
        printf("Error : Expiry timer for Adjacency : %s, %s, %s could not be started\n",
            interface->att_node->node_name, interface->if_name, adjacency->router_name);
    }
}

static void
nbrship_mgmt_enable_disable_intf_nbrship_protocol(
            interface_t *interface, 
            bool_t is_enabled){

    switch(is_enabled){
        case TRUE:
            schedule_hello_on_interface(interface, 5, TRUE);
        break;
        case FALSE:
            stop_interface_hellos(interface);
        break;
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
        default :
            assert(0);

    }
    return 0;
}

void
init_nbrship_mgmt(){

    tcp_app_register_l2_protocol_interest(HELLO_MSG_CODE, 
        process_hello_msg);
    tcp_ip_stack_register_l2_proto_for_l2_hdr_inclusion(HELLO_MSG_CODE);
}
