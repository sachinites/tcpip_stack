#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_intf.h"
#include "isis_adjacency.h"

static void
isis_init_adjacency(isis_adjacency_t *adjacency) {

    memset(adjacency, 0, sizeof(isis_adjacency_t));
    adjacency->last_transition_time = time(NULL); /* Current system time */
    init_glthread(&adjacency->glue);
}

static void
isis_adjacency_delete_expiry_timer(isis_adjacency_t *adjacency) {
   
    assert(adjacency->expiry_timer);
    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

static void
isis_delete_interface_adjacency(isis_adjacency_t *adjacency) {

    remove_glthread(&adjacency->glue);
    isis_adjacency_delete_expiry_timer(adjacency);
    free(adjacency);
}


static void
isis_timer_expire_delete_adjacency_cb(void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_delete_interface_adjacency((isis_adjacency_t *)arg);
}

static void
isis_adjacency_start_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->expiry_timer){
        return;
    }

    adjacency->expiry_timer = timer_register_app_event(
                                    node_get_timer_instance(adjacency->intf->att_node),
                                    isis_timer_expire_delete_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    adjacency->hold_time * 1000,
                                    0);

    if(!adjacency->expiry_timer){
        printf("Error : Expiry timer for Adjacency : %s, %s, %s "
                "could not be started\n",
                adjacency->intf->att_node->node_name,
                adjacency->intf->if_name,
                adjacency->nbr_name);
    }
}

 static void
 isis_adjacency_refresh_expiry_timer(
        isis_adjacency_t *adjacency) {
  
    assert(adjacency->expiry_timer);
    timer_reschedule(adjacency->expiry_timer, adjacency->hold_time * 1000);
}

void
isis_update_interface_adjacency_from_hello(
        interface_t *iif,
        unsigned char *hello_tlv_buffer,
        size_t tlv_buff_size) {

    char *router_id;
    uint8_t tlv_data_len;
    bool new_adj = false;
    isis_adjacency_t *adjacency = NULL;
    isis_intf_info_t *isis_intf_info;

    isis_intf_info = iif->intf_nw_props.isis_intf_info;

    router_id = tlv_buffer_get_particular_tlv(
                    hello_tlv_buffer, 
                    tlv_buff_size,
                    ISIS_TLV_RTR_ID, 
                    &tlv_data_len);

    adjacency = isis_find_adjacency_on_interface(iif, router_id);

    if(!adjacency){
        adjacency = (isis_adjacency_t *)calloc(1, sizeof(isis_adjacency_t));
        isis_init_adjacency(adjacency);
        adjacency->intf = iif;
        glthread_add_next(ISIS_INTF_ADJ_LST_HEAD(iif), &adjacency->glue);
        new_adj = true;
    }

    char tlv_type, tlv_len, *tlv_value = NULL;
    ITERATE_TLV_BEGIN(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size){
        
        switch(tlv_type){
            case ISIS_TLV_NODE_NAME:
                memcpy(adjacency->nbr_name, tlv_value, tlv_len);
            break;
            case ISIS_TLV_RTR_ID:
                memcpy(adjacency->nbr_rtr_id.ip_addr, tlv_value, tlv_len);
            break;    
            case ISIS_TLV_IF_IP:
                memcpy(adjacency->nbr_intf_ip.ip_addr, tlv_value, tlv_len);
            break;
            case ISIS_TLV_IF_MAC:
                memcpy(adjacency->nbr_mac.mac, tlv_value, tlv_len);
            break;
            case ISIS_TLV_HOLD_TIME:
                adjacency->hold_time = *((uint32_t *)tlv_value);
            break;
            case ISIS_TLV_METRIC_VAL:
                adjacency->cost = *((uint32_t *)tlv_value);
            break;
            default: ;
        }
    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    if(new_adj) {
        isis_adjacency_start_expiry_timer(adjacency);
    }
    else {
        isis_adjacency_refresh_expiry_timer(adjacency);
    }

    isis_intf_info->good_hello_pkt_recvd++;
}

isis_adjacency_t *
isis_find_adjacency_on_interface(
        interface_t *intf,
        char *router_id) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;
    isis_intf_info_t *isis_intf_info;

    isis_intf_info = intf->intf_nw_props.isis_intf_info;

    if(!isis_intf_info) return NULL;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

        adjacency = glthread_to_isis_adjacency(curr);
        if(strncmp(adjacency->nbr_rtr_id.ip_addr, router_id, 16) == 0)
            return adjacency;
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    return NULL;
}

void
isis_show_adjacency(isis_adjacency_t *adjacency, uint8_t tab_spaces) {

    PRINT_TABS(tab_spaces);
    printf("Nbr : %s(%s)\n", adjacency->nbr_name, adjacency->nbr_rtr_id.ip_addr);
    PRINT_TABS(tab_spaces);
    printf("Nbr intf ip(mac) : %s(%02x:%02x:%02x:%02x:%02x:%02x)\n",
        adjacency->nbr_rtr_id.ip_addr,
        adjacency->nbr_mac.mac[0],
        adjacency->nbr_mac.mac[1],
        adjacency->nbr_mac.mac[2],
        adjacency->nbr_mac.mac[3],
        adjacency->nbr_mac.mac[4],
        adjacency->nbr_mac.mac[5]
    );
    PRINT_TABS(tab_spaces);
    printf("State : %s   HT : %u   Cost : %u\n",
        isis_adj_state_str(adjacency->adj_state),
        adjacency->hold_time,
        adjacency->cost);
}