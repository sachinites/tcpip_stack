#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_pkt.h"
#include "isis_events.h"

static void
isis_init_adjacency(isis_adjacency_t *adjacency) {

    memset(adjacency, 0, sizeof(isis_adjacency_t));
    adjacency->last_transition_time = time(NULL); /* Current system time */
    adjacency->adj_state = ISIS_ADJ_STATE_DOWN;
    init_glthread(&adjacency->glue);
}

/* Timer fns for ISIS Adjacency Mgmt */
static void
isis_timer_expire_delete_adjacency_cb(void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_delete_adjacency((isis_adjacency_t *)arg);
}

static void
isis_timer_expire_down_adjacency_cb(void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
    isis_change_adjacency_state((isis_adjacency_t *)arg, ISIS_ADJ_STATE_DOWN);
}

static void
isis_adjacency_start_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->expiry_timer){
        return;
    }

    adjacency->expiry_timer = timer_register_app_event(
                                    node_get_timer_instance(adjacency->intf->att_node),
                                    isis_timer_expire_down_adjacency_cb,
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

static void
isis_adjacency_stop_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(!adjacency->expiry_timer){
        return;
    }

    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

static void
isis_adjacency_start_delete_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->delete_timer){
        return;
    }

    adjacency->delete_timer = timer_register_app_event(
                                    node_get_timer_instance(adjacency->intf->att_node),
                                    isis_timer_expire_delete_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    ISIS_ADJ_DEFAULT_DELETE_TIME,
                                    0);

    if(!adjacency->delete_timer){
        printf("Error : Delete timer for Adjacency : %s, %s, %s "
                "could not be started\n",
                adjacency->intf->att_node->node_name,
                adjacency->intf->if_name,
                adjacency->nbr_name);
    }
}

static void
isis_adjacency_stop_delete_timer(
        isis_adjacency_t *adjacency) {

    if(!adjacency->delete_timer){
        return;
    }

    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;
}

/* Timer fns for ISIS Adjacency Mgmt End */


void
isis_delete_adjacency(isis_adjacency_t *adjacency) {

    remove_glthread(&adjacency->glue);
    isis_adjacency_stop_expiry_timer(adjacency);
    isis_adjacency_stop_delete_timer(adjacency);
    free(adjacency);
}

void
isis_delete_all_adjacencies(interface_t *intf) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        isis_delete_adjacency(adjacency);
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);
}


void
isis_update_interface_adjacency_from_hello(
        interface_t *iif,
        unsigned char *hello_tlv_buffer,
        size_t tlv_buff_size) {

    char *router_id;
    uint8_t tlv_data_len;
    bool new_adj = false;
    isis_intf_info_t *isis_intf_info;
    bool re_generate_lsp_pkt = false;
    isis_adjacency_t *adjacency = NULL;
    isis_events_t event_type = isis_event_none;

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

    uchar_t tlv_type, tlv_len, *tlv_value = NULL;
    ITERATE_TLV_BEGIN(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size){
        
        switch(tlv_type){
            case ISIS_TLV_HOSTNAME:
                if (memcmp(adjacency->nbr_name, tlv_value, tlv_len)) {
                    re_generate_lsp_pkt = true;
                    memcpy(adjacency->nbr_name, tlv_value, tlv_len);
                }
            break;
            case ISIS_TLV_RTR_ID:
                if(memcmp(adjacency->nbr_rtr_id.ip_addr, tlv_value, tlv_len)) {
                    re_generate_lsp_pkt = true;
                    event_type = isis_nbr_rtr_id_changed;
                    memcpy(adjacency->nbr_rtr_id.ip_addr, tlv_value, tlv_len);
                }
            break;    
            case ISIS_TLV_IF_IP:
                if(memcmp(adjacency->nbr_intf_ip.ip_addr, tlv_value, tlv_len)) {
                    re_generate_lsp_pkt = true;
                    event_type = isis_nbr_ip_changed;
                    memcpy(adjacency->nbr_intf_ip.ip_addr, tlv_value, tlv_len);
                }
            break;
            case ISIS_TLV_IF_INDEX:
                memcpy(adjacency->nbr_mac.mac, tlv_value, tlv_len);
            break;
            case ISIS_TLV_HOLD_TIME:
                adjacency->hold_time = *((uint32_t *)tlv_value);
            break;
            case ISIS_TLV_METRIC_VAL:
                if (adjacency->cost != *((uint32_t *)tlv_value)) {
                    re_generate_lsp_pkt = true;
                    adjacency->cost = *((uint32_t *)tlv_value);
                    event_type = isis_nbr_metric_changed;
                }
            break;
            default: ;
        }
    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    if(new_adj) {
        isis_adjacency_start_delete_timer(adjacency);
    }
    else {
        isis_adj_state_t adj_next_state = 
            isis_get_next_adj_state_on_receiving_next_hello(adjacency);
        isis_change_adjacency_state(adjacency, adj_next_state);
    }
    
    /* Dont generate LSP pkt if this is new Adj, as new Adj begins in
       down state*/
    if (!new_adj && re_generate_lsp_pkt) {
        isis_schedule_lsp_pkt_generation(iif->att_node, event_type);
    }

    ISIS_INCREMENT_STATS(iif, good_hello_pkt_recvd);
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
isis_show_adjacency(isis_adjacency_t *adjacency,
                    uint8_t tab_spaces) {

    PRINT_TABS(tab_spaces);
    printf("Nbr : %s(%s)\n", adjacency->nbr_name,
        adjacency->nbr_rtr_id.ip_addr);

    PRINT_TABS(tab_spaces);

    printf("Nbr intf ip(mac) : %s(%02x:%02x:%02x:%02x:%02x:%02x)\n",
        adjacency->nbr_intf_ip.ip_addr,
        adjacency->nbr_mac.mac[0],
        adjacency->nbr_mac.mac[1],
        adjacency->nbr_mac.mac[2],
        adjacency->nbr_mac.mac[3],
        adjacency->nbr_mac.mac[4],
        adjacency->nbr_mac.mac[5]
    );
    PRINT_TABS(tab_spaces);
    printf("State : %s   HT : %u sec   Cost : %u\n",
        isis_adj_state_str(adjacency->adj_state),
        adjacency->hold_time,
        adjacency->cost);

    PRINT_TABS(tab_spaces);

    if (adjacency->expiry_timer) {
        printf("Expiry Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->expiry_timer));
    }
    else {
        printf("Expiry Timer : Nil\n");
    }

    PRINT_TABS(tab_spaces);

    if (adjacency->delete_timer) {
        printf("Delete Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->delete_timer));
    }
    else {
        printf("Delete Timer : Nil\n");
    }
}

void
isis_change_adjacency_state(
            isis_adjacency_t *adjacency,
            isis_adj_state_t new_adj_state) {

    node_t *node = adjacency->intf->att_node;
    isis_adj_state_t old_adj_state = adjacency->adj_state;

    switch(old_adj_state){ 

        case ISIS_ADJ_STATE_DOWN:

            switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    break;
                case ISIS_ADJ_STATE_INIT:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_delete_timer(adjacency);
                    isis_adjacency_start_expiry_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_UP:
                    assert(0);
                    break;
                default : ;
            }   
            break;

        case ISIS_ADJ_STATE_INIT:

        switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_INIT:
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_UP:
                {
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    isis_schedule_lsp_pkt_generation(node, isis_event_adj_state_goes_up);;
                }
                    break;
                default : ;
            }   
            break;

        case ISIS_ADJ_STATE_UP:

        switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    isis_schedule_lsp_pkt_generation(node, isis_event_adj_state_goes_down);
                    break;
                case ISIS_ADJ_STATE_INIT:
                    assert(0);
                    break;
                case ISIS_ADJ_STATE_UP:
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    break;
                default : ;
            }   

            break;
        default : ;
    }
}

isis_adj_state_t 
isis_get_next_adj_state_on_receiving_next_hello(
    isis_adjacency_t *adjacency) {

    switch(adjacency->adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return ISIS_ADJ_STATE_INIT;
        case ISIS_ADJ_STATE_INIT:
            return ISIS_ADJ_STATE_UP;
        case ISIS_ADJ_STATE_UP:
            return ISIS_ADJ_STATE_UP;
        default : ; 
    }   
}

bool
isis_any_adjacency_up_on_interface(interface_t *intf) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

        adjacency = glthread_to_isis_adjacency(curr);

        if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {
            return true;
        }

    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    return false;
}

/*  Playing TLV Encoding and Decoding Games  */

#if 0
+-----------------------+--------Parent TLV Begin--
|       Type = 22       |1B
+-----------------------+
|       Length          |1B ----------------------------------^
+-----------------------+                                     |
|    Nbr Lo Addr (int)  |4B                                   |
+-----------------------+                                     |
|      Metric/Cost      |4B                                   |
+-----------------------+                                     |
|   Total SubTLV Length |1B ----------------------------------+-------+
+-----------------------+---------SubTLVs Begin---            |       |
|      SubTLV type1     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type1 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type1 Value  |<SubTLV type1 len>                   |       |
+-----------------------+                                     |       |
|      SubTLV type2     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type2 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type2 Value  |<SubTLV type2 len>                   |       |
+-----------------------+                                     |       |
|      SubTLV type3     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type3 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type3 Value  |< SubTLV type3 len>                  |       |
+-----------------------+--------SubTLVs Ends-----------------v-------v
+-----------------------+--------Parent TLV Ends---                    

SUBTLVs :
SubTLV 4 : Length 8B : Value = <4B local if index><4B Remote if index>
SubTLV 6 : Length 4B : Value = Local Ip Address (4B)
SubTLV 8 : Length 4B : Value = Nbr IP Address (4B)

#endif

byte *
isis_encode_nbr_as_tlv(isis_adjacency_t *adjacency,
                       uint8_t tlv_no,
                       byte *buff,           /* Output buffer to encode tlv in */
                       uint16_t *tlv_len) {  /* output : length encoded (tlv overhead + data len)*/

    
}