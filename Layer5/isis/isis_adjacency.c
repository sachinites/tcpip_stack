#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_intf.h"
#include "isis_const.h"

/* Timer APIs */

static void
isis_timer_expire_delete_adjacency_cb(void *arg, uint32_t arg_size) {

    if (!arg) return;
    
    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;

    interface_t *intf = adjacency->intf;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    intf_info->adjacency = NULL;

    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;

    assert(!adjacency->expiry_timer);

    free(adjacency);
}

static void
isis_adjacency_start_delete_timer(
        isis_adjacency_t *adjacency) {

    if (adjacency->delete_timer)
        return;

    adjacency->delete_timer = timer_register_app_event(
        node_get_timer_instance(adjacency->intf->att_node),
        isis_timer_expire_delete_adjacency_cb,
        (void *)adjacency,
        sizeof(isis_adjacency_t),
        ISIS_ADJ_DEFAULT_DELETE_TIME,
        0);
}

static void
isis_adjacency_stop_delete_timer(
        isis_adjacency_t *adjacency) {

    if (!adjacency->delete_timer) return;

    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;
}


static void
isis_timer_expire_down_adjacency_cb(void *arg, uint32_t arg_size) {

    if (!arg) return;

    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;

    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;

     isis_change_adjacency_state(adjacency, ISIS_ADJ_STATE_DOWN);
}

static void
isis_adjacency_start_expiry_timer(
        isis_adjacency_t *adjacency) {

    if (adjacency->expiry_timer) return;

    adjacency->expiry_timer = timer_register_app_event(
                                node_get_timer_instance(adjacency->intf->att_node),
                                isis_timer_expire_down_adjacency_cb,
                                (void *)adjacency, sizeof(isis_adjacency_t),
                                adjacency->hold_time * 1000,
                                0);
}


static void
isis_adjacency_stop_expiry_timer(
       isis_adjacency_t *adjacency) {

        if (!adjacency->expiry_timer) return;

        timer_de_register_app_event(adjacency->expiry_timer);
        adjacency->expiry_timer = NULL;
}


 static void
 isis_adjacency_refresh_expiry_timer(
        isis_adjacency_t *adjacency) {

        assert(adjacency->expiry_timer);

        timer_reschedule(adjacency->expiry_timer,
                    adjacency->hold_time * 1000);
}

static void
isis_adjacency_set_uptime(isis_adjacency_t *adjacency) {

    assert(adjacency->adj_state == ISIS_ADJ_STATE_UP);
    adjacency->uptime = time(NULL);
}

void
isis_change_adjacency_state(
            isis_adjacency_t *adjacency,
            isis_adj_state_t new_adj_state) {

    isis_adj_state_t old_adj_state = adjacency->adj_state;

    switch(old_adj_state) {

        case ISIS_ADJ_STATE_DOWN:

            switch(new_adj_state) {

                case ISIS_ADJ_STATE_DOWN:
                case ISIS_ADJ_STATE_INIT:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_delete_timer(adjacency);
                    isis_adjacency_start_expiry_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_UP:
                default: ;
            }


        case ISIS_ADJ_STATE_INIT:

            switch(new_adj_state) {

                case ISIS_ADJ_STATE_DOWN:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_INIT:
                case ISIS_ADJ_STATE_UP:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    isis_adjacency_set_uptime(adjacency);
                default: ;
            }


        case ISIS_ADJ_STATE_UP:

                switch(new_adj_state) {

                case ISIS_ADJ_STATE_DOWN:
                     adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_INIT:
                case ISIS_ADJ_STATE_UP:
                    isis_adjacency_refresh_expiry_timer(adjacency);
                default: ;
            }

        default: ;
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

void
 isis_delete_adjacency(isis_adjacency_t * adjacency) {

     interface_t *intf = adjacency->intf;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    assert(intf_info);

    intf_info->adjacency = NULL;

    isis_adjacency_stop_expiry_timer(adjacency);
    isis_adjacency_stop_delete_timer(adjacency);

    free(adjacency);
 }


void
isis_update_interface_adjacency_from_hello(
        interface_t *iif,
        byte *hello_tlv_buffer,
        size_t tlv_buff_size) {

  /* Algorithm : 

    1. If isis_adjacency_t do not exist on iif, create a new one in DOWN state
    2. Iterate over hello_tlv_buffer and copy all 6 TLVs values from hello to Adjacency members 
    3. Track if there is change in any attribute of existing Adjacency in step 2 (bool nbr_attr_changed )
    4. Keep track if Adj is newly created (bool new_adj )
 */ 

    bool new_adj = false;
    bool nbr_attr_changed = false;
    uint32_t ip_addr_int;
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(iif);

    isis_adjacency_t *adjacency = isis_intf_info->adjacency;

    if (!adjacency) {

        adjacency = calloc(1, sizeof(isis_adjacency_t));
        adjacency->intf = iif;
        new_adj = true;
        adjacency->adj_state = ISIS_ADJ_STATE_DOWN; 
        isis_intf_info->adjacency = adjacency;
        isis_adjacency_start_delete_timer(adjacency);
    }
    
    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size){

        switch(tlv_type) {

            case ISIS_TLV_HOSTNAME:
                if (memcmp(adjacency->nbr_name, tlv_value, tlv_len)) {
                    nbr_attr_changed = true;
                    memcpy(adjacency->nbr_name, tlv_value, tlv_len);
                }
            break;
            case ISIS_TLV_RTR_ID:
                if (adjacency->nbr_rtr_id != *(uint32_t *)(tlv_value)) {
                    nbr_attr_changed = true;
                    adjacency->nbr_rtr_id = *(uint32_t *)(tlv_value);
                }
            break;    
            case ISIS_TLV_IF_IP:
                memcpy((byte *)&ip_addr_int, tlv_value, sizeof(ip_addr_int));
                if (adjacency->nbr_intf_ip != ip_addr_int ) {
                    nbr_attr_changed = true;
                    adjacency->nbr_intf_ip = ip_addr_int;
                }
            break;
            case ISIS_TLV_IF_INDEX:
                memcpy((byte *)&adjacency->remote_if_index, tlv_value, tlv_len);
            break;
            case ISIS_TLV_HOLD_TIME:
                adjacency->hold_time = *((uint32_t *)tlv_value);
            break;
            case ISIS_TLV_METRIC_VAL:
                if (adjacency->cost != *((uint32_t *)tlv_value)) {
                    adjacency->cost = *((uint32_t *)tlv_value);
                    nbr_attr_changed = true;
                }
            break;
            default: ;
        }
    }  ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    if (!new_adj) {

        isis_adj_state_t next_state = isis_get_next_adj_state_on_receiving_next_hello(adjacency);
        isis_change_adjacency_state(adjacency, next_state);
    }
 }