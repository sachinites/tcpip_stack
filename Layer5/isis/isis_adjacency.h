#ifndef __IGP_NBRSHIP__
#define __IGP_NBRSHIP__

typedef enum adj_state_ {

    ISIS_ADJ_STATE_DOWN,
    ISIS_ADJ_STATE_INIT,
    ISIS_ADJ_STATE_UP
} adj_state_t;

static inline char *
isis_adj_state_str(adj_state_t adj_state) {

    switch(adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return "ISIS_ADJ_STATE_DOWN";
        case ISIS_ADJ_STATE_INIT:
            return "ISIS_ADJ_STATE_INIT";
        case ISIS_ADJ_STATE_UP:
            return "ISIS_ADJ_STATE_UP";
        default : ;
    }
    return NULL;
}

typedef struct isis_adjacency_{

    /* back ptr to the the interface */
    interface_t *intf; 
    /* nbr Device Name */
    unsigned char nbr_name[NODE_NAME_SIZE];
    /* Nbr intf Ip */
    ip_add_t nbr_intf_ip;
    /*Nbr lo 0 address */
    ip_add_t nbr_rtr_id;
    /* Nbr MAC Addr */
    mac_add_t nbr_mac;
    /* Adj State */
    adj_state_t adj_state;
    /* timestamp when Adj state changed */
    time_t last_transition_time;
    /* Hold time in sec reported by nbr*/
    uint32_t hold_time;
    /* Nbr link cost Value */
    uint32_t cost; 
    /* Expiry timer */
    wheel_timer_elem_t *expiry_timer;
    glthread_t glue;
} isis_adjacency_t;
GLTHREAD_TO_STRUCT(glthread_to_isis_adjacency, isis_adjacency_t, glue);

void
isis_update_interface_adjacency_from_hello(interface_t *iif,
        unsigned char *hello_tlv_buffer,
        size_t tlv_buff_size);

isis_adjacency_t *
isis_find_adjacency_on_interface(
        interface_t *intf,
        char *router_id);

void
isis_show_adjacency(isis_adjacency_t *adjacency, uint8_t tab_spaces);

#endif /* __IGP_NBRSHIP__ */