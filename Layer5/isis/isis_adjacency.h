#ifndef __IGP_NBRSHIP__
#define __IGP_NBRSHIP__

typedef enum adj_state_ {

    ISIS_ADJ_STATE_DOWN,
    ISIS_ADJ_STATE_INIT,
    ISIS_ADJ_STATE_UP
} adj_state_t;

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
    mac_add_t nbr_mac[6];
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

#endif /* __IGP_NBRSHIP__ */