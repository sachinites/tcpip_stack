#ifndef __IGP_NBRSHIP__
#define __IGP_NBRSHIP__

typedef enum isis_adj_state_ {

    ISIS_ADJ_STATE_UNKNOWN,
    ISIS_ADJ_STATE_DOWN,
    ISIS_ADJ_STATE_INIT,
    ISIS_ADJ_STATE_UP
} isis_adj_state_t;

static inline char *
isis_adj_state_str(isis_adj_state_t adj_state) {

    switch(adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return "Down";
        case ISIS_ADJ_STATE_INIT:
            return "Init";
        case ISIS_ADJ_STATE_UP:
            return "Up";
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
   uint32_t nbr_intf_ip;
   /* Mac Address */
   mac_add_t nbr_mac;
    /*Nbr lo 0 address */
    uint32_t nbr_rtr_id;
    /* Nbr if index */
    uint32_t remote_if_index;
    /* Adj State */
    isis_adj_state_t adj_state;
    /* timestamp when Adj state changed */
    time_t last_transition_time;
    /* Hold time in sec reported by nbr*/
    uint32_t hold_time;
    /* Nbr link cost Value */
    uint32_t cost; 
    /* Expiry timer */
    timer_event_handle *expiry_timer;
    /* Delete timer */
    timer_event_handle *delete_timer;
    /* uptime */
    time_t uptime;
    glthread_t glue;
} isis_adjacency_t;
GLTHREAD_TO_STRUCT(glthread_to_isis_adjacency, isis_adjacency_t, glue);

void
isis_adjacency_set_uptime(isis_adjacency_t *adjacency);

void
isis_update_interface_adjacency_from_hello(interface_t *iif,
        unsigned char *hello_tlv_buffer,
        size_t tlv_buff_size);

isis_adjacency_t *
isis_find_adjacency_on_interface(
        interface_t *intf,
        uint32_t nbr_rtr_id);

char *
isis_adjacency_name(isis_adjacency_t *adjacency);

void
isis_show_adjacency(isis_adjacency_t *adjacency, uint8_t tab_spaces);

void
isis_change_adjacency_state(isis_adjacency_t *adjacency,
                            isis_adj_state_t new_state);

isis_adj_state_t 
isis_get_next_adj_state_on_receiving_next_hello(
    isis_adjacency_t *adjacency);

void
isis_delete_adjacency(isis_adjacency_t *adjacency);

int
isis_delete_all_adjacencies(interface_t *intf);

bool
isis_any_adjacency_up_on_interface(interface_t *intf);

byte *
isis_encode_nbr_tlv(isis_adjacency_t *adjacency,
                    byte *buff,  /* Output buffer to encode tlv in */
                    uint16_t *tlv_len);   /* length encoded (tlv overhead + data len)*/

byte *
isis_encode_all_nbr_tlvs(node_t *node, byte *buff) ;

uint8_t 
isis_nbr_tlv_encode_size(isis_adjacency_t *adjacency,
                         uint8_t *subtlv_len);

uint16_t
isis_size_to_encode_all_nbr_tlv(node_t *node);

uint16_t
isis_print_formatted_nbr_tlv(byte *out_buff, 
                             byte *nbr_tlv_buffer,
                             uint8_t tlv_buffer_len);
                             

#endif /* __IGP_NBRSHIP__ */
