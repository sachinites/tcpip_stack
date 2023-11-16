#ifndef __IGP_NBRSHIP__
#define __IGP_NBRSHIP__

#include "isis_advt.h"
#include "isis_struct.h"

typedef struct isis_common_hdr_ isis_common_hdr_t;

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
    Interface *intf; 
    /* nbr Device Name */
    unsigned char nbr_name[NODE_NAME_SIZE];
    /* Nbr intf Ip */
    uint32_t nbr_intf_ip;
   /* Mac Address */
     mac_addr_t nbr_mac;
    /*Nbr lo 0 address */
    uint32_t nbr_rtr_id;
    /* Nbr System ID*/
    isis_system_id_t nbr_sys_id;
    /* LAN ID, only for LAN Adj*/
    isis_lan_id_t lan_id;
    /* Nbrs Priority */
    uint16_t priority;
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
    /* IS Reach Advertisement */
    union {
        /* Advertise P2P adjacency */
        isis_adv_data_t *p2p_adv_data;
        /*is this is LAN adj and self is dis, then advertise PN to nbr*/
        isis_adv_data_t *lan_pn_to_nbr_adv_data;
    } u;

    glthread_t glue;
} isis_adjacency_t;
GLTHREAD_TO_STRUCT(glthread_to_isis_adjacency, isis_adjacency_t, glue);

#define isis_adjacency_is_lan(adjacency_ptr) \
    (ISIS_INTF_INFO(adjacency_ptr->intf)->intf_type == isis_intf_type_lan)

#define isis_adjacency_is_p2p(adjacency_ptr) \
    (ISIS_INTF_INFO(adjacency_ptr->intf)->intf_type == isis_intf_type_p2p)

void
isis_adjacency_set_uptime(isis_adjacency_t *adjacency);

void
isis_update_interface_adjacency_from_hello(
        Interface *iif,
        isis_common_hdr_t *cmn_hdr,
        size_t hello_pkt_size);

isis_adjacency_t *
isis_find_adjacency_on_interface(
        Interface *intf,
        isis_system_id_t *sys_id);

char *
isis_adjacency_name(char *adj_name, isis_adjacency_t *adjacency);

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
isis_delete_all_adjacencies(Interface *intf);

bool
isis_any_adjacency_up_on_interface(Interface *intf);

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
                           
uint32_t 
isis_show_all_adjacencies (node_t *node) ;

bool
isis_update_dis_on_adjacency_transition (isis_adjacency_t *adjacency);

isis_advt_tlv_return_code_t
isis_adjacency_advertise_is_reach (isis_adjacency_t *adjacency);

isis_tlv_wd_return_code_t
isis_adjacency_withdraw_is_reach (isis_adjacency_t *adjacency);

#endif /* __IGP_NBRSHIP__ */
