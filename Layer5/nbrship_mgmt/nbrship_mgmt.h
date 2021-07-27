#ifndef __NMP__
#define __NMP__

#include "../../tcp_public.h"

typedef struct hello_{

    char tlv_buff[0];
} hello_t;

typedef struct nmp_{
    bool is_enabled;
} nmp_t;

typedef struct intf_nmp_{
    bool is_enabled;
    uint32_t sent;
    uint32_t recvd;
    uint32_t bad_hellos;
    timer_event_handle *hellos;
    glthread_t adjacency_list;
} intf_nmp_t;

#define NMP_GET_INTF_NMPDS(intf_ptr)    \
    (intf_ptr->intf_nw_props.nmp)

#define NMP_GET_NODE_NMPDS(node_ptr)    \
    (node_ptr->node_nw_prop.nmp)

#define NMP_IS_INTF_NMP_ENABLED(intf_ptr)   \
    (intf_ptr->intf_nw_props.nmp &&         \
    intf_ptr->intf_nw_props.nmp->is_enabled)

#define NMP_SHOULD_SCHEDULE_HELLO_ON_INTF(intf_ptr) \
    (NMP_IS_INTF_NMP_ENABLED(intf_ptr) &&           \
    intf_ptr->att_node &&                           \
    intf_ptr->att_node->node_nw_prop.nmp &&         \
    intf_ptr->att_node->node_nw_prop.nmp->is_enabled)

static char *
nmp_get_interface_state(interface_t *intf){

    nmp_t *nmp;
    intf_nmp_t *intf_nmp;

    intf_nmp = NMP_GET_INTF_NMPDS(intf);
    if(!intf_nmp) return NULL;

    nmp = NMP_GET_NODE_NMPDS(intf->att_node);

    if(!nmp || !nmp->is_enabled){
        if(intf_nmp->is_enabled) assert(0);
        return "INACTIVE";
    }

    if(nmp && nmp->is_enabled){
        if(intf_nmp->is_enabled)
            return "ACTIVE";
        else
            return "INACTIVE";
    }
    return NULL;
}


bool
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, 
                            bool is_repeat);

ethernet_hdr_t *
get_new_hello_pkt(node_t *node,
		  interface_t *interface,
		  uint32_t *pkt_size);

void 
pause_interface_hellos(interface_t *interface);

void
stop_interface_hellos(interface_t *interface);

static inline bool
is_hellos_scheduled_on_intf(interface_t *interface){

    if(interface->intf_nw_props.nmp &&
        interface->intf_nw_props.nmp->hellos)
        return true;
    else
        return false;
}

#define node_get_timer_instance(node_ptr)   \
    node_ptr->node_nw_prop.wt

typedef struct adjacency_{

    char router_name[NODE_NAME_SIZE];
    char router_id[16]; /*key*/
    char nbr_ip[16];
    mac_add_t nbr_mac;
    glthread_t glue;
    timer_event_handle *expiry_timer;
    time_t uptime;
} adjacency_t;
GLTHREAD_TO_STRUCT(glthread_to_adjacency, adjacency_t, glue);

#define NMP_GET_INTF_ADJ_LIST(intf_ptr) \
    (&(NMP_GET_INTF_NMPDS(intf_ptr)->adjacency_list))

adjacency_t *
find_adjacency_on_interface(interface_t *interface, char *router_id);

void
delete_interface_adjacency(interface_t *interface, 
                            char *router_id); 

void
dump_interface_adjacencies(interface_t *interface);

/*Adjacency Timers*/
void
adjacency_delete_expiry_timer(interface_t *interface, 
                        adjacency_t *adjacency); 

void
adjacency_refresh_expiry_timer(interface_t *interface,
                               adjacency_t *adjacency);

void
adjacency_start_expiry_timer(interface_t *interface,
                             adjacency_t *adjacency);

/*TLV Code Points for NMP protocol*/
#define TLV_NODE_NAME   10
#define TLV_RTR_ID      20
#define TLV_IF_IP       30
#define TLV_IF_MAC      40
#endif /* __NMP__ */
