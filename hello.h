#ifndef __HELLO__
#define __HELLO__

#include "graph.h"
#include <stdlib.h>
#include <memory.h>
#include "Layer2/layer2.h"

typedef struct hello_{

    char router_name[NODE_NAME_SIZE];
    char router_id[16]; /*Loopback Address*/
    char intf_ip[16];
} hello_t;

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, 
                            bool_t is_repeat);

ethernet_hdr_t *
get_new_hello_pkt(node_t *node,
		  interface_t *interface,
		  unsigned int *pkt_size);

void 
pause_interface_hellos(interface_t *interface);

void
stop_interface_hellos(interface_t *interface);

static inline bool_t
is_hellos_scheduled_on_intf(interface_t *interface){

    if(interface->intf_nw_props.hellos)
        return TRUE;
    else
        return FALSE;
}

#define GET_NODE_TIMER_FROM_INTF(intf_ptr)  \
    (intf_ptr->att_node ? intf_ptr->att_node->node_nw_prop.wt : NULL)


typedef struct adjacency_{

    char router_name[NODE_NAME_SIZE];
    char router_id[16];
    char nbr_ip[16];
} adjacency_t;

void
process_hello_msg(interface_t *iif, 
                  ethernet_hdr_t *hello_eth_hdr);

void
delete_interface_adjacency(interface_t *interface);

void
dump_interface_adjacencies(interface_t *interface);

#endif /* __HELLO__ */
