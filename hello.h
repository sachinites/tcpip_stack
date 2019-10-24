#ifndef __HELLO__
#define __HELLO__

#include "graph.h"
#include <stdlib.h>
#include <memory.h>

typedef struct hello_{

    char router_name[NODE_NAME_SIZE];
    char router_id[16]; /*Loopback Address*/
    char intf_ip[16];
} hello_t;

static inline void
init_hello_pkt(hello_t *hello, node_t *node,
               interface_t *interface){

    memset((char *)hello, 0, sizeof(hello_t));
    memcpy(hello->router_name, node->node_name, NODE_NAME_SIZE);
    memcpy(hello->router_id, NODE_LO_ADDR(node), 16);
    memcpy(hello->intf_ip, IF_IP(interface), 16);
}

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, 
                            bool_t is_repeat);

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


#endif /* __HELLO__ */
