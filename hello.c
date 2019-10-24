#include "hello.h"
#include "WheelTimer/WheelTimer.h"
#include <stdio.h>
#include "comm.h"

typedef struct pkt_meta_data_{

    interface_t *intf;
    char *pkt;
    unsigned int pkt_size;
} pkt_meta_data_t;

static void 
transmit_hellos(void *arg, int sizeof_arg){

    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)arg;
    send_pkt_out(pkt_meta_data->pkt, pkt_meta_data->pkt_size,
            pkt_meta_data->intf);
    printf("Hello sent out of interface : (%s)%s\n", 
            pkt_meta_data->intf->att_node->node_name, 
            pkt_meta_data->intf->if_name);
}

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, bool_t is_repeat){

    if(is_hellos_scheduled_on_intf(intf))
        return FALSE;

    node_t *node = intf->att_node;
    
    hello_t *hello = calloc(1, sizeof(hello_t));
    init_hello_pkt(hello, node, intf);

    pkt_meta_data_t pkt_meta_data;
    pkt_meta_data.intf = intf;
    pkt_meta_data.pkt = (char *)hello;
    pkt_meta_data.pkt_size = sizeof(hello_t);

    wheel_timer_elem_t *wt_elem = register_app_event(GET_NODE_TIMER_FROM_INTF(intf),
                                                     transmit_hellos,
                                                     (void *)&pkt_meta_data,
                                                     sizeof(pkt_meta_data_t),
                                                     interval_sec,
                                                     is_repeat ? 1 : 0);
    intf->intf_nw_props.hellos = wt_elem;

    if(is_hellos_scheduled_on_intf(intf))
        return TRUE;

    return FALSE;
}

void
stop_interface_hellos(interface_t *interface){

    if(!is_hellos_scheduled_on_intf(interface))
        return;

    wheel_timer_elem_t *wt_elem = interface->intf_nw_props.hellos;
    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)wt_elem->arg;
    free(pkt_meta_data->pkt);
    de_register_app_event(wt_elem);
    interface->intf_nw_props.hellos = NULL;
}

