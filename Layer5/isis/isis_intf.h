#ifndef __ISIS_INTF__
#define __ISIS_INTF__

typedef struct isis_adjacency_ isis_adjacency_t; // forward declarations
typedef struct isis_intf_info_ {

uint32_t cost;
uint32_t hello_interval;
timer_event_handle *hello_xmit_timer;
isis_adjacency_t *adjacency;
} isis_intf_info_t;

void
isis_enable_protocol_on_interface(interface_t *intf );

bool
isis_node_intf_is_enable(interface_t *intf) ;

void
isis_disable_protocol_on_interface(interface_t *intf );

void
isis_start_sending_hellos(interface_t *intf);

void
isis_stop_sending_hellos(interface_t *intf);

bool
isis_interface_qualify_to_send_hellos(interface_t *intf);


#define ISIS_INTF_INFO(intf_ptr)    \
    ((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))
#define ISIS_INTF_COST(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_interval)
#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_xmit_timer)

#endif  