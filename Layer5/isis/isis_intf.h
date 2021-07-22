#ifndef  __ISIS_INTF__
#define __ISIS_INTF__

bool
isis_node_intf_is_enable(interface_t *intf) ;

void
isis_enable_protocol_on_interface(interface_t *intf);

void
isis_disable_protocol_on_interface(interface_t *intf);

void
isis_start_sending_hellos(interface_t *intf) ;

void
isis_stop_sending_hellos(interface_t *intf);


#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_xmit_timer)


void
isis_show_interface_protocol_state(interface_t *intf);

void
isis_free_intf_info(interface_t *intf);

void
isis_interface_updates(void *arg, size_t arg_size);

#endif // ! __ISIS_INTF__
