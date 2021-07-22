#ifndef  __ISIS_INTF__
#define __ISIS_INTF__


typedef struct isis_intf_info_ {

    uint16_t hello_interval;

    /*  Timer to retransmit hellos out of
        the interface */
    wheel_timer_elem_t *hello_xmit_timer;

    /* stats */
    uint32_t good_hello_pkt_recvd;
    uint32_t bad_hello_pkt_recvd;
    uint32_t good_lsps_pkt_recvd;
    uint32_t bad_lsps_pkt_recvd;
    uint32_t lsp_pkt_sent;
    uint32_t hello_pkt_sent;
    /* intf cost */
    uint32_t cost;

    /* Adj list on this interface */
    glthread_t adj_list_head;
} isis_intf_info_t;


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

#define ISIS_INTF_COST(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->cost)

#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_interval)

void
isis_show_interface_protocol_state(interface_t *intf);

void
isis_free_intf_info(interface_t *intf);

void
isis_interface_updates(void *arg, size_t arg_size);

#endif // ! __ISIS_INTF__
