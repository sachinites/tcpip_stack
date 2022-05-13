#ifndef  __ISIS_INTF__
#define __ISIS_INTF__

typedef struct isis_intf_group_ isis_intf_group_t;
typedef struct isis_adv_data_ isis_adv_data_t;

typedef struct intf_info_ {

    interface_t *intf;
    uint16_t hello_interval;

    /*  Timer to retransmit hellos out of
        the interface */
    timer_event_handle *hello_xmit_timer;

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
    glthread_t lsp_xmit_list_head;
    task_t *lsp_xmit_job;

    /* glue to add to interface group*/
    glthread_t intf_grp_member_glue;
    isis_intf_group_t *intf_grp;

    /* Interface Data to be advertised */
    isis_adv_data_t *adv_data_rtr_id;
} isis_intf_info_t;
GLTHREAD_TO_STRUCT(intf_grp_member_glue_to_intf_info, 
                                            isis_intf_info_t,  intf_grp_member_glue);
                                            
/* Some short-hand macros to make life easy */
#define ISIS_INTF_INFO(intf_ptr)    \
    ((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))
#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_xmit_timer)
#define ISIS_INTF_COST(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->hello_interval)
#define ISIS_INTF_ADJ_LST_HEAD(intf_ptr) \
    (&(((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))->adj_list_head))
#define ISIS_INTF_INCREMENT_STATS(intf_ptr, pkt_type)  \
    (((ISIS_INTF_INFO(intf_ptr))->pkt_type)++)


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

void
isis_refresh_intf_hellos(interface_t *intf);

void
isis_show_interface_protocol_state(interface_t *intf);

void
isis_interface_updates(void *arg, size_t arg_size);

void 
isis_check_and_delete_intf_info(interface_t *intf);

bool
isis_interface_qualify_to_send_hellos(interface_t *intf);

bool
isis_atleast_one_interface_protocol_enabled(node_t *node);

uint32_t 
isis_show_all_intf_stats(node_t *node);

uint32_t
isis_show_one_intf_stats (interface_t *intf, uint32_t rc);

#endif // ! __ISIS_INTF__
