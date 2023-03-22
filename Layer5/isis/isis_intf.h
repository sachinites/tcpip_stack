#ifndef  __ISIS_INTF__
#define __ISIS_INTF__

typedef struct isis_intf_group_ isis_intf_group_t;
typedef struct event_dispatcher_ event_dispatcher_t;

#include "isis_advt.h"

typedef enum isis_intf_type_ {

    isis_intf_type_p2p,
    isis_intf_type_lan
} isis_intf_type_t;

typedef struct intf_info_ {

    Interface *intf;
    uint16_t hello_interval;
    uint16_t priority;

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

    isis_intf_type_t intf_type;

    /* Pseudonode id to be used is this interface is
        selected as DIS for lan segment*/
    uint8_t pn_id;

    /* Adj list on this interface */
    glthread_t adj_list_head;
    glthread_t lsp_xmit_list_head;
    task_t *lsp_xmit_job;

    /* glue to add to interface group*/
    glthread_t intf_grp_member_glue;
    isis_intf_group_t *intf_grp;

    union {
        /* Interface Data to be advertised for P2P interface*/
        isis_advt_info_t p2p_adv_data;
        /* if this intf is LAN and self is DIS, then advertise self-dis to PN*/
        isis_advt_info_t lan_selfdis_to_pn_adv_data;
        /* If this interface is LAN and self is not DIS, then advertise self to PN*/
        isis_advt_info_t lan_self_non_dis_to_pn_adv_data;
    } adv_data;
    /* if this interface is LAN and self is DIS, then advertise PN to self-dis */
    isis_advt_info_t pn_to_selfdis_adv_data;

} isis_intf_info_t;
GLTHREAD_TO_STRUCT(intf_grp_member_glue_to_intf_info, 
                                            isis_intf_info_t,  intf_grp_member_glue);
                                            
/* Some short-hand macros to make life easy */
#define ISIS_INTF_INFO(intf_ptr)    \
    ((isis_intf_info_t *)((intf_ptr)->isis_intf_info))
#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
    (((isis_intf_info_t *)((intf_ptr)->isis_intf_info))->hello_xmit_timer)
#define ISIS_INTF_COST(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->isis_intf_info))->cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) \
    (((isis_intf_info_t *)((intf_ptr)->isis_intf_info))->hello_interval)
#define ISIS_INTF_ADJ_LST_HEAD(intf_ptr) \
    (&(((isis_intf_info_t *)((intf_ptr)->isis_intf_info))->adj_list_head))
#define ISIS_INTF_INCREMENT_STATS(intf_ptr, pkt_type)  \
    (((ISIS_INTF_INFO(intf_ptr))->pkt_type)++)


bool
isis_node_intf_is_enable(Interface *intf) ;

void
isis_enable_protocol_on_interface(Interface *intf);

void
isis_disable_protocol_on_interface(Interface *intf);

void
isis_start_sending_hellos(Interface *intf) ;

void
isis_stop_sending_hellos(Interface *intf);

void
isis_refresh_intf_hellos(Interface *intf);

void
isis_show_interface_protocol_state(Interface *intf);

void
isis_interface_updates(event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

void 
isis_check_and_delete_intf_info(Interface *intf);

bool
isis_interface_qualify_to_send_hellos(Interface *intf);

bool
isis_atleast_one_interface_protocol_enabled(node_t *node);

uint32_t 
isis_show_all_intf_stats(node_t *node);

uint32_t
isis_show_one_intf_stats (Interface *intf, uint32_t rc);

int
isis_config_interface_link_type(Interface *intf, isis_intf_type_t intf_type);

#endif // ! __ISIS_INTF__
