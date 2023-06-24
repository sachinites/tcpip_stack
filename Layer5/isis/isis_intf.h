#ifndef  __ISIS_INTF__
#define __ISIS_INTF__

typedef struct isis_intf_group_ isis_intf_group_t;
typedef struct event_dispatcher_ event_dispatcher_t;

#include "isis_advt.h"
#include "isis_struct.h"

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
    ISIS_LVL level;
    
    /* LAN-ID for this interface if this interface is LAN*/
    isis_lan_id_t lan_id;

    /* For P2P, it will be null*/
    isis_lan_id_t elected_dis;

    /* Adj list on this interface */
    glthread_t adj_list_head;
    glthread_t lsp_xmit_list_head;
    task_t *lsp_xmit_job;

    /* glue to add to interface group*/
    glthread_t intf_grp_member_glue;
    isis_intf_group_t *intf_grp;

    /* if this intf is LAN, then advertise self to PN irrespective whether I am DIS or not*/
    isis_adv_data_t *lan_self_to_pn_adv_data;
    /* if this interface is LAN and self is DIS, then advertise PN to self */
    isis_adv_data_t *lan_pn_to_self_adv_data;

} isis_intf_info_t;
GLTHREAD_TO_STRUCT(intf_grp_member_glue_to_intf_info, 
                                            isis_intf_info_t,  intf_grp_member_glue);
                                            
/* Some short-hand macros to make life easy */
#define  ISIS_INTF_INFO(intf_ptr)    \
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

#define isis_intf_is_lan(intf_ptr) \
    (ISIS_INTF_INFO(intf_ptr)->intf_type == isis_intf_type_lan)

#define isis_intf_is_p2p(intf_ptr) \
    (ISIS_INTF_INFO(intf_ptr)->intf_type == isis_intf_type_p2p)

bool
isis_node_intf_is_enable (Interface *intf) ;

void
isis_enable_protocol_on_interface (Interface *intf);

void
isis_disable_protocol_on_interface (Interface *intf);

void
isis_start_sending_hellos (Interface *intf) ;

void
isis_stop_sending_hellos (Interface *intf);

void
isis_refresh_intf_hellos (Interface *intf);

void
isis_show_interface_protocol_state (Interface *intf);

void
isis_interface_updates (event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

bool
isis_interface_qualify_to_send_hellos (Interface *intf);

void
isis_send_hello_immediately (Interface *intf) ;

uint32_t 
isis_show_all_intf_stats (node_t *node);

uint32_t
isis_show_one_intf_stats (Interface *intf, uint32_t rc);

int
isis_config_interface_link_type (Interface *intf, isis_intf_type_t intf_type);

int
isis_interface_set_priority (Interface *intf, uint16_t priority, bool enable);

int
isis_interface_set_metric (Interface *intf, uint32_t metric, bool enable);

void
isis_interface_reset_stats (Interface *intf) ;

#endif // ! __ISIS_INTF__
