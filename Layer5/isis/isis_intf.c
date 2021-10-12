#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_flood.h"
#include "isis_intf_group.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}

bool
isis_interface_qualify_to_send_hellos(interface_t *intf){

    if (isis_node_intf_is_enable(intf) &&
         IS_INTF_L3_MODE(intf) &&
         IF_IS_UP(intf)) {
             
            return true;
    }
    return false;
}

static void
isis_transmit_hello(void *arg, uint32_t arg_size) {

    if (!arg) return;

    isis_timer_data_t *isis_timer_data =
        (isis_timer_data_t *)arg;

    node_t *node = isis_timer_data->node;
    interface_t *egress_intf = isis_timer_data->intf;
    char *hello_pkt = isis_timer_data->data;
    size_t pkt_size = isis_timer_data->data_size;

    if (hello_pkt && pkt_size) {
        ISIS_INTF_INCREMENT_STATS(egress_intf, hello_pkt_sent);
        send_pkt_out(hello_pkt, pkt_size, egress_intf);
    }
}

void
isis_start_sending_hellos(interface_t *intf) {

    node_t *node;
    size_t hello_pkt_size;

    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
    assert(isis_node_intf_is_enable(intf));
    
    node = intf->att_node;
    wheel_timer_t *wt = node_get_timer_instance(node);

    char *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);

    isis_timer_data_t *isis_timer_data =
        XCALLOC(0, 1, isis_timer_data_t);

    isis_timer_data->node = node;
    isis_timer_data->intf = intf;
    isis_timer_data->data = hello_pkt;
    isis_timer_data->data_size = hello_pkt_size;

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = timer_register_app_event(wt,
                                        isis_transmit_hello,
                                        (void *)isis_timer_data,
                                        sizeof(isis_timer_data_t),
                                        ISIS_INTF_HELLO_INTERVAL(intf) * 1000,
                                        1);

    
    if (ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL) {
        printf("Error : Failed to xmit hellos on interface (%s)%s",
            node->node_name, intf->if_name);
        XFREE(isis_timer_data);
        return;
    }
}

void
isis_stop_sending_hellos(interface_t *intf){

    timer_event_handle *hello_xmit_timer = NULL;

    hello_xmit_timer = ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (!hello_xmit_timer) return;

    isis_timer_data_t *isis_timer_data =
        (isis_timer_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, 0);

    timer_de_register_app_event(hello_xmit_timer);

    tcp_ip_free_pkt_buffer(isis_timer_data->data,
        isis_timer_data->data_size);

    XFREE(isis_timer_data);

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
}

void
isis_refresh_intf_hellos(interface_t *intf) {

    isis_stop_sending_hellos(intf);
    isis_start_sending_hellos(intf);
}


static void
isis_init_intf_info (interface_t *intf) {
    
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    memset(intf_info, 0, sizeof(isis_intf_info_t));
    intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    intf_info->cost = ISIS_DEFAULT_INTF_COST;
    init_glthread(&intf_info->adj_list_head);
    init_glthread(&intf_info->intf_grp_member_glue);
    /* Back Linkage */
    intf_info->intf = intf;
}

void
isis_enable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *intf_info = NULL;

    if (!isis_is_protocol_enable_on_node(intf->att_node)) {
        return;
    }

    intf_info = ISIS_INTF_INFO(intf);

    if (! intf_info ) {

        intf_info = XCALLOC(0, 1, isis_intf_info_t);
        intf->intf_nw_props.isis_intf_info = intf_info;
        isis_init_intf_info(intf);
    }
    
    if (intf_info->hello_xmit_timer == NULL) {
        if (isis_interface_qualify_to_send_hellos(intf) &&
            !ISIS_INTF_INFO(intf)->hello_xmit_timer) {
            isis_start_sending_hellos(intf);
        }
    }
}

static void
isis_free_intf_info(interface_t *intf) {

    if (!ISIS_INTF_INFO(intf)) return;
    XFREE(ISIS_INTF_INFO(intf));
    intf->intf_nw_props.isis_intf_info = NULL;
}

void 
isis_check_and_delete_intf_info(interface_t *intf) {

    if (ISIS_INTF_HELLO_XMIT_TIMER(intf) ||
         !IS_GLTHREAD_LIST_EMPTY(ISIS_INTF_ADJ_LST_HEAD(intf)) ||
         !IS_GLTHREAD_LIST_EMPTY(&ISIS_INTF_INFO(intf)->lsp_xmit_list_head) ||
         !IS_GLTHREAD_LIST_EMPTY(&ISIS_INTF_INFO(intf)->intf_grp_member_glue) ||
         ISIS_INTF_INFO(intf)->lsp_xmit_job) {

       assert(0);
    }    
    isis_free_intf_info(intf);
}

void
isis_disable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) return;

    isis_stop_sending_hellos(intf);
    isis_delete_all_adjacencies(intf);
    isis_intf_purge_lsp_xmit_queue(intf);
    remove_glthread(&intf_info->intf_grp_member_glue);
    intf_info->intf_grp = NULL;
    isis_check_and_delete_intf_info(intf);
}

void
isis_show_interface_protocol_state(interface_t *intf) {

    bool is_enabled;
    glthread_t *curr;
    isis_adjacency_t *adjacency = NULL;
    isis_intf_info_t *intf_info = NULL;

    is_enabled = isis_node_intf_is_enable(intf);

    printf(" %s : %sabled\n", intf->if_name, is_enabled ? "En" : "Dis");
    
    if(!is_enabled) return;

    intf_info = intf->intf_nw_props.isis_intf_info;
   
    if (intf_info->intf_grp) {
         PRINT_TABS(2);
        printf("Intf Group : %s \n", intf_info->intf_grp->name);
    }
    PRINT_TABS(2);
    printf("hello interval : %u sec, Intf Cost : %u\n",
        intf_info->hello_interval, intf_info->cost);

    PRINT_TABS(2);
    printf("hello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");  

    PRINT_TABS(2);
    printf("Stats :\n");
    PRINT_TABS(3);
    printf("> good_hello_pkt_recvd : %u\n", intf_info->good_hello_pkt_recvd);
    PRINT_TABS(3);
    printf("> bad_hello_pkt_recvd : %u\n", intf_info->bad_hello_pkt_recvd);
    PRINT_TABS(3);
    printf("> good_lsps_pkt_recvd : %u\n", intf_info->good_lsps_pkt_recvd);
    PRINT_TABS(3);
    printf("> bad_lsps_pkt_recvd : %u\n", intf_info->bad_lsps_pkt_recvd);
    PRINT_TABS(3);
    printf("> lsp_pkt_sent : %u\n", intf_info->lsp_pkt_sent);
    PRINT_TABS(3);
    printf("> hello_pkt_sent : %u\n", intf_info->hello_pkt_sent);

    PRINT_TABS(2);
    printf("Adjacencies :\n");

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        isis_show_adjacency(adjacency, 4);
        printf("\n");
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr)
    printf("\n");
}

static void
isis_handle_interface_up_down (interface_t *intf, bool old_status) {

    bool any_adj_up = false;

    if (old_status == false) {
        /* Interace has been no-shut */
        /* 1. Start sending hellos out of interface if it qualifies
            2. Start processing hellos on this interface if it qualifies */

            if (!isis_interface_qualify_to_send_hellos(intf)) {
                return;
            }
            isis_start_sending_hellos(intf);
    }
    else {
        /* interface has been shut down */
        isis_stop_sending_hellos(intf);
        any_adj_up = isis_any_adjacency_up_on_interface(intf);
        isis_delete_all_adjacencies(intf);
        if (any_adj_up) {
            isis_schedule_lsp_pkt_generation(intf->att_node,
                                isis_event_admin_config_changed);
        }
    }
}

static void
isis_handle_interface_ip_addr_changed (interface_t *intf, 
                                                                uint32_t old_ip_addr, uint8_t old_mask) {

    /* case 1 : New IP Address Added, start sending hellos if intf qualifies*/

    if (IF_IP_EXIST(intf) && !old_ip_addr && !old_mask) {

        if (isis_interface_qualify_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
        }
        return;
    }

    /* case 2 : IP Address Removed, stop sending hellos, delete all adj on this intf, regen LSP*/

    if (!IF_IP_EXIST(intf) && old_ip_addr && old_mask) {

        bool any_up_adj = false;
        any_up_adj = isis_any_adjacency_up_on_interface(intf);
        isis_stop_sending_hellos(intf);
        isis_delete_all_adjacencies(intf);
        if (any_up_adj) {
            isis_schedule_lsp_pkt_generation(intf->att_node, 
                isis_event_admin_config_changed);
        }
        return;
    }

    /*case 3 : IP Address changed, start sending hellos if intf qualifies with new IP Address
        Nbr must bring down adj if new IP Address do not matches same subnet 
        Nbr must update its Adj data and LSP as per new Ip Address info recvd from this rtr
    */
    
    isis_interface_qualify_to_send_hellos(intf) ?   \
        isis_refresh_intf_hellos(intf) :                       \
        isis_stop_sending_hellos(intf);
        isis_schedule_lsp_pkt_generation(intf->att_node, 
                isis_event_admin_config_changed);
}

void
isis_interface_updates(void *arg, size_t arg_size) {

	intf_notif_data_t *intf_notif_data = 
		(intf_notif_data_t *)arg;

	uint32_t flags = intf_notif_data->change_flags;
	interface_t *intf = intf_notif_data->interface;
	intf_prop_changed_t *old_intf_prop_changed =
            intf_notif_data->old_intf_prop_changed;

    if (!isis_node_intf_is_enable(intf)) return;

    switch(flags) {
        case IF_UP_DOWN_CHANGE_F:
            isis_handle_interface_up_down (intf, old_intf_prop_changed->up_status);
            break;
        case IF_IP_ADDR_CHANGE_F:
            isis_handle_interface_ip_addr_changed (intf, 
                    old_intf_prop_changed->ip_addr.ip_addr,
                    old_intf_prop_changed->ip_addr.mask);
         break;
        case IF_OPER_MODE_CHANGE_F:
        case IF_VLAN_MEMBERSHIP_CHANGE_F:
        case IF_METRIC_CHANGE_F :
        break;
    default: ;
    }
}

bool
isis_atleast_one_interface_protocol_enabled(node_t *node) {

    interface_t *intf;
    
    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
     
            if (isis_node_intf_is_enable(intf)) return true;
            
     } ITERATE_NODE_INTERFACES_END(node, intf);

    return false;
}


/* show per intf stats */

uint32_t
isis_show_one_intf_stats (interface_t *intf, uint32_t rc) {

    byte *buff;
    uint32_t rc_old;
    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info) return 0;

    buff = intf->att_node->print_buff ;
    rc_old = rc;

    rc += sprintf (buff + rc, "%s\t", intf->if_name);
    rc +=  sprintf (buff + rc, "H Tx : %-4u H Rx : %-4u BadH Rx : %-4u "
                                           "LSPs Tx : %-4u LSPs Rx : %-4u Bad LSPs Rx : %-4u\n",
                        intf_info->hello_pkt_sent,
                        intf_info->good_hello_pkt_recvd,
                        intf_info->bad_lsps_pkt_recvd,
                        intf_info->lsp_pkt_sent,
                        intf_info->good_lsps_pkt_recvd,
                        intf_info->bad_lsps_pkt_recvd);
    return rc - rc_old;
}

uint32_t 
isis_show_all_intf_stats(node_t *node) {

    uint32_t rc = 0;
    interface_t *intf;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return 0;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;
        rc += isis_show_one_intf_stats(intf, rc);

    } ITERATE_NODE_INTERFACES_END(node, intf);

    return rc;
}
