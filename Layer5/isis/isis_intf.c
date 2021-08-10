#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_flood.h"

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
        ISIS_INCREMENT_STATS(egress_intf, hello_pkt_sent);
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
        calloc(1, sizeof(isis_timer_data_t));

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
        free(isis_timer_data);
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

    free(isis_timer_data);

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
}

void
isis_refresh_intf_hellos(interface_t *intf) {

    isis_stop_sending_hellos(intf);
    isis_start_sending_hellos(intf);
}


static void
isis_init_isis_intf_info (interface_t *intf) {
    
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
    memset(isis_intf_info, 0, sizeof(isis_intf_info_t));
    isis_intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    isis_intf_info->cost = ISIS_DEFAULT_INTF_COST;
    init_glthread(&isis_intf_info->adj_list_head);
}

void
isis_enable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *isis_intf_info;

    if (!isis_is_protocol_enable_on_node(intf->att_node)) {
        return;
    }

    if (!ISIS_INTF_INFO(intf)) {

        isis_intf_info = calloc(1, sizeof(isis_intf_info_t));
        intf->intf_nw_props.isis_intf_info = isis_intf_info;
        isis_init_isis_intf_info(intf);
    }
    
    if (isis_intf_info->hello_xmit_timer == NULL) {
        if (isis_interface_qualify_to_send_hellos(intf) &&
            !ISIS_INTF_INFO(intf)->hello_xmit_timer) {
            isis_start_sending_hellos(intf);
        }
    }
}

static void
isis_free_intf_info(interface_t *intf) {

    if (!ISIS_INTF_INFO(intf)) return;

    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
    assert(IS_GLTHREAD_LIST_EMPTY(ISIS_INTF_ADJ_LST_HEAD(intf)));
    assert(IS_GLTHREAD_LIST_EMPTY(&ISIS_INTF_INFO(intf)->lsp_xmit_list_head));
    assert(!ISIS_INTF_INFO(intf)->lsp_xmit_job);

    free(ISIS_INTF_INFO(intf));
    intf->intf_nw_props.isis_intf_info = NULL;
}

void 
isis_check_and_delete_intf_info(interface_t *intf) {

    if (ISIS_INTF_HELLO_XMIT_TIMER(intf) ||
         !IS_GLTHREAD_LIST_EMPTY(ISIS_INTF_ADJ_LST_HEAD(intf)) ||
         !IS_GLTHREAD_LIST_EMPTY(&ISIS_INTF_INFO(intf)->lsp_xmit_list_head) ||
         ISIS_INTF_INFO(intf)->lsp_xmit_job) {

        return;
    }    
    isis_free_intf_info(intf);
}

void
isis_disable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *isis_intf_info;

    isis_intf_info = ISIS_INTF_INFO(intf);

    if (!isis_intf_info) return;

    isis_stop_sending_hellos(intf);
    isis_delete_all_adjacencies(intf);
    isis_intf_purge_lsp_xmit_queue(intf);

    isis_check_and_delete_intf_info(intf);
}

void
isis_show_interface_protocol_state(interface_t *intf) {

    bool is_enabled;
    glthread_t *curr;
    isis_adjacency_t *adjacency = NULL;
    isis_intf_info_t *isis_intf_info = NULL;

    is_enabled = isis_node_intf_is_enable(intf);

    printf(" %s : %sabled\n", intf->if_name, is_enabled ? "En" : "Dis");
    
    if(!is_enabled) return;

    isis_intf_info = intf->intf_nw_props.isis_intf_info;
    PRINT_TABS(2);
    printf("hello interval : %u sec, Intf Cost : %u\n",
        isis_intf_info->hello_interval, isis_intf_info->cost);

    PRINT_TABS(2);
    printf("hello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");  

    PRINT_TABS(2);
    printf("Stats :\n");
    PRINT_TABS(3);
    printf("> good_hello_pkt_recvd : %u\n", isis_intf_info->good_hello_pkt_recvd);
    PRINT_TABS(3);
    printf("> bad_hello_pkt_recvd : %u\n", isis_intf_info->bad_hello_pkt_recvd);
    PRINT_TABS(3);
    printf("> good_lsps_pkt_recvd : %u\n", isis_intf_info->good_lsps_pkt_recvd);
    PRINT_TABS(3);
    printf("> bad_lsps_pkt_recvd : %u\n", isis_intf_info->bad_lsps_pkt_recvd);
    PRINT_TABS(3);
    printf("> lsp_pkt_sent : %u\n", isis_intf_info->lsp_pkt_sent);
    PRINT_TABS(3);
    printf("> hello_pkt_sent : %u\n", isis_intf_info->hello_pkt_sent);

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
        isis_delete_all_adjacencies(intf);
        isis_schedule_lsp_pkt_generation(intf->att_node,
            isis_event_admin_config_changed);
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