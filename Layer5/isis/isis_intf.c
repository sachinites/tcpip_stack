#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_adjacency.h"
#include "isis_lsdb.h"
#include "isis_flood.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}


bool
isis_interface_qualify_to_send_hellos(interface_t *intf) {

    if (isis_node_intf_is_enable(intf) &&
          IS_INTF_L3_MODE(intf) &&
          IF_IS_UP(intf)) {

              return true;
          }

    return false;
}


void
isis_enable_protocol_on_interface(interface_t *intf ) {

    isis_intf_info_t *intf_info = NULL;

    /* 1. Enable protocol on interface only when protocol is already enabled
            at node level, else throw an error
        2. If protocol already enabled on interface, then do nothing
        3. Enable the protocol on interface finally
    */
   if (ISIS_NODE_INFO(intf->att_node) == NULL) {
       printf("Error : Enable Protocol on node first\n");
       return;
   }

    intf_info = ISIS_INTF_INFO(intf);

    if (intf_info) {
        return;
    }

    intf_info = calloc ( 1, sizeof (isis_intf_info_t));
    intf->intf_nw_props.isis_intf_info = intf_info;
    intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    intf_info->cost = ISIS_DEFAULT_INTF_COST;

    sprintf(tlb, "%s : protocol is enabled on interface\n", ISIS_CONFIG_TRACE);
    tcp_trace(intf->att_node, intf, tlb);


    if (intf_info->hello_xmit_timer == NULL) {

        if (isis_interface_qualify_to_send_hellos(intf)) {
             isis_start_sending_hellos(intf);
        }
    }
}

static void
isis_free_intf_info(interface_t *intf) {

    if (!ISIS_INTF_INFO(intf)) return;
    free(ISIS_INTF_INFO(intf));
    intf->intf_nw_props.isis_intf_info = NULL;
}

static void 
isis_check_and_delete_intf_info(interface_t *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info) return;

    if (intf_info->hello_xmit_timer ||
         intf_info->adjacency ||
         !IS_GLTHREAD_LIST_EMPTY(&intf_info->lsp_xmit_list_head)) {
       assert(0);
    }    
    
    isis_free_intf_info(intf);
}

void
isis_disable_protocol_on_interface(interface_t *intf ) {

    isis_intf_info_t *intf_info = NULL;
    intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info)  return;
    isis_stop_sending_hellos(intf);
    isis_delete_adjacency(intf_info->adjacency);
    isis_intf_purge_lsp_xmit_queue(intf) ;
    isis_check_and_delete_intf_info(intf);
}

static void
isis_transmit_hello(void *arg, uint32_t arg_size) {

    if (!arg) return;

    isis_timer_data_t *isis_timer_data = 
            (isis_timer_data_t *)arg;

    node_t *node = isis_timer_data->node;
    interface_t *intf = isis_timer_data->intf;
    byte *hello_pkt = (byte *)isis_timer_data->data;
    uint32_t pkt_size = isis_timer_data->data_size;

    send_pkt_out(hello_pkt, pkt_size, intf);
    ISIS_INTF_INCREMENT_STATS(intf, hello_pkt_sent);
}

void
isis_start_sending_hellos(interface_t *intf) {

        node_t *node;
       size_t hello_pkt_size;

        assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
        assert(isis_node_intf_is_enable(intf));

        node = intf->att_node;
        wheel_timer_t *wt = node_get_timer_instance(node);
        
        byte *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);

       isis_timer_data_t *isis_timer_data =
                    calloc(1, sizeof(isis_timer_data_t));

        isis_timer_data->node = intf->att_node;
        isis_timer_data->intf = intf;
        isis_timer_data->data = (void *)hello_pkt;
        isis_timer_data->data_size = hello_pkt_size;

        ISIS_INTF_HELLO_XMIT_TIMER(intf)  = timer_register_app_event(wt, 
                                                  isis_transmit_hello,
                                                  (void *)isis_timer_data,
                                                  sizeof(isis_timer_data_t),
                                                  ISIS_INTF_HELLO_INTERVAL(intf) * 1000,
                                                  1);
}

void
isis_stop_sending_hellos(interface_t *intf) {

      timer_event_handle *hello_xmit_timer = NULL;

      hello_xmit_timer =  ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (!hello_xmit_timer) return;

    isis_timer_data_t *isis_timer_data =
        (isis_timer_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, 0);

    tcp_ip_free_pkt_buffer(isis_timer_data->data, 
                                        isis_timer_data->data_size);

    free(isis_timer_data);

    timer_de_register_app_event(hello_xmit_timer);
    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
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

    isis_intf_info = ISIS_INTF_INFO(intf);
  
    PRINT_TABS(2);
    printf("hello interval : %u sec, Intf Cost : %u\n",
        isis_intf_info->hello_interval, isis_intf_info->cost);

    PRINT_TABS(2);
    printf("hello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");  

    PRINT_TABS(2);
    printf("Adjacencies :\n");

   adjacency = isis_intf_info->adjacency;
   if (!adjacency) return;
   isis_show_adjacency(adjacency, 4);
   printf("\n");
}

/* show per intf stats */

void
isis_show_one_intf_stats (interface_t *intf) {

    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info) return;

    printf ("%s\t", intf->if_name);
    printf ("H Tx : %-4u H Rx : %-4u BadH Rx : %-4u\n",
                        intf_info->hello_pkt_sent,
                        intf_info->good_hello_pkt_recvd,
                        intf_info->bad_hello_pkt_recvd);
}

void
isis_show_all_intf_stats(node_t *node) {

    interface_t *intf;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_one_intf_stats(intf);

    } ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_refresh_intf_hellos(interface_t *intf) {

    isis_stop_sending_hellos(intf);
    isis_start_sending_hellos(intf);
}

static void
isis_handle_interface_up_down (interface_t *intf, bool old_status) {

    /* Current Status of interface can be examined :  IF_IS_UP (intf) */

    /* When interface is enabled ( old_status == false ):
        1. Start sending Hellos (isis_start_sending_hellos( ) ) only if interface qualifies (isis_interface_qualify_to_send_hellos ( ) )  */

    if (old_status == false) {
        if (!isis_interface_qualify_to_send_hellos(intf)) return;
        isis_start_sending_hellos(intf);
    }

    /* When interface is shut down ( old_status == true )
        1. Stop sending Hellos ( isis_stop_sending_hellos( ( ) )
        2. Delete Adjacency on this interface ( isis_delete_adjacency( ) )*/
    else {
        isis_stop_sending_hellos(intf);
        isis_adjacency_t *adjacency = ISIS_INTF_INFO(intf)->adjacency;
        if (!adjacency) return;
        isis_adj_state_t adj_state = adjacency->adj_state;
        isis_delete_adjacency(adjacency);
        ISIS_INTF_INFO(intf)->adjacency = NULL;
        if (adj_state == ISIS_ADJ_STATE_UP) {
            isis_schedule_lsp_pkt_generation(intf->att_node);
        }
    }
}

static void
isis_handle_interface_ip_addr_changed (interface_t *intf, 
                                                                uint32_t old_ip_addr, uint8_t old_mask) {

    /* 1. Addition of new IP Address
            > Start sending hellos if interface Qualifies */
        if (IF_IP_EXIST(intf) && !old_ip_addr && !old_mask) {

            if (isis_interface_qualify_to_send_hellos(intf)) {
                isis_start_sending_hellos(intf);
            }
            return;
        }

    /* 2. Removal of IP Address
            > Stop sending hellos if xmitting
            > delete adjacency object if exist */
        if (!IF_IP_EXIST(intf) && old_mask && old_ip_addr) {

            isis_stop_sending_hellos(intf);
            isis_adjacency_t *adjacency = ISIS_INTF_INFO(intf)->adjacency;
            if (!adjacency) return;
            isis_delete_adjacency(adjacency);
            isis_adj_state_t adj_state = adjacency->adj_state;
            ISIS_INTF_INFO(intf)->adjacency = NULL;
            if (adj_state == ISIS_ADJ_STATE_UP) {
                isis_schedule_lsp_pkt_generation(intf->att_node);
            }
            return;
        }


    /*    3. Change of IP Address
            > if interface qualify to send hellos, Update hello content (  isis_refresh_intf_hellos() )
            > otherwise stop sending hellos */ 

    isis_interface_qualify_to_send_hellos(intf) ?
        isis_refresh_intf_hellos(intf) :
        isis_stop_sending_hellos(intf);

    if (ISIS_INTF_INFO(intf)->adjacency && 
         ISIS_INTF_INFO(intf)->adjacency->adj_state == ISIS_ADJ_STATE_UP) {
        isis_schedule_lsp_pkt_generation(intf->att_node);
    }
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

    switch (flags) {

    case IF_UP_DOWN_CHANGE_F:
        isis_handle_interface_up_down(intf, old_intf_prop_changed->up_status);
        break;
    case IF_IP_ADDR_CHANGE_F:
        isis_handle_interface_ip_addr_changed(intf,
                                              old_intf_prop_changed->ip_addr.ip_addr,
                                              old_intf_prop_changed->ip_addr.mask);
        break;
    case IF_OPER_MODE_CHANGE_F:
    case IF_VLAN_MEMBERSHIP_CHANGE_F:
    case IF_METRIC_CHANGE_F:
    default:;
    }
}
