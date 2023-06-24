#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_adjacency.h"
#include "isis_rtr.h"
#include "isis_flood.h"
#include "isis_intf_group.h"
#include "isis_dis.h"
#include "isis_utils.h"

bool
isis_node_intf_is_enable(Interface *intf) {

    return !(intf->isis_intf_info == NULL);
}

bool
isis_interface_qualify_to_send_hellos(Interface *intf){

    if (isis_node_intf_is_enable(intf) &&
         intf->IsIpConfigured() &&
         intf->is_up) {
             
            return true;
    }
    return false;
}

static void
isis_transmit_hello(event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    pkt_block_t *pkt_block;

    if (!arg) return;

    isis_timer_data_t *isis_timer_data =
        (isis_timer_data_t *)arg;

    node_t *node = isis_timer_data->node;
    Interface *egress_intf = isis_timer_data->intf;
    char *hello_pkt = isis_timer_data->data;
    pkt_size_t pkt_size = (pkt_size_t )isis_timer_data->data_size;

    if (hello_pkt && pkt_size) {
        ISIS_INTF_INCREMENT_STATS(egress_intf, hello_pkt_sent);
        pkt_block = pkt_block_get_new((uint8_t *)hello_pkt, pkt_size);
        egress_intf->SendPacketOut(pkt_block);
        XFREE(pkt_block);
    }
}

void
isis_send_hello_immediately (Interface *intf) {

     byte *hello_pkt;
     bool new_hello;
     pkt_block_t *pkt_block;
     size_t hello_pkt_size;
     isis_timer_data_t *isis_timer_data;
     timer_event_handle *hello_xmit_timer ;

    hello_xmit_timer = ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (hello_xmit_timer) {
        isis_timer_data =
        (isis_timer_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, hello_xmit_timer->arg);
        hello_pkt = (byte *) isis_timer_data->data;
        hello_pkt_size =isis_timer_data->data_size;
        new_hello = false;
    }
    else {

        hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);
        new_hello = true;
    }

     if (hello_pkt && hello_pkt_size) {

            ISIS_INTF_INCREMENT_STATS(intf, hello_pkt_sent);
            pkt_block = pkt_block_get_new(hello_pkt, hello_pkt_size);
            intf->SendPacketOut(pkt_block);
            new_hello ? pkt_block_free (pkt_block) : XFREE(pkt_block);
    }
 
}

void
isis_start_sending_hellos (Interface *intf) {

    node_t *node;
    size_t hello_pkt_size;
    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO (intf);
    
    if (!intf_info) return;
    if (intf_info->hello_xmit_timer) return;
   
    node = intf->att_node;
    byte *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);

    isis_timer_data_t *isis_timer_data =
        XCALLOC(0, 1, isis_timer_data_t);

    isis_timer_data->node = node;
    isis_timer_data->intf = intf;
    isis_timer_data->data = hello_pkt;
    isis_timer_data->data_size = hello_pkt_size;

    intf_info->hello_xmit_timer = timer_register_app_event(
                                        CP_TIMER(node),
                                        isis_transmit_hello,
                                        (void *)isis_timer_data,
                                        sizeof(isis_timer_data_t),
                                        ISIS_INTF_HELLO_INTERVAL(intf) * 1000,
                                        1);
    
    if (intf_info->hello_xmit_timer == NULL) {
        XFREE(isis_timer_data);
    }
}

void
isis_stop_sending_hellos(Interface *intf){

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
isis_refresh_intf_hellos(Interface *intf) {

    isis_stop_sending_hellos(intf);
    if (isis_interface_qualify_to_send_hellos (intf)) {
        isis_start_sending_hellos(intf);
        isis_send_hello_immediately (intf);
    }
}


static void
isis_init_intf_info (Interface *intf) {
      
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    memset(intf_info, 0, sizeof(isis_intf_info_t));
    intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    intf_info->cost = ISIS_DEFAULT_INTF_COST;
    intf_info->priority = ISIS_INTF_DEFAULT_PRIORITY;
    intf_info->intf_type = isis_intf_type_lan;
    intf_info->level = isis_level_1; /* Only Lvl 1 is Supported for now*/
    intf_info->lan_id = {0, 0};
    init_glthread(&intf_info->adj_list_head);
    init_glthread(&intf_info->intf_grp_member_glue);
    if ( isis_intf_is_lan (intf)) {
        isis_intf_allocate_lan_id (intf);
        intf_info->elected_dis = {0, 0};
        isis_intf_assign_new_dis (intf, intf_info->lan_id);
    }
    /* Back Linkage */
    intf_info->intf = intf;
}

void
isis_enable_protocol_on_interface(Interface *intf) {

    isis_intf_info_t *intf_info = NULL;

    if (!isis_is_protocol_enable_on_node(intf->att_node)) {
        return;
    }

    intf_info = ISIS_INTF_INFO(intf);

    if (! intf_info ) {

        intf_info = XCALLOC(0, 1, isis_intf_info_t);
        intf->isis_intf_info = intf_info;
        isis_init_intf_info(intf);
    }
    
    if (intf_info->hello_xmit_timer == NULL) {
        if (isis_interface_qualify_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
            isis_send_hello_immediately (intf);
        }
    }
}

static void
isis_free_intf_info(Interface *intf) {

    if (!ISIS_INTF_INFO(intf)) return;
    XFREE(ISIS_INTF_INFO(intf));
    intf->isis_intf_info = NULL;
}

static void 
isis_check_and_delete_intf_info(Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    assert (!ISIS_INTF_HELLO_XMIT_TIMER(intf));
    assert (IS_GLTHREAD_LIST_EMPTY(ISIS_INTF_ADJ_LST_HEAD(intf)) );
    assert (IS_GLTHREAD_LIST_EMPTY(&intf_info->lsp_xmit_list_head) );
    assert (IS_GLTHREAD_LIST_EMPTY(&intf_info->intf_grp_member_glue) );
    assert (!intf_info->lsp_xmit_job);
    assert (isis_is_lan_id_null (intf_info->lan_id));
    assert (isis_is_lan_id_null (intf_info->elected_dis) );
    assert (!intf_info->lan_self_to_pn_adv_data);
    assert (!intf_info->lan_pn_to_self_adv_data);

    isis_free_intf_info(intf);
}

void
isis_disable_protocol_on_interface(Interface *intf) {

    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) return;

    isis_stop_sending_hellos(intf);
    isis_delete_all_adjacencies(intf);
    remove_glthread(&intf_info->intf_grp_member_glue);
    intf_info->intf_grp = NULL;
    if (isis_intf_is_lan(intf)) {
        isis_intf_resign_dis(intf);
        isis_intf_deallocate_lan_id (intf);
    }
    /* Must be last call in this fn, as prev call could
        result in LSP pkts queuing again*/
     isis_intf_purge_lsp_xmit_queue(intf);
    isis_check_and_delete_intf_info(intf);
}

void
isis_show_interface_protocol_state(Interface *intf) {

    bool is_enabled;
    glthread_t *curr;
    byte buffer[32];
    isis_adjacency_t *adjacency = NULL;
    isis_intf_info_t *intf_info = NULL;

    is_enabled = isis_node_intf_is_enable(intf);

    cprintf(" %s : %sabled\n", intf->if_name.c_str(), is_enabled ? "En" : "Dis");
    
    if(!is_enabled) return;

    intf_info = intf->isis_intf_info;
   
   PRINT_TABS(2);
   cprintf ("link-type: %s", intf_info->intf_type == isis_intf_type_p2p ? "p2p" : "lan");
   if (intf_info->intf_type == isis_intf_type_lan) {
        cprintf ("    lan-id : %s\n", isis_lan_id_tostring(&intf_info->lan_id, buffer));
        cprintf ("    elected dis-id : %s\n", isis_lan_id_tostring(&intf_info->elected_dis, buffer));
   }
   else {
        cprintf ("\n");
   }
    if (intf_info->intf_grp) {
         PRINT_TABS(2);
        cprintf("Intf Group : %s \n", intf_info->intf_grp->name);
    }
    PRINT_TABS(2);
    cprintf("hello interval : %u sec, Intf Cost : %u, Priority : %hu\n",
        intf_info->hello_interval, intf_info->cost, intf_info->priority);

    PRINT_TABS(2);
    cprintf("hello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");  

    PRINT_TABS(2);
    cprintf("Stats :\n");
    PRINT_TABS(3);
    cprintf("> good_hello_pkt_recvd : %u\n", intf_info->good_hello_pkt_recvd);
    PRINT_TABS(3);
    cprintf("> bad_hello_pkt_recvd : %u\n", intf_info->bad_hello_pkt_recvd);
    PRINT_TABS(3);
    cprintf("> good_lsps_pkt_recvd : %u\n", intf_info->good_lsps_pkt_recvd);
    PRINT_TABS(3);
    cprintf("> bad_lsps_pkt_recvd : %u\n", intf_info->bad_lsps_pkt_recvd);
    PRINT_TABS(3);
    cprintf("> lsp_pkt_sent : %u\n", intf_info->lsp_pkt_sent);
    PRINT_TABS(3);
    cprintf("> hello_pkt_sent : %u\n", intf_info->hello_pkt_sent);

    PRINT_TABS(2);
    cprintf("Adjacencies :\n");

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        isis_show_adjacency(adjacency, 4);
        cprintf("\n");
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr)
    cprintf("\n");
}

static void
isis_handle_interface_up_down (Interface *intf, bool old_status) {

    isis_lan_id_t new_dis;

    if (old_status == false) {

        new_dis = isis_intf_reelect_dis (intf);
        isis_intf_assign_new_dis (intf, new_dis);
        /* Interace has been no-shut */
        /* 1. Start sending hellos out of interface if it qualifies
            2. Start processing hellos on this interface if it qualifies */
        if (isis_interface_qualify_to_send_hellos(intf)) {
             isis_start_sending_hellos (intf);
             isis_send_hello_immediately (intf);
        }
    }
    else {

        /* interface has been shut down */
        isis_stop_sending_hellos(intf);
        isis_delete_all_adjacencies(intf);
        isis_intf_resign_dis (intf);
    }
}

static void
isis_handle_interface_ip_addr_changed (Interface *intf, 
                                                                uint32_t old_ip_addr, uint8_t old_mask) {

    uint8_t mask;
    uint32_t ip_addr;
    glthread_t *curr;
    isis_lan_id_t new_dis;
    isis_intf_info_t *intf_info;    
    isis_adv_data_t *advt_data;
    isis_adjacency_t *adjacency;

    /* case 1 : New IP Address Added, start sending hellos if intf qualifies*/

    if (intf->IsIpConfigured() && !old_ip_addr && !old_mask) {

        /* Update Hellos*/
        if (isis_interface_qualify_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
            isis_send_hello_immediately (intf);
        }

        /* Adding an IP Address may make interface eligible for DIS election. Though it
            wont have any adjacency at this point, we would go ahead and re-elect self as DIS
            and accordingly advertise IS reach TLVs.*/
        if (isis_intf_is_lan (intf)) {
            isis_intf_resign_dis (intf);
            new_dis = isis_intf_reelect_dis (intf);
            isis_intf_assign_new_dis (intf, new_dis);
        }
        else {
            /* No Action needed*/
        }
        return;
    }

    /* case 2 : IP Address Removed, stop sending hellos, delete all adj on this intf, regen LSP*/

    if (!intf->IsIpConfigured() && old_ip_addr && old_mask) {

        isis_stop_sending_hellos(intf);
        isis_delete_all_adjacencies(intf);
         if (isis_intf_is_lan (intf)) {
            isis_intf_resign_dis (intf);
         }
         else {
            /* No Action needed*/
         }
        return;
    }

    /*case 3 : IP Address changed, start sending hellos if intf qualifies with new IP Address
        Nbr must bring down adj if new IP Address do not matches same subnet 
        Nbr must update its Adj data and LSP as per new Ip Address info recvd from this rtr */
    
    isis_stop_sending_hellos(intf);
    if (isis_interface_qualify_to_send_hellos(intf)) {
        isis_refresh_intf_hellos(intf);
        isis_send_hello_immediately (intf);
    }     

    /* Update local IP advertised in IS REACH TLVs */
    if (isis_intf_is_lan (intf)) {

        intf_info = ISIS_INTF_INFO (intf);
        intf->InterfaceGetIpAddressMask (&ip_addr, &mask);

        /* Update advt_data from self to PN i.e. intf_info->lan_self_to_pn_adv_data */
        if (intf_info->lan_self_to_pn_adv_data) {

            advt_data = intf_info->lan_self_to_pn_adv_data;
            advt_data->u.adj_data.local_intf_ip = ip_addr;
            isis_schedule_regen_fragment (intf->att_node, advt_data->fragment, isis_event_admin_config_changed);
        }

        /* Update advt_data from PN to self-DIS i.e. intf_info->lan_pn_to_self_adv_data */
        if (intf_info->lan_pn_to_self_adv_data) {

            advt_data = intf_info->lan_pn_to_self_adv_data;
            advt_data->u.adj_data.remote_intf_ip =  ip_addr;
            isis_schedule_regen_fragment (intf->att_node, advt_data->fragment, isis_event_admin_config_changed);
        }
    }
    else {
        
        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {
            
            adjacency = glthread_to_isis_adjacency(curr);
             if (!adjacency->u.p2p_adv_data) continue;
             advt_data = adjacency->u.p2p_adv_data;
             intf->InterfaceGetIpAddressMask (&ip_addr, &mask);
             advt_data->u.adj_data.local_intf_ip = ip_addr;
            isis_schedule_regen_fragment (intf->att_node, advt_data->fragment, isis_event_admin_config_changed);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    }
}

void
isis_interface_updates (event_dispatcher_t *ev_dis, void *arg, size_t arg_size) {

	intf_notif_data_t *intf_notif_data = 
		(intf_notif_data_t *)arg;

	uint32_t flags = intf_notif_data->change_flags;
	Interface *intf = intf_notif_data->interface;
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

/* show per intf stats */
uint32_t
isis_show_one_intf_stats (Interface *intf, uint32_t rc) {

    byte *buff;
    uint32_t rc_old;
    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info) return 0;

    buff = intf->att_node->print_buff ;
    rc_old = rc;

    rc += cprintf ("%s\t", intf->if_name.c_str());
    rc += cprintf ("H Tx : %-4u H Rx : %-4u BadH Rx : %-4u "
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
    Interface *intf;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return 0;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;
        rc += isis_show_one_intf_stats(intf, rc);

    } ITERATE_NODE_INTERFACES_END(node, intf);

    return rc;
}

int
isis_config_interface_link_type(Interface *intf, isis_intf_type_t intf_type) {

    bool rc;
    pn_id_t pn_id;
    uint32_t rtr_id;
    node_t *node = intf->att_node;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!intf_info) return -1;

    if (intf_info->intf_type == intf_type) return 0;

    isis_delete_all_adjacencies(intf);
    isis_stop_sending_hellos(intf);

    if (intf_type == isis_intf_type_p2p) {
        isis_intf_resign_dis (intf);
        isis_intf_deallocate_lan_id (intf);
        intf_info->intf_type = intf_type;
    }
    else {
        intf_info->intf_type = intf_type;
        isis_intf_allocate_lan_id (intf);
        isis_intf_assign_new_dis (intf, intf_info->lan_id);
    }

    isis_interface_reset_stats (intf);

    if (isis_interface_qualify_to_send_hellos(intf)) {
        isis_start_sending_hellos(intf);
        isis_send_hello_immediately (intf);
    }
    return 0;
}

int
isis_interface_set_priority (Interface *intf, uint16_t priority,  bool enable) {

    isis_lan_id_t old_dis_id,
                          new_dis_id;

   node_t *node = intf->att_node;

   isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

   if (!intf_info) return -1;

    if (enable) {
        if (intf_info->priority == priority) return 0;
        intf_info->priority = priority;
    }
    else {
        if (intf_info->priority == ISIS_INTF_DEFAULT_PRIORITY) return 0;
        intf_info->priority = ISIS_INTF_DEFAULT_PRIORITY;
    }

    isis_stop_sending_hellos(intf);

    if (isis_interface_qualify_to_send_hellos (intf)) {
        isis_start_sending_hellos(intf);
        isis_send_hello_immediately (intf);
    }

    if (isis_intf_is_p2p(intf)) return 0;

    old_dis_id = intf_info->elected_dis;
    new_dis_id =  isis_intf_reelect_dis(intf);    

    if (isis_lan_id_compare (&old_dis_id, &new_dis_id) == CMP_PREF_EQUAL) {
        return 0;
    }

    isis_intf_resign_dis (intf);
    isis_intf_assign_new_dis (intf,  new_dis_id);
    return 0;
}

int
isis_interface_set_metric (Interface *intf, uint32_t metric, bool enable) {

    isis_adv_data_t *advt_data;

    isis_lan_id_t old_dis_id,
                          new_dis_id;

   node_t *node = intf->att_node;

   isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

   if (!intf_info) return -1;

    if (enable) {
        if (intf_info->cost == metric) return 0;
        intf_info->cost = metric;
    }
    else {
        if (intf_info->cost == ISIS_DEFAULT_INTF_COST) return 0;
        intf_info->cost = ISIS_DEFAULT_INTF_COST;
    }

    isis_stop_sending_hellos(intf);

    if (isis_interface_qualify_to_send_hellos (intf)) {
        isis_start_sending_hellos(intf);
        isis_send_hello_immediately (intf);
    }

    if (isis_intf_is_p2p(intf)) return 0;

   /* Update all advertisments in which we are advertising the metrics*/

   advt_data = intf_info->lan_pn_to_self_adv_data;

    if (advt_data) {

        advt_data->u.adj_data.metric = intf_info->cost;

        if (advt_data->fragment) {
            isis_schedule_regen_fragment (node, advt_data->fragment, isis_event_admin_config_changed);
        }
    }

    return 0;
}

void
isis_interface_reset_stats (Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);
    
    if (!intf_info) return;

    intf_info->good_hello_pkt_recvd = 0;
    intf_info->bad_hello_pkt_recvd = 0;
    intf_info->good_lsps_pkt_recvd = 0;
    intf_info->bad_lsps_pkt_recvd = 0;
    intf_info->lsp_pkt_sent = 0;
    intf_info ->hello_pkt_sent = 0;
}
