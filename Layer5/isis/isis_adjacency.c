#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_enums.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_pkt.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_intf_group.h"
#include "isis_layer2map.h"
#include "isis_dis.h"
#include "isis_utils.h"

static void
isis_init_adjacency(isis_adjacency_t *adjacency) {

    memset(adjacency, 0, sizeof(isis_adjacency_t));
    adjacency->last_transition_time = time(NULL); /* Current system time */
    adjacency->adj_state = ISIS_ADJ_STATE_DOWN;
    adjacency->priority = ISIS_INTF_DEFAULT_PRIORITY;
    init_glthread(&adjacency->glue);
}

/* Timer fns for ISIS Adjacency Mgmt */
static void
isis_timer_expire_delete_adjacency_cb(
                                      event_dispatcher_t *ev_dis,
                                      void *arg,
                                      uint32_t arg_size){

    if (!arg) return;
    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;
    isis_delete_adjacency(adjacency);
}

static void
isis_timer_expire_down_adjacency_cb(event_dispatcher_t *ev_dis,
                                     void *arg, uint32_t arg_size){

    if (!arg) return;

    char adj_name[128];
    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;

   trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ,
        "Adjacency %s Up timer Expired\n",
        isis_adjacency_name(adj_name, adjacency));

    isis_change_adjacency_state((isis_adjacency_t *)arg, ISIS_ADJ_STATE_DOWN);
}

static void
isis_adjacency_start_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->expiry_timer){
        return;
    }

    char adj_name[128];

    adjacency->expiry_timer = timer_register_app_event(
                                    CP_TIMER(adjacency->intf->att_node),
                                    isis_timer_expire_down_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    adjacency->hold_time * 1000,
                                    0);

    if(!adjacency->expiry_timer){
        
        trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ERRORS,
            "Adjacency %s Expiry timer failed to start\n",
            isis_adjacency_name(adj_name, adjacency));
        return;
    }

    trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ,
        "Adjacency %s Expiry timer started\n",
        isis_adjacency_name(adj_name, adjacency));
}

 static void
 isis_adjacency_refresh_expiry_timer(
        isis_adjacency_t *adjacency) {
  
    assert(adjacency->expiry_timer);
    timer_reschedule(adjacency->expiry_timer, adjacency->hold_time * 1000);
}

static void
isis_adjacency_stop_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(!adjacency->expiry_timer){
        return;
    }

    char adj_name[128];

    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
    trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ,
        "Adjacency %s Expiry timer stopped\n",
        isis_adjacency_name(adj_name, adjacency));
}

void
isis_adjacency_set_uptime(isis_adjacency_t *adjacency) {

    assert(adjacency->adj_state == ISIS_ADJ_STATE_UP);
    adjacency->uptime = time(NULL);
}

static void
isis_adjacency_start_delete_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->delete_timer){
        return;
    }

    char adj_name[128];

    adjacency->delete_timer = timer_register_app_event(
                                    CP_TIMER(adjacency->intf->att_node),
                                    isis_timer_expire_delete_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    ISIS_ADJ_DEFAULT_DELETE_TIME,
                                    0);
    
    if (!adjacency->delete_timer){
        trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ERRORS,
            "Adjacency %s Delete timer could not be started\n",
            isis_adjacency_name(adj_name, adjacency));
        return;
    }

   trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ, 
            "Adjacency %s Delete timer started\n",
             isis_adjacency_name(adj_name, adjacency));
}

static void
isis_adjacency_stop_delete_timer(
        isis_adjacency_t *adjacency) {

    if(!adjacency->delete_timer){
        return;
    }

    char adj_name[128];
    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;

     trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ | TR_ISIS_EVENTS, 
            "Adjacency %s Delete timer stopped\n",
            isis_adjacency_name(adj_name, adjacency));
}

/* Timer fns for ISIS Adjacency Mgmt End */


void
isis_delete_adjacency(isis_adjacency_t *adjacency) {

    char adj_name[128];
    remove_glthread(&adjacency->glue);
    isis_adjacency_stop_expiry_timer(adjacency);
    isis_adjacency_stop_delete_timer(adjacency);
    trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ | TR_ISIS_EVENTS, 
        "Adjacency %s Deleted\n", isis_adjacency_name(adj_name, adjacency));
    if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {
        ISIS_DECREMENT_NODE_STATS(adjacency->intf->att_node, adjacency_up_count);
        isis_update_layer2_mapping_on_adjacency_down(adjacency);
        isis_adjacency_withdraw_is_reach (adjacency);
    }
    isis_dynamic_intf_grp_update_on_adjacency_delete(adjacency);
   XFREE(adjacency);
}

int
isis_delete_all_adjacencies(Interface *intf) {

    int rc = 0;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        isis_delete_adjacency(adjacency);
        rc++;
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);
    return rc;
}



static int
isis_adjacency_comp_fn(void *data1, void *data2) {

    int8_t rc;

    isis_adjacency_t *adj1 = (isis_adjacency_t *)data1;
    isis_adjacency_t *adj2 = (isis_adjacency_t *)data2;
    
    if (adj1->adj_state != adj2->adj_state) {
        if (adj1->adj_state != ISIS_ADJ_STATE_UP) return CMP_NOT_PREFERRED;
    }
    if (adj1->priority < adj2->priority) return CMP_NOT_PREFERRED;
    if (adj1->priority > adj2->priority) return CMP_PREFERRED;
    if (adj1->nbr_rtr_id < adj2->nbr_rtr_id) return CMP_NOT_PREFERRED;
    if (adj1->nbr_rtr_id > adj2->nbr_rtr_id) return CMP_PREFERRED;

    rc = memcmp (&adj1->nbr_mac, &adj2->nbr_mac, sizeof(adj2->nbr_mac));

    if (rc > 0) return CMP_PREFERRED;
    if (rc < 0) return CMP_NOT_PREFERRED;

    return CMP_PREF_EQUAL;
}

void
isis_update_interface_adjacency_from_hello(
        Interface *iif,
        isis_common_hdr_t *cmn_hdr,
        size_t hello_pkt_size) {

    node_t *node;
    char ip_addr[16];
    byte lan_id_str[32];
    byte sys_id_str[32];
    uint16_t tlv_buff_size;
    uint8_t tlv_data_len;
    bool new_adj = false;
    bool regen_lsp = false;
    bool reelect_dis = false;
    byte *hello_tlv_buffer;
    isis_system_id_t sys_id;
    c_string intf_ip_addr_str;
    uint32_t four_byte_data;
    uint32_t intf_ip_addr_int;
    isis_adjacency_t *adjacency = NULL;
    isis_adjacency_t adjacency_backup;
    isis_p2p_hello_pkt_hdr_t *p2p_hdr = NULL;
    isis_lan_hello_pkt_hdr_t *lan_hdr = NULL;
    bool force_bring_down_adjacency = false;

    node = iif->att_node;

    hello_tlv_buffer = isis_get_pkt_tlv_buffer (cmn_hdr, &tlv_buff_size);

    switch (cmn_hdr->pdu_type) {
        case ISIS_PTP_HELLO_PKT_TYPE:
            p2p_hdr = (isis_p2p_hello_pkt_hdr_t *)(cmn_hdr + 1);
            sys_id = p2p_hdr->source_id;
            break;
        default:
            lan_hdr = (isis_lan_hello_pkt_hdr_t *)(cmn_hdr + 1);
            sys_id = lan_hdr->source_id;
    }

    isis_system_id_tostring (&sys_id, sys_id_str);

    adjacency = isis_find_adjacency_on_interface(iif, &sys_id);

    if(!adjacency){
        adjacency = (isis_adjacency_t *)XCALLOC(0, 1, isis_adjacency_t);
        isis_init_adjacency(adjacency);
        adjacency->intf = iif;
        adjacency->nbr_sys_id = sys_id;
        adjacency->priority = lan_hdr ? lan_hdr->priority : ISIS_INTF_DEFAULT_PRIORITY;
        if (lan_hdr) adjacency->lan_id = lan_hdr->lan_id;
        glthread_priority_insert(ISIS_INTF_ADJ_LST_HEAD(iif), 
                                                &adjacency->glue,
                                                isis_adjacency_comp_fn,
                                                (int)&((isis_adjacency_t *)0)->glue);
        new_adj = true;
        trace (ISIS_TR(node), TR_ISIS_ADJ,  "%s : New Adjacency for nbr %s on intf %s Created\n",
            ISIS_ADJ_MGMT, sys_id_str, iif->if_name.c_str());
    }
    else {
        memcpy(&adjacency_backup, adjacency, sizeof(isis_adjacency_t));
    }

    /* Change in Nbr's LAN-ID */
    if (!new_adj && lan_hdr && 
            (isis_lan_id_compare (&adjacency->lan_id, &lan_hdr->lan_id) != CMP_PREF_EQUAL)) {
        
        trace (ISIS_TR(node), TR_ISIS_ADJ, "%s : Nbr %s reported new lan-id %s on intf %s\n",
             ISIS_ADJ_MGMT, sys_id_str, isis_lan_id_tostring(&lan_hdr->lan_id, lan_id_str), 
             iif->if_name.c_str());

        if (isis_lan_id_compare(
                &(ISIS_INTF_INFO(iif)->elected_dis), 
                &lan_hdr->lan_id) != CMP_PREF_EQUAL) {
            /* We dont need to do any action if the new lan-id reported was not DIS*/
            adjacency->lan_id = lan_hdr->lan_id;
        }
        else {
           trace (ISIS_TR(node), TR_ISIS_ADJ, "%s : Dis Election will happen on intf %s, reason new lan-id  reported was also elected DIS\n",
            ISIS_ADJ_MGMT, iif->if_name.c_str());
            adjacency->lan_id = lan_hdr->lan_id;
            reelect_dis = true;
        }
    }

    if (!new_adj &&
          lan_hdr &&
        (adjacency->priority != lan_hdr->priority)) {
            adjacency->priority =  lan_hdr->priority;
            reelect_dis = true;
    }

    if (reelect_dis && 
            (adjacency->adj_state == ISIS_ADJ_STATE_DOWN || 
            adjacency->adj_state == ISIS_ADJ_STATE_UP)) {
    
        isis_update_dis_on_adjacency_transition (adjacency);
    }

    byte tlv_type, tlv_len, *tlv_value = NULL;
    ITERATE_TLV_BEGIN(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size){
        
        switch(tlv_type){
            case ISIS_TLV_HOSTNAME:
                if (memcmp(adjacency->nbr_name, tlv_value, tlv_len)) {
                    regen_lsp = true;
                    memcpy(adjacency->nbr_name, tlv_value, tlv_len);
                }
            break;
            case ISIS_TLV_RTR_ID:
                if (adjacency->nbr_rtr_id != *(uint32_t *)(tlv_value)) {
                    adjacency->nbr_rtr_id = *(uint32_t *)(tlv_value);
                    force_bring_down_adjacency = true;
                }
            break;    
            case ISIS_TLV_IF_IP:
                memcpy((byte *)&four_byte_data, tlv_value, sizeof(four_byte_data));
                if (adjacency->nbr_intf_ip != four_byte_data ) {
                    adjacency->nbr_intf_ip = four_byte_data;
                     force_bring_down_adjacency = true;
                }
            break;
            case ISIS_TLV_IF_INDEX:
                if (adjacency->remote_if_index != *(uint32_t *)tlv_value) {
                    memcpy((byte *)&adjacency->remote_if_index, tlv_value, tlv_len);
                    regen_lsp = true;
                }
            break;
            case ISIS_TLV_HOLD_TIME:
                adjacency->hold_time = *((uint32_t *)tlv_value);
            break;
            case ISIS_TLV_METRIC_VAL:
                if (adjacency->cost != *((uint32_t *)tlv_value)) {
                    adjacency->cost = *((uint32_t *)tlv_value);
                    regen_lsp= true;
                }
            break;
            case ISIS_TLV_IF_MAC:
                if (memcmp(adjacency->nbr_mac.mac, (byte *)tlv_value, tlv_len)) {
                    memcpy(adjacency->nbr_mac.mac, tlv_value, tlv_len);
                    force_bring_down_adjacency = true;
                }
            default: ;
        }
    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    if(new_adj) {
        isis_adjacency_start_delete_timer(adjacency);
        isis_dynamic_intf_grp_update_on_adjacency_create (adjacency);
    }
    else if (force_bring_down_adjacency) {
        isis_update_layer2_mapping_on_adjacency_down(&adjacency_backup);
        isis_change_adjacency_state(adjacency, ISIS_ADJ_STATE_DOWN);
    }
    else {
            isis_adj_state_t adj_next_state = 
                isis_get_next_adj_state_on_receiving_next_hello(adjacency);
        isis_change_adjacency_state(adjacency, adj_next_state);
    }

   if (regen_lsp && !force_bring_down_adjacency) {
        trace(ISIS_TR(node), TR_ISIS_ADJ | TR_ISIS_EVENTS, 
            "%s : ISIS Adjacency attributes changed, regen LSP \n", ISIS_ADJ_MGMT);
        isis_adjacency_withdraw_is_reach(adjacency);
        isis_adjacency_advertise_is_reach(adjacency);
   }
    ISIS_INTF_INCREMENT_STATS(iif, good_hello_pkt_recvd);
}

char *
isis_adjacency_name(char *adj_name, isis_adjacency_t *adjacency) {

    snprintf(adj_name, sizeof(adj_name), "%s::%s", 
        adjacency->intf->if_name.c_str(), 
        adjacency->nbr_name);
    return adj_name;
}

isis_adjacency_t *
isis_find_adjacency_on_interface(
        Interface *intf,
        isis_system_id_t *sys_id) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;
    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);

    if(!intf_info) return NULL;

    if (!sys_id) {
        curr = glthread_get_next (ISIS_INTF_ADJ_LST_HEAD(intf));
        if (!curr) return NULL;
        return glthread_to_isis_adjacency(curr);
    }

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

        adjacency = glthread_to_isis_adjacency(curr);
        if (isis_system_id_compare (&adjacency->nbr_sys_id, sys_id)  == CMP_PREF_EQUAL) {
            return adjacency;
        }
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    return NULL;
}

void
isis_show_adjacency( isis_adjacency_t *adjacency,
                                    uint8_t tab_spaces) {

    char ip_addr_str[16];
    byte lan_id_str[32];
    byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];

    PRINT_TABS(tab_spaces);
    tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id, ip_addr_str);
    cprintf("Nbr : %s(%s)   priority : %u\n", adjacency->nbr_name, ip_addr_str, adjacency->priority);
    PRINT_TABS(tab_spaces);
    cprintf ("Nbr Sys-id : %s\n", isis_system_id_tostring (&adjacency->nbr_sys_id, lan_id_str));

    if (ISIS_INTF_INFO(adjacency->intf)->intf_type == isis_intf_type_lan) {
        PRINT_TABS(tab_spaces);
        cprintf ("Nbr Lan-id : %s\n", isis_lan_id_tostring (&adjacency->lan_id, lan_id_str));
    }

    PRINT_TABS(tab_spaces);
    tcp_ip_covert_ip_n_to_p( adjacency->nbr_intf_ip, ip_addr_str);
    cprintf("Nbr intf ip : %s  ifindex : %u\n",
        ip_addr_str,
        adjacency->remote_if_index);

    PRINT_TABS(tab_spaces);
    cprintf("Nbr Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            adjacency->nbr_mac.mac[0], 
            adjacency->nbr_mac.mac[1], 
            adjacency->nbr_mac.mac[2], 
            adjacency->nbr_mac.mac[3], 
            adjacency->nbr_mac.mac[4], 
            adjacency->nbr_mac.mac[5]);
        
    PRINT_TABS(tab_spaces);
    cprintf("State : %s   HT : %u sec   Cost : %u\n",
        isis_adj_state_str(adjacency->adj_state),
        adjacency->hold_time,
        adjacency->cost);

    PRINT_TABS(tab_spaces);

    if (adjacency->expiry_timer) {
        cprintf("Expiry Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->expiry_timer));
    }
    else {
        cprintf("Expiry Timer : Nil\n");
    }

    PRINT_TABS(tab_spaces);

    if (adjacency->delete_timer) {
        cprintf("Delete Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->delete_timer));
    }
    else {
        cprintf("Delete Timer : Nil\n");
    }

    if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {

        PRINT_TABS(tab_spaces);
        cprintf("Up Time : %s\n", hrs_min_sec_format(
                (unsigned int)difftime(time(NULL), adjacency->uptime), 
                time_str, HRS_MIN_SEC_FMT_TIME_LEN));
    }
}

void
isis_change_adjacency_state(
            isis_adjacency_t *adjacency,
            isis_adj_state_t new_adj_state) {

    char adj_name[128];
    isis_intf_info_t *intf_info;
    node_t *node = adjacency->intf->att_node;
    isis_adj_state_t old_adj_state = adjacency->adj_state;

    intf_info = ISIS_INTF_INFO(adjacency->intf);
    
    if (old_adj_state != new_adj_state) {
        trace (ISIS_TR(adjacency->intf->att_node), TR_ISIS_ADJ,
            "%s : Adj %s state moving from %s to %s\n",
            ISIS_ADJ_MGMT,
            isis_adjacency_name(adj_name, adjacency),
            isis_adj_state_str(old_adj_state),
            isis_adj_state_str(new_adj_state));
    }

    switch(old_adj_state){ 

        case ISIS_ADJ_STATE_DOWN:

            switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    break;
                case ISIS_ADJ_STATE_INIT:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_delete_timer(adjacency);
                    isis_adjacency_start_expiry_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_UP:
                    assert(0);
                    break;
                default : ;
            }   
            break;

        case ISIS_ADJ_STATE_INIT:

        switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_INIT:
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    break;
                case ISIS_ADJ_STATE_UP:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    isis_adjacency_set_uptime(adjacency);
                    ISIS_INCREMENT_NODE_STATS(node,
                                isis_event_count[isis_event_adj_state_changed]);

                    ISIS_INCREMENT_NODE_STATS(node, adjacency_up_count);

                    if (intf_info->intf_grp) {
                        isis_intf_grp_refresh_member_interface (intf_info->intf);
                    }

                    isis_update_layer2_mapping_on_adjacency_up(adjacency);
                     (isis_adjacency_is_lan (adjacency)) ? 
                        isis_update_dis_on_adjacency_transition(adjacency) :
                        isis_adjacency_advertise_is_reach(adjacency);
                    break;
                default : ;
            }   

        case ISIS_ADJ_STATE_UP:

        switch(new_adj_state){
                case ISIS_ADJ_STATE_DOWN:
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    ISIS_INCREMENT_NODE_STATS(node,
                                isis_event_count[isis_event_adj_state_changed]);
                    ISIS_DECREMENT_NODE_STATS(node, adjacency_up_count);
                   
                    if (intf_info->intf_grp) {
                        isis_intf_grp_refresh_member_interface (intf_info->intf);
                    }
                    
                    isis_update_layer2_mapping_on_adjacency_down(adjacency);
                    (isis_adjacency_is_lan(adjacency)) ? 
                        isis_update_dis_on_adjacency_transition(adjacency) : isis_adjacency_withdraw_is_reach(adjacency);
                    break;
                case ISIS_ADJ_STATE_INIT:
                    assert(0);
                    break;
                case ISIS_ADJ_STATE_UP:
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    break;
                default : ;
            }   

            break;
        default : ;
    }
}

isis_adj_state_t 
isis_get_next_adj_state_on_receiving_next_hello(
    isis_adjacency_t *adjacency) {

    switch(adjacency->adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return ISIS_ADJ_STATE_INIT;
        case ISIS_ADJ_STATE_INIT:
            return ISIS_ADJ_STATE_UP;
        case ISIS_ADJ_STATE_UP:
            return ISIS_ADJ_STATE_UP;
        default : ; 
    }
    return ISIS_ADJ_STATE_UNKNOWN;
}

bool
isis_any_adjacency_up_on_interface(Interface *intf) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

        adjacency = glthread_to_isis_adjacency(curr);

        if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {
            return true;
        }

    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    return false;
}

/*  Playing TLV Encoding and Decoding Games  */

#if 0
+-----------------------+--------Parent TLV Begin--
|       Type = 22       |1B
+-----------------------+
|       Total Length    |1B ----------------------------------^
+-----------------------+                                     |
|    Nbr Lo Addr (int)  |4B                                   |
+-----------------------+                                     |
|      Metric/Cost      |4B                                   |
+-----------------------+                                     |
|   Total SubTLV Length |1B ----------------------------------+-------+
+-----------------------+---------SubTLVs Begin---            |       |
|      SubTLV type1     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type1 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type1 Value  |<SubTLV type1 len>                   |       |
+-----------------------+                                     |       |
|      SubTLV type2     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type2 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type2 Value  |<SubTLV type2 len>                   |       |
+-----------------------+                                     |       |
|      SubTLV type3     |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type3 len    |1B                                   |       |
+-----------------------+                                     |       |
|   SubTLV type3 Value  |< SubTLV type3 len>                  |       |
+-----------------------+--------SubTLVs Ends-----------------v-------v
+-----------------------+--------Parent TLV Ends---                    

SUBTLVs :
SubTLV 4 : Length 8B : Value = <4B local if index><4B Remote if index>
SubTLV 6 : Length 4B : Value = Local Ip Address (4B)
SubTLV 8 : Length 4B : Value = Nbr IP Address (4B)

#endif

uint8_t 
isis_nbr_tlv_encode_size(isis_adjacency_t *adjacency,
                         uint8_t *subtlv_len) {

    uint32_t ptlv_data_len = 0;  /* parent tlv data len */
    uint32_t total_subtlv_len = 0;

    *subtlv_len = 0;

    if (adjacency->adj_state != ISIS_ADJ_STATE_UP) return 0;

    ptlv_data_len += TLV_OVERHEAD_SIZE;
    ptlv_data_len += 4;         /* loopback address */
    ptlv_data_len += 4;         /* Cost/Metric */
    ptlv_data_len += 1;         /* total Sub TLV len */

     /* encode subtlv 4 */
    total_subtlv_len += TLV_OVERHEAD_SIZE + 4 + 4;

    /* encode subtlv 6 */
    total_subtlv_len += TLV_OVERHEAD_SIZE + 4;

    /* encode subtlv 8 */
    total_subtlv_len += TLV_OVERHEAD_SIZE + 4;

    ptlv_data_len += total_subtlv_len;

    if (ptlv_data_len > 0xFF) {
        cprintf("Error : TLV size exceeded\n");
        return 0;
    }
    *subtlv_len = total_subtlv_len;
    
    return ptlv_data_len;
}

byte *
isis_encode_nbr_tlv(isis_adjacency_t *adjacency,
                    byte *buff,           /* Output buffer to encode tlv in */
                    uint16_t *tlv_len) {  /* output : length encoded (tlv overhead + data len)*/

    uint8_t subtlv_len;
    uint32_t four_byte_data;
    uint32_t if_indexes[2];

    byte *start_buff = buff;

    *tlv_len = isis_nbr_tlv_encode_size(adjacency, &subtlv_len);

    /* Now encode the data into buff */

    *start_buff = ISIS_IS_REACH_TLV;
    start_buff += 1;

    *start_buff = *tlv_len - TLV_OVERHEAD_SIZE;
    start_buff += 1;

    /* loopback Address */
    memcpy(start_buff, (byte *)&adjacency->nbr_rtr_id, sizeof(adjacency->nbr_rtr_id));
    start_buff += sizeof(adjacency->nbr_rtr_id);
    
    /* Metric / Cost */
    four_byte_data = ISIS_INTF_COST(adjacency->intf);
    memcpy(start_buff, (byte *)&four_byte_data, sizeof(uint32_t));
    start_buff += sizeof(uint32_t);

    /* Total Sub TLV len */
    memcpy(start_buff, (byte *)&subtlv_len, sizeof(uint32_t));
    start_buff += sizeof(uint8_t);

    /* 
       Now We are at the start of Ist SubTLV,
       encode local and remote if index
       Encoding SubTLV 4
    */

    if_indexes[0] = adjacency->intf->ifindex;
    if_indexes[1] = adjacency->remote_if_index;

    start_buff = tlv_buffer_insert_tlv(start_buff,
                        ISIS_TLV_IF_INDEX, 8,
                        (byte *)if_indexes);

    /* Encode local ip Address 
       Encoding SubTLV 6 */
    four_byte_data = IF_IP(adjacency->intf);

    start_buff = tlv_buffer_insert_tlv(start_buff,
                        ISIS_TLV_LOCAL_IP, 4,
                        (byte *)&four_byte_data);

    /* Encode remote ip Address 
       Encoding SubTLV 8 */
    start_buff = tlv_buffer_insert_tlv(start_buff,
                        ISIS_TLV_REMOTE_IP, 4,
                        (byte *)&adjacency->nbr_intf_ip);

    return start_buff;
}

byte *
isis_encode_all_nbr_tlvs(node_t *node, byte *buff) {

    glthread_t *curr;
    Interface *intf;
    uint16_t bytes_encoded;
    isis_adjacency_t *adjacency;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return buff;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            buff = isis_encode_nbr_tlv(adjacency, buff, &bytes_encoded);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

   } ITERATE_NODE_INTERFACES_END(node, intf);

    return buff;
}

uint16_t
isis_size_to_encode_all_nbr_tlv(node_t *node) {

    glthread_t *curr;
    Interface *intf;
    uint16_t bytes_needed;
    uint8_t subtlv_bytes_needed;
    isis_adjacency_t *adjacency;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    bytes_needed = 0;
    subtlv_bytes_needed = 0;

    if (!isis_is_protocol_enable_on_node(node)) return 0;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            bytes_needed += isis_nbr_tlv_encode_size(adjacency, &subtlv_bytes_needed);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

   } ITERATE_NODE_INTERFACES_END(node, intf);

    return bytes_needed;
}

uint32_t 
isis_show_all_adjacencies (node_t *node) {

     uint32_t rc = 0;
     glthread_t *curr;
     Interface *intf;
     isis_intf_info_t *intf_info;
     isis_adjacency_t *adjacency;
     byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];

     byte *buff = node->print_buff;

    ITERATE_NODE_INTERFACES_BEGIN (node, intf) {

        if ( !isis_node_intf_is_enable(intf)) continue;
        
        intf_info = ISIS_INTF_INFO(intf);
        
        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

            adjacency = glthread_to_isis_adjacency(curr);

            if (!adjacency) continue;

            rc += cprintf("%-16s   %-16s   %-6s   %-4s %s\n", 
            intf->if_name.c_str(), adjacency->nbr_name,
            isis_adj_state_str(adjacency->adj_state),
             (intf_info->intf_type == isis_intf_type_p2p) ? "p2p" : "lan",
            hrs_min_sec_format(
                (unsigned int)difftime(time(NULL), adjacency->uptime),
                time_str, HRS_MIN_SEC_FMT_TIME_LEN));

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    } ITERATE_NODE_INTERFACES_END (node, intf);
    return rc;
 }

/* Whenever the Adjacency state transitions  between DOWN and UP on a LAN,
    DIS relection should happen. We repositon the adjacency in interface adj list which is
    sorted list of Adjacencies based on priority order. This is DIS-election only. DIS re-election
    may result in DIS either changed or not. If DIS is not changed, then no action need to be performed.
    But if DIS is changed, we need to forgot the current DIS (which in turn result in withdrawing the required
    advertisements) and learn a new DIS (which in-turn result in starting required advertisements ).
    Return true if DIS is changed */
bool
isis_update_dis_on_adjacency_transition (isis_adjacency_t *adjacency) {
    
    Interface *intf;
    isis_lan_id_t old_dis_id,
                          new_dis_id;
    isis_intf_info_t *intf_info;

    assert (adjacency->adj_state == ISIS_ADJ_STATE_UP ||
            adjacency->adj_state == ISIS_ADJ_STATE_DOWN);

    intf = adjacency->intf;
    remove_glthread(&adjacency->glue);
    glthread_priority_insert(ISIS_INTF_ADJ_LST_HEAD(intf),
                                            &adjacency->glue,
                                            isis_adjacency_comp_fn,
                                            (int)&((isis_adjacency_t *)0)->glue);

    if (isis_adjacency_is_p2p(adjacency)) return false;

    intf_info = ISIS_INTF_INFO(intf);
    old_dis_id = intf_info->elected_dis;
    new_dis_id =  isis_intf_reelect_dis(intf);
    
    if (isis_lan_id_compare (&old_dis_id, &new_dis_id) == CMP_PREF_EQUAL) {
        
        /* DIS has not changed, Now i have to take action depending on whether I am DIS
            Or not*/
            if (isis_am_i_dis (adjacency->intf)) {
                    (adjacency->adj_state == ISIS_ADJ_STATE_DOWN ) ?
                    /* with Draw PN --> NBR ISIS IS REACH advertisement*/
                    isis_adjacency_withdraw_is_reach (adjacency) :
                    /* Advertise PN --> NBR ISIS IS REACH Advertisement*/ 
                    isis_adjacency_advertise_is_reach (adjacency);
            }
            else {
                    /* No Action to be done by me. Non-DIS do not update any IS REACH
                    advertisement for a LAN interface*/
            }
            return true;
    }

    isis_intf_resign_dis (intf);
    isis_intf_assign_new_dis (intf,  new_dis_id);
    return true;
}

/* This fn advertise LAN adjacency by a ISIS rtr. On a LAN, when we learn
    Nbr, we need to advertise this nbr as link ( is-reach ) info in our advertisements.
    For a Nbr on a LAN, this responsibility is performed only by elected DIS node
    If I am DIS, and i have a Nbr N:
        advertise adjacency to Nbr N as : PN --> Nbr ( i.e. advertise on behalf of PN)
    */
static isis_advt_tlv_return_code_t
 isis_adjacency_advertise_lan (isis_adjacency_t *adjacency) {

    isis_intf_info_t *intf_info;
    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;

    assert(isis_adjacency_is_lan (adjacency));

    intf_info = ISIS_INTF_INFO(adjacency->intf);

    /* If I am not a DIS, I have nothing to advertise for this adjacency*/
    if (!isis_am_i_dis(adjacency->intf)) 
        return ISIS_TLV_RECORD_ADVT_SUCCESS ;

    /* If I am DIS, it is my responsibility to advertise adjacency on behalf of PN*/
    if (adjacency->u.lan_pn_to_nbr_adv_data) {

        if (adjacency->u.lan_pn_to_nbr_adv_data->fragment) {
            return ISIS_TLV_RECORD_ADVT_ALREADY;
        }

        return isis_advertise_tlv(
            adjacency->intf->att_node,
            intf_info->elected_dis.pn_id,
            adjacency->u.lan_pn_to_nbr_adv_data,
            &advt_info);
    }

    adjacency->u.lan_pn_to_nbr_adv_data =
        (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);

    advt_data = adjacency->u.lan_pn_to_nbr_adv_data;
    advt_data->src.holder = &adjacency->u.lan_pn_to_nbr_adv_data;

    advt_data->tlv_no = ISIS_IS_REACH_TLV;
    advt_data->u.adj_data.nbr_sys_id = adjacency->nbr_sys_id;
    advt_data->u.adj_data.metric = adjacency->cost;
    advt_data->u.adj_data.local_ifindex = 0;
    advt_data->u.adj_data.remote_ifindex = adjacency->remote_if_index;
    advt_data->u.adj_data.local_intf_ip = 0;
    advt_data->u.adj_data.remote_intf_ip = adjacency->nbr_intf_ip;
    init_glthread(&advt_data->glue);
    advt_data->fragment = NULL;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);
    return isis_advertise_tlv(
            adjacency->intf->att_node,
            intf_info->elected_dis.pn_id,
            advt_data,
            &advt_info);
 }

/* This fn advertise P2P adjacency by a ISIS rtr. On a P2P, when we learn
    Nbr, we need to advertise this nbr as link ( is-reach ) info in our advertisements.
    For a Nbr on a P2P interface.
        advertise adjacency to Nbr N as : SELF --> Nbr.
*/
static isis_advt_tlv_return_code_t
isis_adjacency_advertise_p2p (isis_adjacency_t *adjacency) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;

    assert(isis_adjacency_is_p2p (adjacency));

    advt_data = adjacency->u.p2p_adv_data;

    if (advt_data) {
            if (advt_data->fragment) {
                    return ISIS_TLV_RECORD_ADVT_ALREADY;
            }
            else {
                return isis_advertise_tlv (
                                adjacency->intf->att_node,
                                0,
                                advt_data,
                                &advt_info);
            }
        }

        advt_data = (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t) ;

        advt_data->tlv_no = ISIS_IS_REACH_TLV;
        advt_data->u.adj_data.nbr_sys_id = adjacency->nbr_sys_id;
        advt_data->u.adj_data.metric = adjacency->cost;
        advt_data->u.adj_data.local_ifindex = adjacency->intf->ifindex;
        advt_data->u.adj_data.remote_ifindex = adjacency->remote_if_index;
        advt_data->u.adj_data.local_intf_ip =  IF_IP(adjacency->intf);
        advt_data->u.adj_data.remote_intf_ip = adjacency->nbr_intf_ip;
        init_glthread(&advt_data->glue);
        adjacency->u.p2p_adv_data = advt_data;
        advt_data->src.holder = &adjacency->u.p2p_adv_data;
        advt_data->fragment = NULL;
        advt_data->tlv_size = isis_get_adv_data_size(advt_data);
        return isis_advertise_tlv (
                                adjacency->intf->att_node,
                                0,
                                advt_data,
                                &advt_info);
}

/* This is Top level API to looks after Adjacency/Nbr advertisement when
    Adjacency goes UP*/
isis_advt_tlv_return_code_t
isis_adjacency_advertise_is_reach (isis_adjacency_t *adjacency) {

    isis_advt_tlv_return_code_t rc;

    if (adjacency->adj_state != ISIS_ADJ_STATE_UP) return;

    if (isis_adjacency_is_p2p (adjacency)) {
        rc = isis_adjacency_advertise_p2p (adjacency);
    }
    else {
        rc = isis_adjacency_advertise_lan (adjacency);
    }

    switch (rc) {
        case ISIS_TLV_RECORD_ADVT_SUCCESS:
        case ISIS_TLV_RECORD_ADVT_ALREADY:
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        default: ;
    }
    return rc;
}

/* This fn is to withdraw P2P Nbr advertisement when Adjacency is deleted Or goes DOWN.
    Note whenever the TLV is removed or added, we trigger sequence of operations as follows :
        TLV Removed from fragment's TLV list --> Fragment's LSP Pkt regenerated --> 
        Fragment's LSP Pkt flooded
        This fn does exactly opposite of  isis_adjacency_advertise_p2p( ).
    */
static isis_tlv_wd_return_code_t
isis_adjacency_withdraw_p2p_is_reach (isis_adjacency_t *adjacency) {

    isis_adv_data_t *adv_data;
    isis_tlv_wd_return_code_t rc;

    assert (isis_adjacency_is_p2p (adjacency));

    if (!adjacency->u.p2p_adv_data) return ISIS_TLV_WD_TLV_NOT_FOUND;

    adv_data = adjacency->u.p2p_adv_data;

    isis_advt_data_clear_backlinkage(
            ISIS_NODE_INFO(adjacency->intf->att_node), adv_data);
    assert (!adjacency->u.p2p_adv_data);

    if (!adv_data->fragment) {
        isis_wait_list_advt_data_remove(adjacency->intf->att_node, adv_data);
        isis_free_advt_data(adv_data);
        return ISIS_TLV_WD_FRAG_NOT_FOUND;
    }

    rc = isis_withdraw_tlv_advertisement (adjacency->intf->att_node, adv_data);
    isis_free_advt_data(adv_data);
    return rc;
}

/* This fn is to withdraw LAN Nbr advertisement when Adjacency is deleted Or goes DOWN.
    Note whenever the TLV is removed or added, we trigger sequence of operations as follows :
        TLV Removed from fragment's TLV list --> Fragment's LSP Pkt regenerated --> 
        Fragment's LSP Pkt flooded
        This fn does exactly opposite of  isis_adjacency_advertise_lan( ).
        When the Nbr is unlearnt ( adjacency delete or goes down), If I am not DIS, no action.
        If am DIS, then withdraw PN --> NBR advertisements.
*/
static isis_tlv_wd_return_code_t
isis_adjacency_withdraw_lan_is_reach (isis_adjacency_t *adjacency) {
    
    isis_adv_data_t *adv_data;
     isis_tlv_wd_return_code_t rc;

     assert (isis_adjacency_is_lan (adjacency));

    /* Nothing to withdraw if nbr goes down as i am not DIS*/
    if (!isis_am_i_dis (adjacency->intf)) return ISIS_TLV_WD_TLV_NOT_FOUND;

    /* Not Advertising already, ok !*/
    if (adjacency->u.lan_pn_to_nbr_adv_data == NULL) return ISIS_TLV_WD_TLV_NOT_FOUND;

    adv_data = adjacency->u.lan_pn_to_nbr_adv_data;

    isis_advt_data_clear_backlinkage(
            ISIS_NODE_INFO(adjacency->intf->att_node), adv_data);
    assert( !adjacency->u.lan_pn_to_nbr_adv_data);

    if (!adv_data->fragment) {
        isis_wait_list_advt_data_remove (adjacency->intf->att_node, adv_data);
        isis_free_advt_data(adv_data);
        return ISIS_TLV_WD_FRAG_NOT_FOUND;
    }

    /* Withdraw PN-->NBR advertisement for this Adjacency*/
    rc = isis_withdraw_tlv_advertisement(adjacency->intf->att_node, adv_data);
    isis_free_advt_data(adv_data);
    return rc;
}

/* This is Top level API to looks after Adjacency/Nbr advertisement when
    Adjacency goes DOWN or deleted*/

isis_tlv_wd_return_code_t
isis_adjacency_withdraw_is_reach (isis_adjacency_t *adjacency) {

    isis_tlv_wd_return_code_t rc;

    if (isis_adjacency_is_p2p (adjacency)) {
        rc = isis_adjacency_withdraw_p2p_is_reach (adjacency);
    }
    else {
        rc = isis_adjacency_withdraw_lan_is_reach (adjacency);
    }

    switch (rc) {
        case ISIS_TLV_WD_SUCCESS:
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
        case ISIS_TLV_WD_TLV_NOT_FOUND:
        case ISIS_TLV_WD_FAILED:
        default: ;
    }
    return rc;
}
 
