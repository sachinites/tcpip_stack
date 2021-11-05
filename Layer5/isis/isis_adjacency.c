#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_pkt.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_intf_group.h"
#include "isis_layer2map.h"

static void
isis_init_adjacency(isis_adjacency_t *adjacency) {

    memset(adjacency, 0, sizeof(isis_adjacency_t));
    adjacency->last_transition_time = time(NULL); /* Current system time */
    adjacency->adj_state = ISIS_ADJ_STATE_DOWN;
    init_glthread(&adjacency->glue);
}

/* Timer fns for ISIS Adjacency Mgmt */
static void
isis_timer_expire_delete_adjacency_cb(void *arg, uint32_t arg_size){

    if (!arg) return;
    isis_delete_adjacency((isis_adjacency_t *)arg);
}

static void
isis_timer_expire_down_adjacency_cb(void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;

    sprintf(tlb, "%s : Adjacency %s Up timer Expired\n",
        ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);

    isis_change_adjacency_state((isis_adjacency_t *)arg, ISIS_ADJ_STATE_DOWN);
}

static void
isis_adjacency_start_expiry_timer(
        isis_adjacency_t *adjacency) {

    if(adjacency->expiry_timer){
        return;
    }

    adjacency->expiry_timer = timer_register_app_event(
                                    node_get_timer_instance(adjacency->intf->att_node),
                                    isis_timer_expire_down_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    adjacency->hold_time * 1000,
                                    0);

    if(!adjacency->expiry_timer){
        
        sprintf(tlb, "%s : Adjacency %s Expiry timer failed to start\n",
            ISIS_ERROR, isis_adjacency_name(adjacency));
        tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
        return;
    }

    sprintf(tlb, "%s : Adjacency %s Expiry timer started\n",
        ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
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

    timer_de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
    sprintf(tlb, "%s : Adjacency %s Expiry timer stopped\n",
        ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
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

    adjacency->delete_timer = timer_register_app_event(
                                    node_get_timer_instance(adjacency->intf->att_node),
                                    isis_timer_expire_delete_adjacency_cb,
                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                    ISIS_ADJ_DEFAULT_DELETE_TIME,
                                    0);
    
    sprintf(tlb, "%s : Adjacency %s Delete timer started\n",
            ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);

    if(!adjacency->delete_timer){
        sprintf(tlb, "%s : Adjacency %s Delete timer could not be started\n",
            ISIS_ERROR, isis_adjacency_name(adjacency));
        tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
    }
}

static void
isis_adjacency_stop_delete_timer(
        isis_adjacency_t *adjacency) {

    if(!adjacency->delete_timer){
        return;
    }

    timer_de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;

    sprintf(tlb, "%s : Adjacency %s Delete timer stopped\n",
            ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
}

/* Timer fns for ISIS Adjacency Mgmt End */


void
isis_delete_adjacency(isis_adjacency_t *adjacency) {

    remove_glthread(&adjacency->glue);
    isis_adjacency_stop_expiry_timer(adjacency);
    isis_adjacency_stop_delete_timer(adjacency);
    sprintf(tlb, "%s : Adjacency %s Deleted\n",
            ISIS_ADJ_MGMT, isis_adjacency_name(adjacency));
    tcp_trace(adjacency->intf->att_node, adjacency->intf, tlb);
    if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {
        ISIS_DECREMENT_NODE_STATS(adjacency->intf->att_node, adjacency_up_count);
        isis_update_layer2_mapping_on_adjacency_down(adjacency);
        isis_schedule_lsp_pkt_generation(adjacency->intf->att_node, isis_event_up_adj_deleted);
    }
    isis_dynamic_intf_grp_update_on_adjacency_delete(adjacency);
   XFREE(adjacency);
}

int
isis_delete_all_adjacencies(interface_t *intf) {

    int rc = 0;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    sprintf(tlb, "%s : Deleting all Adjacencies\n", ISIS_ADJ_MGMT);
    tcp_trace(intf->att_node, intf, tlb);

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        isis_delete_adjacency(adjacency);
        rc++;
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);
    return rc;
}

void
isis_update_interface_adjacency_from_hello(
        interface_t *iif,
        byte *hello_tlv_buffer,
        size_t tlv_buff_size) {

    char * router_id_str;
    uint8_t tlv_data_len;
    bool new_adj = false;
    bool regen_lsp = false;
    char *intf_ip_addr_str;
    uint32_t *router_id_int;
    uint32_t four_byte_data;
    uint32_t intf_ip_addr_int;
    isis_intf_info_t *intf_info;
    isis_adjacency_t *adjacency = NULL;
    isis_adjacency_t adjacency_backup;
    bool force_bring_down_adjacency = false;

    router_id_int = (uint32_t *)tlv_buffer_get_particular_tlv(
                    hello_tlv_buffer, 
                    tlv_buff_size,
                    ISIS_TLV_RTR_ID, 
                    &tlv_data_len);

    adjacency = isis_find_adjacency_on_interface(iif, *router_id_int);

    if(!adjacency){
        adjacency = (isis_adjacency_t *)XCALLOC(0, 1, isis_adjacency_t);
        isis_init_adjacency(adjacency);
        adjacency->intf = iif;
        glthread_add_next(ISIS_INTF_ADJ_LST_HEAD(iif), &adjacency->glue);
        new_adj = true;
        router_id_str = tcp_ip_covert_ip_n_to_p(*router_id_int, 0);
        sprintf(tlb, "%s : New Adjacency for nbr %s on intf %s Created\n",
            ISIS_ADJ_MGMT, router_id_str, iif->if_name);
        tcp_trace(iif->att_node, iif, tlb);
    }
    else {
        memcpy(&adjacency_backup, adjacency, sizeof(isis_adjacency_t));
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
       sprintf(tlb, "%s : ISIS Adjacency attributes changed, regen LSP \n",  ISIS_ADJ_MGMT);
        tcp_trace(iif->att_node, iif, tlb);
        isis_schedule_lsp_pkt_generation(iif->att_node, isis_event_nbr_attribute_changed);
   }
    ISIS_INTF_INCREMENT_STATS(iif, good_hello_pkt_recvd);
}

char *
isis_adjacency_name(isis_adjacency_t *adjacency) {

    static char adj_name[64];

    sprintf(adj_name, adjacency->intf->if_name, "::", adjacency->nbr_name);
    return adj_name;
}

isis_adjacency_t *
isis_find_adjacency_on_interface(
        interface_t *intf,
        uint32_t nbr_rtr_id) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;
    isis_intf_info_t *intf_info;

    intf_info = ISIS_INTF_INFO(intf);

    if(!intf_info) return NULL;

    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

        adjacency = glthread_to_isis_adjacency(curr);
        if (!nbr_rtr_id) return adjacency;
        if (adjacency->nbr_rtr_id == nbr_rtr_id) {
            return adjacency;
        }
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    return NULL;
}

void
isis_show_adjacency( isis_adjacency_t *adjacency,
                                    uint8_t tab_spaces) {

    char *ip_addr_str;

    PRINT_TABS(tab_spaces);
    ip_addr_str = tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id, 0);
    printf("Nbr : %s(%s)\n", adjacency->nbr_name, ip_addr_str);

    PRINT_TABS(tab_spaces);
    ip_addr_str = tcp_ip_covert_ip_n_to_p( adjacency->nbr_intf_ip, 0);
    printf("Nbr intf ip : %s  ifindex : %u\n",
        ip_addr_str,
        adjacency->remote_if_index);

    PRINT_TABS(tab_spaces);
    printf("Nbr Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            adjacency->nbr_mac.mac[0], 
            adjacency->nbr_mac.mac[1], 
            adjacency->nbr_mac.mac[2], 
            adjacency->nbr_mac.mac[3], 
            adjacency->nbr_mac.mac[4], 
            adjacency->nbr_mac.mac[5]);
        
    PRINT_TABS(tab_spaces);
    printf("State : %s   HT : %u sec   Cost : %u\n",
        isis_adj_state_str(adjacency->adj_state),
        adjacency->hold_time,
        adjacency->cost);

    PRINT_TABS(tab_spaces);

    if (adjacency->expiry_timer) {
        printf("Expiry Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->expiry_timer));
    }
    else {
        printf("Expiry Timer : Nil\n");
    }

    PRINT_TABS(tab_spaces);

    if (adjacency->delete_timer) {
        printf("Delete Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->delete_timer));
    }
    else {
        printf("Delete Timer : Nil\n");
    }

    if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {

        PRINT_TABS(tab_spaces);
        printf("Up Time : %s\n", hrs_min_sec_format(
                (unsigned int)difftime(time(NULL), adjacency->uptime)));
    }
}

void
isis_change_adjacency_state(
            isis_adjacency_t *adjacency,
            isis_adj_state_t new_adj_state) {

    isis_intf_info_t *intf_info;
    node_t *node = adjacency->intf->att_node;
    isis_adj_state_t old_adj_state = adjacency->adj_state;

    intf_info = ISIS_INTF_INFO(adjacency->intf);
    
    if (old_adj_state != new_adj_state) {
        sprintf(tlb, "%s : Adj %s state moving from %s to %s\n",
            ISIS_ADJ_MGMT, isis_adjacency_name(adjacency),
            isis_adj_state_str(old_adj_state),
            isis_adj_state_str(new_adj_state));
        tcp_trace(node, adjacency->intf, tlb);
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

                    if (ISIS_NODE_INFO(node)->adjacency_up_count == 1) {
                        isis_enter_reconciliation_phase(node);
                    }
                    else if (isis_is_reconciliation_in_progress(node)){
                        isis_restart_reconciliation_timer(node);
                    }
                    else {
                        isis_schedule_lsp_pkt_generation(node, isis_event_adj_state_changed);
                    }

                    isis_update_layer2_mapping_on_adjacency_up(adjacency);
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

                    if (isis_is_reconciliation_in_progress(node) &&
                        ISIS_NODE_INFO(node)->adjacency_up_count){

                        isis_restart_reconciliation_timer(node);
                    }
                    else {
                        isis_schedule_lsp_pkt_generation(node, isis_event_adj_state_changed);
                    }
                    isis_update_layer2_mapping_on_adjacency_down(adjacency);
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
}

bool
isis_any_adjacency_up_on_interface(interface_t *intf) {

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
        printf("Error : TLV size exceeded\n");
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

    if_indexes[0] = IF_INDEX(adjacency->intf);
    if_indexes[1] = adjacency->remote_if_index;

    start_buff = tlv_buffer_insert_tlv(start_buff,
                        ISIS_TLV_IF_INDEX, 8,
                        (byte *)if_indexes);

    /* Encode local ip Address 
       Encoding SubTLV 6 */
    four_byte_data = tcp_ip_covert_ip_p_to_n(IF_IP(adjacency->intf));

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
    interface_t *intf;
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
    interface_t *intf;
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

 /* Return the no of bytes written into out_buff */
uint16_t
isis_print_formatted_nbr_tlv22(byte *out_buff, 
                             byte *nbr_tlv_buffer,
                             uint8_t tlv_buffer_len) {

    uint16_t rc = 0;
    uint8_t subtlv_len;
    byte *subtlv_navigator;
    unsigned char *ip_addr;
    uint32_t ip_addr_int, metric;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len) {

        rc += sprintf(out_buff + rc,
                      "\tTLV%d  Len : %d\n", tlv_type, tlv_len);

        ip_addr_int = *(uint32_t *)tlv_value;
        metric = *(uint32_t *)(((uint32_t *)tlv_value) + 1);
        subtlv_len = *(uint8_t *)((uint32_t *)tlv_value + 2);

        rc += sprintf(out_buff + rc, "\t\tNbr Rtr ID : %s   Metric : %u   SubTLV Len : %d\n",
                      tcp_ip_covert_ip_n_to_p(ip_addr_int, 0),
                      metric, subtlv_len);

        subtlv_navigator = tlv_value + 
                            sizeof(uint32_t) +  // 4B IP Addr
                            sizeof(uint32_t) +  // 4B metric
                            sizeof(uint8_t);    // 1B subtlv len

        /* Now Read the Sub TLVs */
        byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

        ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len) {

            switch(tlv_type2) {
                case ISIS_TLV_IF_INDEX:

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                  tlv_type2, tlv_len2,
                                  *(uint32_t *)tlv_value2,
                                  *(uint32_t *)((uint32_t *)tlv_value2 + 1));

                    break;
                case ISIS_TLV_LOCAL_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   Local IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));

                    break;
                case ISIS_TLV_REMOTE_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   Remote IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));

                    break;
                default:
                    ;
            }

        } ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len);
 
    } ITERATE_TLV_END(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len);
    return rc;
}

uint32_t 
isis_show_all_adjacencies (node_t *node) {

     uint32_t rc = 0;
     glthread_t *curr;
     interface_t *intf;
     isis_adjacency_t *adjacency;

     byte *buff = node->print_buff;

    ITERATE_NODE_INTERFACES_BEGIN (node, intf) {

        if ( !isis_node_intf_is_enable(intf)) continue;
        
        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr){

            adjacency = glthread_to_isis_adjacency(curr);

            if (!adjacency) continue;

            rc += sprintf(buff + rc, "%-16s   %-16s   %-6s   %s\n", 
            intf->if_name, adjacency->nbr_name,
            isis_adj_state_str(adjacency->adj_state),
            hrs_min_sec_format(
                (unsigned int)difftime(time(NULL), adjacency->uptime)));

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    } ITERATE_NODE_INTERFACES_END (node, intf);
    return rc;
 }