#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_struct.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_pn.h"

pn_id_t
isis_reserve_new_pn_id (node_t *node, bool *found) {

    pn_id_t pn_id;
    *found = false;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    for (pn_id = 0; pn_id < ISIS_MAX_PN_SUPPORTED; pn_id++) {

        if (node_info->advt_db[pn_id] ) continue;
        *found = true;
        return pn_id;
    }
    
    return 0;
}

void
isis_intf_allocate_lan_id (Interface *intf) {

    bool rc;
    pn_id_t pn_id;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    
    if (!intf_info) return;

    assert(intf_info->intf_type == isis_intf_type_lan);
    assert (intf_info->lan_id.pn_id == 0);

    pn_id = isis_reserve_new_pn_id (intf->att_node, &rc);
    assert(rc);

    isis_create_advt_db (ISIS_NODE_INFO (intf->att_node) , pn_id);
    intf_info->lan_id = {NODE_LO_ADDR_INT(intf->att_node), pn_id};
}

void
isis_intf_deallocate_lan_id (Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    
    if (!intf_info) return;

    assert(intf_info->intf_type == isis_intf_type_lan);
    assert (intf_info->lan_id.pn_id); 

    isis_destroy_advt_db (ISIS_NODE_INFO(intf->att_node), 
                                            intf_info->lan_id.pn_id); 
    intf_info->lan_id = {0, 0};
}

/* DIS Mgmt Functions */

/* Deletet the Current DIS*/
void 
isis_intf_resign_dis (Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);

    if (!intf_info) return;

    /* Delete the DIS data ...*/
    intf_info->elected_dis = {0, 0};
}

/* Trigger DIS Re-election, return rtr id of the DIS*/
isis_lan_id_t
isis_intf_reelect_dis (Interface *intf) {

    uint32_t rtr_id;
    glthread_t *curr;
    isis_adjacency_t *adj;
    isis_lan_id_t self_lan_id;     
    isis_lan_id_t null_lan_id;   

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);

    null_lan_id = {0, 0};
    self_lan_id = intf_info->lan_id;

    if (!intf_info) return null_lan_id; 

    if (intf_info->intf_type == isis_intf_type_p2p) return null_lan_id;

    if (IS_GLTHREAD_LIST_EMPTY(ISIS_INTF_ADJ_LST_HEAD(intf))) {
        return self_lan_id;
    }

    curr = glthread_get_next (ISIS_INTF_ADJ_LST_HEAD(intf));
    adj = glthread_to_isis_adjacency(curr);

    if (adj->adj_state != ISIS_ADJ_STATE_UP) return self_lan_id;

    if (intf_info->priority > adj->priority) return self_lan_id;
    if (intf_info->priority < adj->priority) return adj->lan_id;

    rtr_id = NODE_LO_ADDR_INT(intf->att_node);
    if (rtr_id > adj->nbr_rtr_id) return self_lan_id;
    if (rtr_id < adj->nbr_rtr_id) return adj->lan_id;
    
    return null_lan_id;
}

void
isis_intf_assign_new_dis (Interface *intf, isis_lan_id_t new_dis_id) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    
    if (!intf_info) return;

    assert(intf_info->elected_dis.rtr_id == 0 &&
                intf_info->elected_dis.pn_id == 0);

    intf_info->elected_dis = new_dis_id;
    ISIS_INCREMENT_NODE_STATS(intf->att_node,
        isis_event_count[isis_event_dis_changed]);
    // .. .
}