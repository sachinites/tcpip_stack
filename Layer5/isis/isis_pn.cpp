#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_struct.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_pn.h"
#include "isis_utils.h"

extern advt_id_t isis_gen_avt_id () ;

pn_id_t
isis_reserve_new_pn_id (node_t *node, bool *found) {

    int i;
    *found = false;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {

        if (node_info->advt_db[i] ) continue;
        *found = true;
        return (pn_id_t)i;
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

    isis_destroy_advt_db (intf->att_node, 
                                            intf_info->lan_id.pn_id); 
    intf_info->lan_id = {0, 0};
}

/* DIS Mgmt Functions */

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

/* Deletet the Current DIS*/
void 
isis_intf_resign_dis (Interface *intf) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;
    isis_tlv_wd_return_code_t rc;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);

    if (!intf_info) return;

    /* Delete the DIS data ...
        I am resigning as a DIS, so withdraw all advertisements which I did
        with DIS privileges
    */
    /* Step 1 : 
        Since, we are resigning as DIS, Delete ISIS REACH advt info
        from from PN to self i.e  intf_info->lan_pn_to_self_adv_data;
    */
    if (intf_info->lan_pn_to_self_adv_data) {
        
        assert(isis_am_i_dis (intf));

        rc = isis_withdraw_tlv_advertisement(intf->att_node,
                                             intf_info->lan_pn_to_self_adv_data);
        intf_info->lan_pn_to_self_adv_data = NULL;
    }

    /* Step 2 : 
        Since, we are resigning as DIS, Delete all ISIS REACH advt info
        from from PN to all Nbrs i.e. on all ajacencies on this interface,
        delete advt info adjacency->lan_pn_to_adj_adv_data
        Also, Purge all the fragments generate by this PN
    */
    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        
        if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;

        /* Adjacency may not have advertised by now, skip ...*/
        if (adjacency->u.lan_pn_to_nbr_adv_data == NULL) continue;

        rc = isis_withdraw_tlv_advertisement(intf->att_node,
                                             adjacency->u.lan_pn_to_nbr_adv_data);
        adjacency->u.lan_pn_to_nbr_adv_data = NULL;

    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    /* Step 3 : Forget who the DIS is. Therefore, withdraw the intf_info->lan_self_to_pn_adv_data*/
    rc = isis_withdraw_tlv_advertisement(intf->att_node,
                                             intf_info->lan_self_to_pn_adv_data);
    intf_info->lan_self_to_pn_adv_data = NULL;

    intf_info->elected_dis = {0, 0};
}

void
isis_intf_assign_new_dis (Interface *intf, isis_lan_id_t new_dis_id) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;    
    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_tlv_record_advt_return_code_t rc;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    
    if (!intf_info) return;

    assert(intf_info->elected_dis.rtr_id == 0 &&
                intf_info->elected_dis.pn_id == 0);

    intf_info->elected_dis = new_dis_id;
    ISIS_INCREMENT_NODE_STATS(intf->att_node,
        isis_event_count[isis_event_dis_changed]);

    /* Prepare new Advertisements since i am elected as new DIS*/

    /* Step 1 : 
        Advertise intf_info->adv_data.lan_self_to_pn_adv_data
    */
    assert(!intf_info->lan_self_to_pn_adv_data);
    
    intf_info->lan_self_to_pn_adv_data = 
        (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t) ;
    
    advt_data = intf_info->lan_self_to_pn_adv_data;

    advt_data->advt_id = isis_gen_avt_id ();
    advt_data->tlv_no = ISIS_IS_REACH_TLV;
    advt_data->u.adj_data.nbr_sys_id.rtr_id = intf_info->elected_dis.rtr_id;
    advt_data->u.adj_data.nbr_sys_id.pn_id = intf_info->elected_dis.pn_id;
    advt_data->u.adj_data.metric = intf_info->cost;
    advt_data->u.adj_data.local_ifindex = intf->ifindex;
    advt_data->u.adj_data.remote_ifindex = 0;
    advt_data->u.adj_data.local_intf_ip =  IF_IP(intf);
    advt_data->u.adj_data.remote_intf_ip = 0;
    init_glthread(&advt_data->glue);
    advt_data->fragment = NULL;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    rc =  isis_record_tlv_advertisement (
                                intf->att_node,
                                0,
                                advt_data,
                                &intf_info->lan_self_to_pn_adv_data,
                                &advt_info);

    switch (rc) {
        case ISIS_TLV_RECORD_ADVT_SUCCESS:
        break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
        assert(0);
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        assert(0);
        default:
        assert(0);
    }

    /* Step 2 : 
        Advertise intf_info->pn_to_self_adv_data
    */
    assert(!intf_info->lan_pn_to_self_adv_data);

    if (!isis_am_i_dis (intf)) return;

    intf_info->lan_pn_to_self_adv_data = 
        (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t) ;
    
    advt_data = intf_info->lan_pn_to_self_adv_data;

    advt_data->advt_id = isis_gen_avt_id ();
    advt_data->tlv_no = ISIS_IS_REACH_TLV;
    advt_data->u.adj_data.nbr_sys_id = (ISIS_NODE_INFO(intf->att_node))->sys_id;
    advt_data->u.adj_data.metric = 0;
    advt_data->u.adj_data.local_ifindex = 0;
    advt_data->u.adj_data.remote_ifindex = intf->ifindex;
    advt_data->u.adj_data.local_intf_ip = 0;
    advt_data->u.adj_data.remote_intf_ip = IF_IP(intf);
    init_glthread(&advt_data->glue);
    advt_data->fragment = NULL;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    rc = isis_record_tlv_advertisement (
                                intf->att_node,
                                intf_info->elected_dis.pn_id,
                                advt_data,
                                &intf_info->lan_pn_to_self_adv_data,
                                &advt_info);

    switch (rc) {

    case ISIS_TLV_RECORD_ADVT_SUCCESS:
        break;
    case ISIS_TLV_RECORD_ADVT_ALREADY:
        assert(0);
    case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        assert(0);
    default:
        assert(0);
    }

    /* Step 3 : Advertise all Adjacencies on this interface as PN--> Nbr*/
    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
        isis_adjacency_advertise_is_reach(adjacency);

    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);
}

bool
isis_am_i_dis (Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) return false;

    if (isis_intf_is_p2p (intf)) return false;

    if (isis_lan_id_compare (&intf_info->elected_dis, &intf_info->lan_id) ==
                CMP_PREF_EQUAL) return true;

    return false;
}