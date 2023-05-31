#include "../../tcp_public.h"
#include "isis_utils.h"
#include "isis_const.h"
#include "isis_enums.h"
#include "isis_struct.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_dis.h"

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
    isis_stop_sending_hellos(intf);
}

/* DIS Mgmt Functions */

/* Trigger DIS Re-election, return LAN-ID of the Node which is 
	elected as DIS. This fn do not modifies the protocol state in anyway. */
isis_lan_id_t
isis_intf_reelect_dis (Interface *intf) {

    uint32_t rtr_id;
    glthread_t *curr;
    isis_adjacency_t *adj;
    isis_lan_id_t self_lan_id;
    isis_lan_id_t null_lan_id = {0, 0};

    if (!intf->is_up || !intf->IsIpConfigured()) return null_lan_id;
    if (isis_intf_is_p2p (intf)) return null_lan_id;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);

    if (!intf_info) return null_lan_id; 

    self_lan_id = intf_info->lan_id;

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

/* This fn delete the known DIS by this node. The DIS could be self or some-other
	Nbr. This fn looks after to update Advt -DB (and hence the protocol advertisements)
	When DIS is forgotten (resigned). This fn performs 3 steps as commented below. The
	Ist two steps are meaningful to be performed only by self DIS, whereas last step is performed
	whether I am DIS or not*/
void 
isis_intf_resign_dis (Interface *intf) {

    glthread_t *curr;
    isis_adv_data_t *adv_data;
    bool update_hello = false;
    isis_adjacency_t *adjacency;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO (intf);

    if (!intf_info) return;

    /* Delete the DIS data ...
        I am resigning as a DIS, so withdraw all advertisements which I did
        with DIS privileges
    */
    /* Step 1 : 
        Since, we are resigning as self-DIS, Delete ISIS REACH advt info
        from from PN to self i.e. intf_info->lan_pn_to_self_adv_data; This Advertisement
        is done only by DIS node.
    */
    if (intf_info->lan_pn_to_self_adv_data) {
        
        assert(isis_am_i_dis (intf));

        adv_data = intf_info->lan_pn_to_self_adv_data;

        isis_advt_data_clear_backlinkage(
            ISIS_NODE_INFO(intf->att_node), adv_data);
        assert (!intf_info->lan_pn_to_self_adv_data);

        if (!adv_data->fragment) {
            isis_wait_list_advt_data_remove(intf->att_node, adv_data);
            isis_free_advt_data(adv_data);
            return;
        }

        isis_withdraw_tlv_advertisement(intf->att_node, adv_data);
        isis_free_advt_data( adv_data); 
        update_hello = true;
    }

    /* Step 2 : 
        Since, we are resigning as self-DIS, Delete all ISIS REACH advt info
        from from PN to all Nbrs i.e. on all ajacencies on this interface,
        delete advt info adjacency->lan_pn_to_adj_adv_data. So, basically
        we are removing IS-REACH advertisements from PN's fragments. If
        fragments goes empty, we discard them without purging.
    */
	if (isis_am_i_dis (intf)) {
    	ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        	adjacency = glthread_to_isis_adjacency(curr);
        
        	if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;

        	/* Adjacency may not have advertised by now, skip ...*/
        	if (adjacency->u.lan_pn_to_nbr_adv_data == NULL) continue;

            adv_data = adjacency->u.lan_pn_to_nbr_adv_data;

            isis_advt_data_clear_backlinkage(
                    ISIS_NODE_INFO(intf->att_node), adv_data);
            assert(!adjacency->u.lan_pn_to_nbr_adv_data);

            if (!adv_data->fragment) {
                isis_wait_list_advt_data_remove (intf->att_node, adv_data);
                isis_free_advt_data(adv_data);
                return ;
            }

            isis_withdraw_tlv_advertisement(intf->att_node, adv_data);
            isis_free_advt_data(adv_data);
        	 
    	} ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);
	}

    /* Step 3 : Now eventually Forget who the DIS is. Therefore, 
        withdraw the intf_info->lan_self_to_pn_adv_data.advt_id.
	    This step is performed irrespective whether weare DIS or not
    */
   if (intf_info->lan_self_to_pn_adv_data) {
    
        adv_data = intf_info->lan_self_to_pn_adv_data;

        isis_advt_data_clear_backlinkage(
            ISIS_NODE_INFO(intf->att_node), adv_data);
        assert (!intf_info->lan_self_to_pn_adv_data);

        if (!adv_data->fragment) {
            isis_wait_list_advt_data_remove (intf->att_node, adv_data);
            isis_free_advt_data(adv_data);
            return;
        }

        isis_withdraw_tlv_advertisement(intf->att_node, adv_data);
        isis_free_advt_data(adv_data);
   }

    intf_info->elected_dis = {0, 0};

    if (update_hello) {
        /* Start sending hellos at normal  time interval since i am no more DIS
            on this intefrace*/
        isis_stop_sending_hellos (intf);
        if (isis_interface_qualify_to_send_hellos (intf)) {
            isis_start_sending_hellos (intf);
        }
    }
}

/* This fn assigns a new DIS to the LAN intf of the node. The DIS could be some
	other Nbr node, or self. This fn implements three steps. Step 1 is performed when
	We come to know who the DIS is (including myself), Step 2 & 3is performed only when
	I am selected as DIS. This fn looks after the avertisement responsibilities to be perforned
	when self becomes DIS (steps 2 and 3)*/
void
isis_intf_assign_new_dis (Interface *intf, isis_lan_id_t new_dis_id) {

    glthread_t *curr;
    isis_adjacency_t *adjacency;    
    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_advt_tlv_return_code_t rc;

    if (!intf->is_up) return;
    if (isis_intf_is_p2p (intf)) return;
    if (isis_is_lan_id_null (new_dis_id)) return;

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    if (!intf_info) return ;
    
    assert (isis_is_lan_id_null (intf_info->elected_dis));

    intf_info->elected_dis = new_dis_id;

    ISIS_INCREMENT_NODE_STATS(intf->att_node,
        isis_event_count[isis_event_dis_changed]);

    /* Step 1 : 
    	Advertise self --> PN is-reach info.
        Advertise intf_info->adv_data.lan_self_to_pn_adv_data
    */
    assert(!intf_info->lan_self_to_pn_adv_data);
    
    intf_info->lan_self_to_pn_adv_data = 
        (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t) ;
    
    advt_data = intf_info->lan_self_to_pn_adv_data;
    advt_data->src.holder =  &intf_info->lan_self_to_pn_adv_data;
    advt_data->tlv_no = ISIS_IS_REACH_TLV;
    advt_data->u.adj_data.nbr_sys_id.rtr_id = intf_info->elected_dis.rtr_id;
    advt_data->u.adj_data.nbr_sys_id.pn_id = intf_info->elected_dis.pn_id;
    advt_data->u.adj_data.metric = 0;
    advt_data->u.adj_data.local_ifindex = intf->ifindex;
    advt_data->u.adj_data.remote_ifindex = 0;
    advt_data->u.adj_data.local_intf_ip =  IF_IP(intf);
    advt_data->u.adj_data.remote_intf_ip = 0;
    init_glthread(&advt_data->glue);
    advt_data->fragment = NULL;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    rc = isis_advertise_tlv (
                                intf->att_node,
                                0,
                                advt_data,
                                &advt_info);

    switch (rc) {
        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        case ISIS_TLV_RECORD_ADVT_NO_FRAG:
            break;
        default: ;
    }

    /* Step 2 : 
    	Advertise PN-->SELF is-reach info.
        Advertise intf_info->pn_to_self_adv_data
    */
    assert(!intf_info->lan_pn_to_self_adv_data);

    if (!isis_am_i_dis (intf)) return ;

    intf_info->lan_pn_to_self_adv_data = 
        (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t) ;
    
    advt_data = intf_info->lan_pn_to_self_adv_data;
    advt_data->src.holder = &intf_info->lan_pn_to_self_adv_data;
    advt_data->tlv_no = ISIS_IS_REACH_TLV;
    advt_data->u.adj_data.nbr_sys_id = (ISIS_NODE_INFO(intf->att_node))->sys_id;
    advt_data->u.adj_data.metric = intf_info->cost;
    advt_data->u.adj_data.local_ifindex = 0;
    advt_data->u.adj_data.remote_ifindex = intf->ifindex;
    advt_data->u.adj_data.local_intf_ip = 0;
    advt_data->u.adj_data.remote_intf_ip = IF_IP(intf);
    init_glthread(&advt_data->glue);
    advt_data->fragment = NULL;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    rc = isis_advertise_tlv (
                                intf->att_node,
                                intf_info->elected_dis.pn_id,
                                advt_data,
                                &advt_info);

    switch (rc) {
        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        case ISIS_TLV_RECORD_ADVT_NO_FRAG:
            break;
        default: ;
    }

    /* Step 3 : 
		Advertise PN-->NBR is-reach info. That is we are advertising is-reach TLVs
		on behalf of PN.
    	Advertise all Adjacencies on this interface as PN--> Nbr*/
    ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

        adjacency = glthread_to_isis_adjacency(curr);
        if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
        rc = isis_adjacency_advertise_is_reach(adjacency);

        switch (rc)
        {
        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        case ISIS_TLV_RECORD_ADVT_NO_FRAG:
            break;
        default: ;
        }
    } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

    /* ToDo : Update Hellos, start sending Hellos at interval of 3.3 seconds since i am
            DIS on this interface*/
    isis_stop_sending_hellos (intf);
    if (isis_interface_qualify_to_send_hellos (intf)) {
        isis_start_sending_hellos (intf);
    }

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
