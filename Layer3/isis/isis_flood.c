#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_events.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_flood.h"
#include "isis_adjacency.h"
#include "isis_lspdb.h"
#include "isis_intf_group.h"
#include "isis_spf.h"

extern void
isis_parse_lsp_tlvs_internal(isis_lsp_pkt_t *new_lsp_pkt, 
                             bool *on_demand_tlv);

static void
isis_assign_lsp_src_mac_addr(Interface *intf,
                             isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(lsp_pkt->pkt);
    memcpy(eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_addr_t));
}

void
isis_lsp_pkt_flood_complete(node_t *node, isis_lsp_pkt_t *lsp_pkt ){

    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    tracer (ISIS_TR(node), TR_ISIS_LSDB, "%s : Flooding of LSP %s completed\n", 
            ISIS_LSPDB_MGMT,
            isis_print_lsp_id (lsp_pkt, lsp_id_str));
}

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    lsp_pkt->flood_eligibility = false;
}

static void
isis_lsp_xmit_job(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    Interface *intf;
    pkt_block_t *pkt_block;
    isis_lsp_pkt_t *lsp_pkt;
    bool has_up_adjacency;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    
    intf = (Interface *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(intf->att_node);
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    intf_info->lsp_xmit_job = NULL;

     tracer (ISIS_TR(intf->att_node), TR_ISIS_LSDB | TR_ISIS_EVENTS,
        "%s : lsp xmit job triggered on interface %s\n", ISIS_LSPDB_MGMT, intf->if_name.c_str());

    if (!isis_node_intf_is_enable(intf)) return;

    has_up_adjacency = isis_any_adjacency_up_on_interface(intf);

    pkt_block = pkt_block_get_new(NULL, 0);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        assert(lsp_pkt->flood_queue_count);       
        XFREE(lsp_xmit_elem);
        
        if (has_up_adjacency && lsp_pkt->flood_eligibility && 
            !node_info->lsdb_advt_block){
    
            isis_assign_lsp_src_mac_addr(intf, lsp_pkt);
            pkt_block_set_new_pkt(pkt_block, (uint8_t *)lsp_pkt->pkt, lsp_pkt->pkt_size);
            pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);
            /* This needs an optimization, but code changes will be too much !*/
            pkt_block_t *pkt_block2 = pkt_block_dup(pkt_block);
            cp2dp_xmit_pkt(intf->att_node, pkt_block2, intf);
            ISIS_INTF_INCREMENT_STATS(intf, lsp_pkt_sent);
            tracer (ISIS_TR(intf->att_node), TR_ISIS_LSDB, "%s : LSP %s pushed out of interface %s\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
            pkt_block_dereference(pkt_block2);
        } else {
            tracer (ISIS_TR(intf->att_node), TR_ISIS_LSDB, 
                "%s : LSP %s discarded from output flood Queue of interface %s, %d %d\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str(),
                has_up_adjacency, lsp_pkt->flood_eligibility);
        }

        lsp_pkt->flood_queue_count--;
        node_info->pending_lsp_flood_count--;

        if (!lsp_pkt->flood_queue_count) {
            isis_lsp_pkt_flood_complete(intf->att_node, lsp_pkt);
        }

        isis_deref_isis_pkt(intf->att_node, lsp_pkt);

    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr);

    XFREE(pkt_block);

    /* If there are no more LSPs to be pushed out for flooding, and
        we are shutting down then, check and delete protocol configuration
    */
    if ( node_info->pending_lsp_flood_count ==0                &&
         isis_is_protocol_shutdown_in_progress(intf->att_node)) {
        
        isis_check_and_shutdown_protocol_now(intf->att_node,
            ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK);
    }
    
}

void
isis_queue_lsp_pkt_for_transmission(
        Interface *intf,
        isis_lsp_pkt_t *lsp_pkt) {

    isis_node_info_t *node_info;
    isis_intf_info_t *intf_info;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    if (!isis_node_intf_is_enable(intf)) return;

    if (!lsp_pkt->flood_eligibility) return;

    intf_info = ISIS_INTF_INFO(intf);
    node_info = ISIS_NODE_INFO(intf->att_node);

    isis_lsp_xmit_elem_t *lsp_xmit_elem =
        XCALLOC(0, 1, isis_lsp_xmit_elem_t);
    
    init_glthread(&lsp_xmit_elem->glue);
    lsp_xmit_elem->lsp_pkt = lsp_pkt;
    isis_ref_isis_pkt(lsp_pkt);

    glthread_add_next(&intf_info->lsp_xmit_list_head,
                      &lsp_xmit_elem->glue);

    tracer (ISIS_TR(intf->att_node), TR_ISIS_LSDB, "%s : LSP %s scheduled to flood out of %s\n",
            ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str),
            intf->if_name.c_str());

    lsp_pkt->flood_queue_count++;
    node_info->pending_lsp_flood_count++;

    if (!intf_info->lsp_xmit_job) {

       intf_info->lsp_xmit_job =
            task_create_new_job(EV(intf->att_node), 
                    intf, isis_lsp_xmit_job, TASK_ONE_SHOT,
                    TASK_PRIORITY_COMPUTE);
    }
}

void
isis_intf_purge_lsp_xmit_queue(Interface *intf) {

    glthread_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    isis_intf_info_t *intf_info;
    isis_node_info_t *node_info;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;

    if (!isis_node_intf_is_enable(intf)) return;
    
    intf_info = ISIS_INTF_INFO(intf);
    node_info = ISIS_NODE_INFO(intf->att_node);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        XFREE(lsp_xmit_elem);
        lsp_pkt->flood_queue_count--;
        isis_deref_isis_pkt(intf->att_node, lsp_pkt);
        node_info->pending_lsp_flood_count--;
        
    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr);

    if (intf_info->lsp_xmit_job) {
        task_cancel_job(EV(intf->att_node), intf_info->lsp_xmit_job);
        intf_info->lsp_xmit_job = NULL;
    }
}

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_lsp_pkt_t *lsp_pkt,
                        Interface *exempt_iif) {

    Interface *intf;
    glthread_t *curr;
    avltree_node_t *avl_node;
    bool is_lsp_queued = false;
    isis_intf_group_t *intf_grp;
    isis_node_info_t *node_info;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    node_info  = ISIS_NODE_INFO(node);

    if (!lsp_pkt->flood_eligibility) return;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;

        if (intf == exempt_iif) {
           tracer (ISIS_TR(node), TR_ISIS_LSDB, 
                "%s : LSP %s flood skip out of intf %s, Reason :reciepient intf\n",
                ISIS_LSPDB_MGMT,  isis_print_lsp_id(lsp_pkt, lsp_id_str), 
                intf->if_name.c_str());
            continue;
        }

        if (ISIS_INTF_INFO(intf)->intf_grp) continue;

         tracer (ISIS_TR(node), TR_ISIS_LSDB, "%s : LSP %s scheduled for flood out of intf %s\n",
            ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);
        is_lsp_queued = true;

    } ITERATE_NODE_INTERFACES_END(node, intf);

    /* Now iterate over all interface grps */
    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);

        if (exempt_iif && ISIS_INTF_INFO(exempt_iif)->intf_grp == intf_grp) { 
        
             tracer (ISIS_TR(node), TR_ISIS_LSDB, "%s : LSP %s flood skip out of intf %s, Reason : reciepient intf grp %s\n",
                        ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), exempt_iif->if_name.c_str(),
                        ISIS_INTF_INFO(exempt_iif)->intf_grp->name);
            continue;
        }
        
        intf = isis_intf_grp_get_first_active_intf_grp_member(node, intf_grp);
        if (!intf || !isis_any_adjacency_up_on_interface(intf)) continue;
        
       tracer (ISIS_TR(node), TR_ISIS_LSDB, "%s : LSP %s scheduled for flood out of intf %s intf-grp %s\n",
                    ISIS_LSPDB_MGMT,
                    isis_print_lsp_id(lsp_pkt, lsp_id_str),
                    intf->if_name.c_str(),
                    ISIS_INTF_INFO(intf)->intf_grp ? ISIS_INTF_INFO(intf)->intf_grp->name : "None");

        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);
        is_lsp_queued = true;

    }  ITERATE_AVL_TREE_END;

    if (is_lsp_queued) {
        ISIS_INCREMENT_NODE_STATS(node, lsp_flood_count);
    }
}

void
isis_schedule_purge_lsp_flood_cbk (node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    isis_fragment_t *fragment;

    fragment = lsp_pkt->fragment;
    fragment->regen_flags = ISIS_SHOULD_INCL_PURGE_BIT;
    isis_regenerate_lsp_fragment (node, fragment, fragment->regen_flags);
    
    tracer (ISIS_TR(node), TR_ISIS_LSDB | TR_ISIS_EVENTS, 
            "%s : Purging LSP %s\n", ISIS_LSPDB_MGMT,
            isis_print_lsp_id (fragment->lsp_pkt, lsp_id_str));

    isis_schedule_lsp_flood (node, fragment->lsp_pkt, NULL);
}

void
isis_walk_all_self_zero_lsps (node_t *node, void (*fn_ptr)(node_t *, isis_lsp_pkt_t *)) {

    int i;
    isis_advt_db_t *advt_db;
    isis_fragment_t *fragment0;

    isis_node_info_t *node_info = ISIS_NODE_INFO (node);

    for (i = 0 ; i < ISIS_MAX_PN_SUPPORTED; i++) {

        advt_db = node_info->advt_db[i];
        if (!advt_db) continue;

        fragment0 = advt_db->fragments[0];

        /* fragment may not exist if node is not DIS for this LAN*/
        if (!fragment0 || !fragment0->lsp_pkt) continue;

        fn_ptr (node, fragment0->lsp_pkt);
    }
}
