#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_events.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_flood.h"
#include "isis_adjacency.h"

typedef struct isis_lsp_xmit_elem_ {

    isis_pkt_t *lsp_pkt;
    glthread_t glue;
} isis_lsp_xmit_elem_t;
GLTHREAD_TO_STRUCT(glue_to_lsp_xmit_elem, 
    isis_lsp_xmit_elem_t, glue);


static void
isis_assign_lsp_src_mac_addr(interface_t *intf,
                             isis_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(lsp_pkt->pkt);
    memcpy(eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_add_t));                           
}

void
isis_lsp_pkt_flood_complete(node_t *node){

}

static void
isis_lsp_xmit_job(void *arg, uint32_t arg_size) {

    uint32_t rc;
    glthread_t *curr;
    interface_t *intf;
    isis_pkt_t *lsp_pkt;
    bool has_up_adjacency;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;
    
    intf = (interface_t *)arg;
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);

    isis_intf_info->lsp_xmit_job = NULL;

    if (!isis_node_intf_is_enable(intf)) return;

    has_up_adjacency = isis_any_adjacency_up_on_interface(intf);

    ITERATE_GLTHREAD_BEGIN(&isis_intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        free(lsp_xmit_elem);
        
        if (has_up_adjacency && lsp_pkt->flood_eligibility){

            isis_assign_lsp_src_mac_addr(intf, lsp_pkt);
            send_pkt_out(lsp_pkt->pkt, lsp_pkt->pkt_size, intf);
            ISIS_INCREMENT_STATS(intf, lsp_pkt_sent);
        }

        rc = isis_deref_isis_pkt(lsp_pkt);

    } ITERATE_GLTHREAD_END(&isis_intf_info->lsp_xmit_list_head, curr);
}

void
isis_queue_lsp_pkt_for_transmission(
        interface_t *intf,
        isis_pkt_t *lsp_pkt) {

    isis_intf_info_t *isis_intf_info;
    
    if (!isis_node_intf_is_enable(intf)) return;

    if (!lsp_pkt->flood_eligibility) return;

    isis_intf_info = ISIS_INTF_INFO(intf);

    isis_lsp_xmit_elem_t *lsp_xmit_elem =
        calloc(1, sizeof(isis_lsp_xmit_elem_t));
    
    init_glthread(&lsp_xmit_elem->glue);
    lsp_xmit_elem->lsp_pkt = lsp_pkt;
    isis_ref_isis_pkt(lsp_pkt);

    glthread_add_last(&isis_intf_info->lsp_xmit_list_head,
                      &lsp_xmit_elem->glue);

    if (!isis_intf_info->lsp_xmit_job) {

        isis_intf_info->lsp_xmit_job =
            task_create_new_job(intf, isis_lsp_xmit_job, TASK_ONE_SHOT);
    }
}

void
isis_intf_purge_lsp_xmit_queue(interface_t *intf) {

    glthread_t *curr;
    isis_pkt_t *lsp_pkt;
    isis_intf_info_t *isis_intf_info;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;

    if (!isis_node_intf_is_enable(intf)) return;
    
    isis_intf_info = ISIS_INTF_INFO(intf);

    ITERATE_GLTHREAD_BEGIN(&isis_intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        free(lsp_xmit_elem);
        isis_deref_isis_pkt(lsp_pkt);

    } ITERATE_GLTHREAD_END(&isis_intf_info->lsp_xmit_list_head, curr);

    if (isis_intf_info->lsp_xmit_job) {
        task_cancel_job(isis_intf_info->lsp_xmit_job);
        isis_intf_info->lsp_xmit_job = NULL;
    }
}

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_pkt_t *lsp_pkt,
                        interface_t *exempt_iif) {

    interface_t *intf;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!lsp_pkt->flood_eligibility) return;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf) ||
                intf == exempt_iif) continue;

        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);

    } ITERATE_NODE_INTERFACES_END(node, intf);

    ISIS_INCREMENT_NODE_STATS(node, lsp_flood_count);
}

void
isis_update_lsp_flood_timer_with_new_lsp_pkt(
        node_t *node,
        isis_pkt_t *new_lsp_pkt) { /* Could be NULL */

    isis_pkt_t *old_lsp_pkt;
    isis_timer_data_t *old_isis_timer_data = NULL;
    isis_timer_data_t *new_isis_timer_data = NULL;
    
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    
    timer_event_handle *wt_elem = isis_node_info->periodic_lsp_flood_timer;

    if(!wt_elem) return;

    old_isis_timer_data = wt_elem_get_and_set_app_data(wt_elem, 0);

    /* case 1 : */
    if (!old_isis_timer_data && !new_lsp_pkt) goto done;

    /* case 2 : */
    else if (!old_isis_timer_data && new_lsp_pkt) {

        new_isis_timer_data =
            calloc(1, sizeof(isis_timer_data_t));

        new_isis_timer_data->node = node;
        new_isis_timer_data->intf = NULL;
        new_isis_timer_data->data = (char *)new_lsp_pkt;
        isis_ref_isis_pkt(new_lsp_pkt);
        new_isis_timer_data->data_size = sizeof(isis_pkt_t);
        wt_elem_get_and_set_app_data(wt_elem, new_isis_timer_data);
        goto done;
    }

    /* case 3 : */
    else if (old_isis_timer_data && !new_lsp_pkt) {

        isis_deref_isis_pkt((isis_pkt_t *)old_isis_timer_data->data);
        free(old_isis_timer_data);
        assert(0);
        goto done;
    }

    /* case 4 : Both are non null*/
    else {

        isis_deref_isis_pkt((isis_pkt_t *)old_isis_timer_data->data);
        isis_ref_isis_pkt(new_lsp_pkt);
        old_isis_timer_data->data = (char *)new_lsp_pkt;
        wt_elem_get_and_set_app_data(wt_elem, old_isis_timer_data);
        goto done;
    }

    done:
        ;
}

static void
timer_wrapper_isis_lsp_flood(void *arg, uint32_t arg_size) {

    if (!arg) return;
    
    isis_timer_data_t *isis_timer_data = 
        (isis_timer_data_t *)arg;

    ISIS_INCREMENT_NODE_STATS((isis_timer_data->node), seq_no);

    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(
                        (isis_pkt_t *)isis_timer_data->data);
    
    *seq_no = (ISIS_NODE_INFO(isis_timer_data->node))->seq_no;

#if 0
    printf("Node : %s : periodic flood seq no %u\n", 
        isis_timer_data->node->node_name, *seq_no);
#endif

    isis_schedule_lsp_flood(isis_timer_data->node,
                   (isis_pkt_t *)isis_timer_data->data, NULL);
}

void
isis_start_lsp_pkt_periodic_flooding(node_t *node) {

    wheel_timer_t *wt;
    isis_pkt_t *self_lsp_pkt;
    isis_node_info_t *isis_node_info;

    wt = node_get_timer_instance(node);
    isis_node_info = ISIS_NODE_INFO(node);
    self_lsp_pkt = isis_node_info->isis_self_lsp_pkt;

    isis_timer_data_t *isis_timer_data = NULL;

    /* Even if there is no LSP pkt to flood, start the
        timer any way */
    if (isis_node_info->isis_self_lsp_pkt) {
        
        isis_timer_data = calloc(1, sizeof(isis_timer_data_t));
        isis_timer_data->node = node;
        isis_timer_data->intf = NULL;
        isis_timer_data->data =
            (char *)(isis_node_info->isis_self_lsp_pkt);
        isis_ref_isis_pkt(isis_node_info->isis_self_lsp_pkt);
        isis_timer_data->data_size = sizeof(isis_pkt_t);
    }
       
    isis_node_info->periodic_lsp_flood_timer = 
                timer_register_app_event(wt,
                timer_wrapper_isis_lsp_flood,
                (void *)isis_timer_data,
                isis_timer_data ? sizeof(isis_timer_data_t) : 0,
                isis_node_info->lsp_flood_interval * 1000,
                1);
}

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node){

    isis_timer_data_t *isis_timer_data = NULL;
    timer_event_handle *periodic_lsp_flood_timer;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    periodic_lsp_flood_timer = isis_node_info->periodic_lsp_flood_timer;

    if (!periodic_lsp_flood_timer) return;

    isis_timer_data = wt_elem_get_and_set_app_data(
                            periodic_lsp_flood_timer, 0);

    timer_de_register_app_event(periodic_lsp_flood_timer);

    if (isis_timer_data) {

        isis_deref_isis_pkt((isis_pkt_t *)isis_timer_data->data);
        free(isis_timer_data);
    }
    
    isis_node_info->periodic_lsp_flood_timer = NULL;
}
