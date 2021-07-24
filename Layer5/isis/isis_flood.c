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

        if (rc == 0) {
            isis_lsp_pkt_flood_complete(intf->att_node);
        }

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
isis_flood_lsp(node_t *node, isis_pkt_t *lsp_pkt) {

    interface_t *intf;

    if (!lsp_pkt->flood_eligibility) return;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;

        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);

    } ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_lsp_pkt_flood_complete(node_t *node) {

  
}