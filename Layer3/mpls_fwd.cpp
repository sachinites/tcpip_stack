#include <assert.h>
#include "../graph.h"
#include "mpls_fwd.h"
#include "rt_table/nexthop.h"
#include "../Tracer/tracer.h"
#include "../pkt_block.h"
#include "../utils.h"
#include "../Interface/InterfaceUApi.h"

extern void
demote_pkt_to_layer2 (node_t *node,
                                       uint32_t next_hop_ip,
                                      c_string outgoing_intf,
                                      pkt_block_t *pkt_block,
                                      hdr_type_t hdr_type) ;

static int
mpls_rt_table_equalkeys(void *k1, void *k2)
{
    label_val_t *ky1 = (label_val_t *)k1;
    label_val_t *ky2 = (label_val_t *)k2;

    /* Keys are already decoded values, compare directly */

    if (*ky1 != *ky2) return 0;

    return 1;
}

static unsigned int
hashfromkey_label (void *key)
{
    label_val_t *key1 = (label_val_t *)key;
    return (unsigned int) (*key1);
}

void 
mpls_rt_table_init (node_t *node, mpls_rt_table_t **mpls_rt_table) {

    *mpls_rt_table = (mpls_rt_table_t *)XCALLOC2(0, 1, mpls_rt_table_t);
    (*mpls_rt_table)->ht = create_hashtable(20, hashfromkey_label, mpls_rt_table_equalkeys);
    (*mpls_rt_table)->node = node;
}

/* Algorithm : 
    Lookup if the hashtable if the route already exist , if already exist, add a nexthop to it */
bool
mpls_install_route (node_t *node, label_val_t in_label, nexthop_t *nxthop) {

    hashtable_t *ht; 
    /* Look up the mpls rt table using in_label as key*/
    label_val_t label_val = get_label_value (in_label);

    ht = NODE_MPLS_RT_TABLE (node)->ht;

    mpls_route_t *mpls_route = (mpls_route_t *)hashtable_search(ht, (void *)&label_val);

    if (!mpls_route) {

        mpls_route = (mpls_route_t *)XCALLOC2(0, 1, mpls_route_t);
        mpls_route->in_label = in_label;
        mpls_route->nxthop_idx = 0;
        mpls_route->install_time = time(NULL);
        mpls_route->flags = 0;
        mpls_route->nexthops[labelled_rt_map_proto_id_to_nxthop_index(nxthop->proto)][0] = nxthop;
        nexthop_reference(nxthop);
        mpls_route->nh_count = 1;
        /* Allocate key and store decoded label value for consistency with search */
        label_val_t *key = (label_val_t *)calloc(1, sizeof(label_val_t));
        *key = label_val;  // Use decoded value, same as search
        hashtable_insert(ht, (void *)key, (void *)mpls_route);
        tracer (node->dptr, DMPLS, "MPLS RIB : New Mpls Route %d added successfully", label_val);
        return true;
    }

    /* Add a nexthop to the mpls route*/
    if (nh_is_nexthop_exist_in_nh_array (mpls_route->nexthops[labelled_rt_map_proto_id_to_nxthop_index(nxthop->proto)], nxthop)) {
        
        tracer (node->dptr, DMPLS | DERR, "MPLS RIB : Attempt to add duplicate Nexthop to Mpls Route %d \n", label_val);
        return false;
    }

    assert ( nh_insert_new_nexthop_nh_array (mpls_route->nexthops[labelled_rt_map_proto_id_to_nxthop_index(nxthop->proto)], nxthop) ); 
    mpls_route->nh_count++;
    return true;
}

void
mpls_uninstall_route (node_t *node, label_val_t in_label, nexthop_t *nxthop) {

    bool rc;
    hashtable_t *ht; 
    nexthop_t * removed_nh;

    /* Look up the mpls rt table using in_label as key*/
    label_val_t label_val = get_label_value (in_label);

    ht = NODE_MPLS_RT_TABLE (node)->ht;

    mpls_route_t *mpls_route = (mpls_route_t *)hashtable_search(ht, (void *)&label_val);

    if (!mpls_route) {
        tracer (node->dptr, DMPLS | DERR, "MPLS RIB : Route %d not found, Route deletion failed\n", label_val);
        return;
    }

    rc  = nh_remove_nexthop_from_nh_array (mpls_route->nexthops[labelled_rt_map_proto_id_to_nxthop_index(nxthop->proto)], nxthop);

    if (!rc) {
        tracer (node->dptr, DMPLS | DERR, "MPLS RIB : Nexthop not found in Mpls Route %d, Route deletion failed\n", label_val);
        return;
    }

    /* Remove the nexthop from the mpls route*/
    tracer (node->dptr, DMPLS, "MPLS RIB : Nexthop removed from Mpls Route %d\n", label_val);

    mpls_route->nh_count--;

    if (mpls_route->nh_count == 0) {
        mpls_route = (mpls_route_t *)hashtable_remove (ht, (void *)&label_val);
        assert (mpls_route);
        XFREE (mpls_route);
    }
    
}

void 
mpls_apply_label_stack_on_pkt (pkt_block_t *pkt_block, lstack_t *lstack) {

    int i = 0;
    bool s_bit = false;
    pkt_size_t pkt_size;
    label_val_t *pkt_label;

    for (i = 0; i < MAX_LBL_DEPTH; i++) {

        if (lstack->labels[i].op == LBL_STACK_OPS_UNKNOWN) continue;

        switch (lstack->labels[i].op ) {

            case LBL_POP:
                if (pkt_block_get_starting_hdr (pkt_block) == MPLS_HDR) {
                    pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (is_stack_bottom (*pkt_label)) s_bit = true;
                    pkt_block_set_new_pkt (pkt_block, (uint8_t *)(pkt_label + 1), pkt_size - sizeof (label_val_t));
                    if (s_bit) pkt_block_set_starting_hdr_type (pkt_block,  MISC_APP_HDR);
                }
            break;


            case LBL_PUSH:
                pkt_block_expand_buffer_left (pkt_block, sizeof (label_val_t));
                pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                *pkt_label = get_label_value (lstack->labels[i].label_val );
                if (pkt_block_get_starting_hdr (pkt_block) != MPLS_HDR) {
                    pkt_block_set_starting_hdr_type (pkt_block, MPLS_HDR);
                    set_stack_bottom (pkt_label);
                }
            break;


            case LBL_SWAP:
                s_bit = false;
                if (pkt_block_get_starting_hdr (pkt_block) == MPLS_HDR) {
                    pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (is_stack_bottom (*pkt_label)) s_bit = true;
                    *pkt_label = get_label_value (lstack->labels[i].label_val );
                    if (s_bit) set_stack_bottom (pkt_label);
                }
            break;

        }
    }
}

static nexthop_t *
mlps_route_get_active_nexthop (mpls_route_t *mpls_route, Interface *exclude_oif)  {

    int nh_index_old;
    nexthop_t *nexthop;
    labelled_nxthop_proto_id_t nh_proto;

    nh_index_old = mpls_route->nxthop_idx;

    FOR_ALL_LABELLED_NXTHOP_PROTO(nh_proto) {

        do {

            nexthop = mpls_route->nexthops[nh_proto][mpls_route->nxthop_idx];

            if (!nexthop) { 

                mpls_route->nxthop_idx++;

                if (mpls_route->nxthop_idx == MAX_NXT_HOPS) {
                    mpls_route->nxthop_idx = 0;
                }

                if (mpls_route->nxthop_idx == nh_index_old) {
                    break;
                }

                continue;
            }

            if (nexthop->oif.get() == exclude_oif && exclude_oif) {

                mpls_route->nxthop_idx++;

                if (mpls_route->nxthop_idx == MAX_NXT_HOPS) {
                    mpls_route->nxthop_idx = 0;
                }

                if (mpls_route->nxthop_idx == nh_index_old) {
                    break;
                }

                continue;
            }

            mpls_route->nxthop_idx++;

            if (mpls_route->nxthop_idx == MAX_NXT_HOPS) {
                mpls_route->nxthop_idx = 0;
            }

            return nexthop;

        } while (1);

    }

    return NULL;
}

void 
mpls_route_pkt (node_t *node, Interface *recv_intf, pkt_block_t *pkt_block) {

    assert (pkt_block_get_starting_hdr(pkt_block) == MPLS_HDR);

    hashtable_t *ht; 
    pkt_size_t pkt_size;

    label_val_t *pkt_label = (label_val_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    label_val_t label_val = get_label_value(*pkt_label);

    ht = NODE_MPLS_RT_TABLE (node)->ht;

    /* Look up MPLS route entry based on incoming label */
    mpls_route_t *mpls_route = (mpls_route_t *)hashtable_search(ht, (void *)&label_val);

    if (!mpls_route)  {
        tracer (node->dptr, DMPLS | DERR, "MPLS RIB : Route %d not found for label %d\n", label_val);
        return;
    }
    
    /* Apply label stack operations */
    nexthop_t *nexthop = mlps_route_get_active_nexthop (mpls_route, recv_intf);

    if (!nexthop) {
        tracer (node->dptr, DMPLS | DERR, "MPLS RIB : No active nexthop found for label %d\n", label_val);
        return;
    }

    mpls_apply_label_stack_on_pkt (pkt_block, nexthop->lbls);

    tracer (node->dptr, DMPLS, "MPLS RIB:  Demoting MPLS Pkt to Layer 2, Routing label : %d\n", label_val);

    demote_pkt_to_layer2 (
        node,           
        tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
        (c_string)nexthop->oif->if_name.c_str(),          
        pkt_block,  
        MPLS_HDR);   

    nexthop->hit_count++;
}

/* Display mpls routing table */

void
mpls_display_routing_table (node_t *node) {

    nexthop_t *nexthop;
    mpls_route_t *mpls_route;
    labelled_nxthop_proto_id_t nh_proto;
    hashtable_t *ht = NODE_MPLS_RT_TABLE(node)->ht;

    struct hashtable_itr *itr = hashtable_iterator(ht);
    unsigned char uptime_buff[HRS_MIN_SEC_FMT_TIME_LEN];

    while ((mpls_route = (mpls_route_t *)hashtable_iterator_value(itr))) {

        cprintf ("In-label : %d\n", get_label_value(mpls_route->in_label));

        FOR_ALL_LABELLED_NXTHOP_PROTO(nh_proto) {

            for (int i = 0; i < MAX_NXT_HOPS; i++) {

                if (!mpls_route->nexthops[nh_proto][i]) continue;

                nexthop = mpls_route->nexthops[nh_proto][i];

                /* Print the label and its nexthop in Cisco like format */        
                cprintf ("-> Nexthop : %s  OIF : %s\n", nexthop->gw_ip, nexthop->oif->if_name.c_str());
                cprintf (".  Proto : %s\n", labelled_nxthop_proto_id_tostring(nh_proto));
                cprintf (".  Hit Count : %llu\n", nexthop->hit_count);
                cprintf (".  Uptime : %s\n", 
                    hrs_min_sec_format((unsigned int)difftime(time(NULL),
                    mpls_route->install_time), uptime_buff, 
                    HRS_MIN_SEC_FMT_TIME_LEN));

                cprintf (".  Label Stack : ");
                
                for (int j = 0; j < MAX_LBL_DEPTH; j++) {

                    if (nexthop->lbls->labels[j].op == LBL_STACK_OPS_UNKNOWN) continue;

                    cprintf ("%d(%s) ", 
                            get_label_value( nexthop->lbls->labels[j].label_val), 
                            mpls_op_tostring(nexthop->lbls->labels[j].op));
                }
                printw ("\n");
            }
        }
        if (!hashtable_iterator_advance(itr)) break;
        printw ("\n");
    }

    free(itr);
}