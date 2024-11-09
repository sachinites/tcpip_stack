#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"
#include "isis_flood.h"
#include "isis_policy.h"
#include "isis_ted.h"

void
isis_cancel_spf_job(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info ||
        !node_info->spf_job_task) return;

    task_cancel_job(EV(node),  node_info->spf_job_task);
    node_info->spf_job_task = NULL;
}

static inline void
isis_free_spf_result(isis_spf_result_t *spf_result){

    nh_flush_nexthops(spf_result->nexthops);
    remove_glthread(&spf_result->spf_res_glue);
    XFREE(spf_result);
}

static void
isis_init_node_spf_data(ted_node_t *node, bool delete_spf_result){

    isis_spf_data_t **_spf_data = (isis_spf_data_t **)&ISIS_NODE_SPF_DATA(node);
    isis_spf_data_t *spf_data = *_spf_data;

    if (! spf_data ) {
        spf_data = XCALLOC(0, 1, isis_spf_data_t);
        init_glthread(&spf_data->spf_result_head);
        spf_data->node = node;
        *_spf_data = spf_data;
    }

    else if(delete_spf_result){

        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

            isis_spf_result_t *res = isis_spf_res_glue_to_spf_result(curr);
            isis_free_spf_result(res);
        } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
        init_glthread(&spf_data->spf_result_head);
    }

    spf_data->spf_metric = ISIS_INFINITE_METRIC;
    remove_glthread(&spf_data->priority_thread_glue);
    nh_flush_nexthops(spf_data->nexthops);
    spf_data->is_spf_processed = false;
}

static int 
isis_spf_comparison_fn(void *data1, void *data2){

    isis_spf_data_t *spf_data_1 = (isis_spf_data_t *)data1;
    isis_spf_data_t *spf_data_2 = (isis_spf_data_t *)data2;

    if(spf_data_1->spf_metric < spf_data_2->spf_metric)
        return CMP_PREFERRED;
    if(spf_data_1->spf_metric > spf_data_2->spf_metric)
        return CMP_NOT_PREFERRED;

#if 0
    if (spf_data1->node->pn_no && !spf_data2->node->pn_no)
        return CMP_PREFERRED;
    if (!spf_data1->node->pn_no && spf_data2->node->pn_no)
        return CMP_NOT_PREFERRED;
#endif

    return CMP_PREF_EQUAL;
}

static isis_spf_result_t *
isis_spf_lookup_spf_result_by_node(ted_node_t *spf_root, ted_node_t *node){

    glthread_t *curr;
    isis_spf_result_t *spf_result;
    isis_spf_data_t *curr_spf_data;

    isis_spf_data_t *spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(spf_root);

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

        spf_result = isis_spf_res_glue_to_spf_result(curr);
        if(spf_result->node == node)
            return spf_result;
    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
    return NULL;
}

static int
isis_spf_install_routes(node_t *spf_root, ted_node_t *ted_spf_root){

    char ip_addr[16];
    l3_route_t *l3route;
    ted_prefix_t *ted_prefix;
    avltree_node_t *avl_node;
    isis_node_info_t *node_info;
    uint32_t prefix32bit, mask32bit;

    rt_table_t *rt_table = 
        NODE_RT_TABLE(spf_root);

    node_info = ISIS_NODE_INFO(spf_root);

    /*Clear all routes except direct routes*/
    clear_rt_table(rt_table, PROTO_ISIS);

    /* Now iterate over result list and install routes for
     * loopback address of all routers*/

    int i = 0;
    int count = 0; /*no of routes installed*/
    glthread_t *curr;
    isis_spf_result_t *spf_result;
    nexthop_t *nexthop = NULL;
    isis_spf_data_t *spf_data = (isis_spf_data_t *)(ISIS_NODE_SPF_DATA(ted_spf_root));

    nxthop_proto_id_t nxthop_proto = 
        l3_rt_map_proto_id_to_nxthop_index(PROTO_ISIS);

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

        spf_result = isis_spf_res_glue_to_spf_result(curr);
        
        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Computing Routes Begin\n", 
                        ISIS_ROUTE,
                        spf_result->node->node_name);

        if (spf_result->node->pn_no) continue;

        /* Router ID */
        if (isis_evaluate_policy(spf_root,
                                              node_info->import_policy,
                                              spf_result->node->rtr_id, 32) == PFX_LST_DENY) {

            goto Exported_Prefixes;
        }

        for (i = 0; i < MAX_NXT_HOPS; i++){

            nexthop = spf_result->nexthops[i];

            if (!nexthop) break;

            tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Route Add %s/%d\n", 
                        ISIS_ROUTE,
                        spf_result->node->node_name,
                        tcp_ip_covert_ip_n_to_p(spf_result->node->rtr_id, ip_addr), 32);            

                rt_ipv4_route_add (spf_root, 
                        spf_result->node->rtr_id, 32,
                        tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                        nexthop->oif,
                        spf_result->spf_metric,
                        PROTO_ISIS, true);       

            count++;
        }

        Exported_Prefixes:

            /* Exported Prefixes */
            
             ITERATE_AVL_TREE_BEGIN(spf_result->node->prefix_tree_root, avl_node){

                    ted_prefix = avltree_container_of(avl_node, ted_prefix_t, avl_glue);
                    
                    if (isis_evaluate_policy(spf_root, 
                                                    node_info->import_policy,
                                                    ted_prefix->prefix, ted_prefix->mask) == PFX_LST_DENY){
                        continue;
                    }

                    mask32bit = tcp_ip_convert_dmask_to_bin_mask (ted_prefix->mask);
                    prefix32bit = ted_prefix->prefix & mask32bit;

                    l3route = rt_table_lookup_exact_match(rt_table, 
                                        tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr),
                                        ted_prefix->mask);
                    
                    tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Considering Route %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask); 

                    /*Case 0 : If directly connected route, skip */
                    if (l3route && l3_is_direct_route(l3route)) {
                        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Route %s/%d is Local, skipped",
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask); 

                        continue;
                    }

                    /* Case 1 : No L3 route present in RIB by ISIS */
                    if (!l3route ||  !l3route->nexthops[nxthop_proto][0] ) {

                        for (i = 0; i < MAX_NXT_HOPS; i++){
                            
                            nexthop = spf_result->nexthops[i];
                            if (!nexthop) break;

                        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Route Add %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask);      

                            rt_ipv4_route_add (spf_root, 
                                    prefix32bit, ted_prefix->mask, 
                                    tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                    nexthop->oif,
                                    spf_result->spf_metric + ted_prefix->metric,
                                    PROTO_ISIS, true);       

                             count++;
                        }

                        continue;
                    }

                        
                    /* Case 2 : Better route already present in RIB */
                    if (l3route->spf_metric[nxthop_proto] < 
                            (spf_result->spf_metric + ted_prefix->metric)) {

                        continue;
                    }

                    /* Case 3 : IF new route is a better route, then replace the route in routing table*/
                    if (l3route->spf_metric[nxthop_proto] > 
                            (spf_result->spf_metric + ted_prefix->metric)) {

                        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Route Delete %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask); 

                        rt_ipv4_route_del (spf_root,
                                 prefix32bit, ted_prefix->mask,  PROTO_ISIS, true);

                        for (i = 0; i < MAX_NXT_HOPS; i++){

                            nexthop = spf_result->nexthops[i];
                            if (!nexthop) break;

                        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : Route Replaced %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask);      

                            rt_ipv4_route_add (spf_root, 
                                    prefix32bit, ted_prefix->mask, 
                                    tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                    nexthop->oif,
                                    spf_result->spf_metric + ted_prefix->metric,
                                    PROTO_ISIS, true);       

                             count++;
                        }
                        continue;
                    }

                    /* Case 4: ECMP case, merge the nexthops */
                    for (i = 0; i < MAX_NXT_HOPS; i++) {

                        nexthop = spf_result->nexthops[i];
                        if (!nexthop) break;

                        tracer (ISIS_TR(spf_root), TR_ISIS_ROUTE, "%s : Dest %s  : ECMP Route Add %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask);  

                        rt_ipv4_route_add (spf_root, 
                                    prefix32bit, ted_prefix->mask, 
                                    tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                    nexthop->oif,
                                    spf_result->spf_metric + ted_prefix->metric,
                                    PROTO_ISIS, true);       

                         count++;
                    }
             } ITERATE_AVL_TREE_END;

    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
    return count;
}

static void
isis_initialize_direct_nbrs (node_t *spf_root, ted_node_t *ted_spf_root){

    /*Initialize direct nbrs*/
    char ip_addr[16];
    ted_intf_t *oif, *oif2;
    ted_node_t *nbr = NULL;
    nexthop_t *nexthop = NULL;
    unsigned char log_buf[256];
    isis_spf_data_t *nbr_spf_data;
    ted_node_t *nbr_of_pn = NULL;
    uint32_t nxt_hop_ip , nxt_hop_ip2;

    tracer (ISIS_TR(spf_root), TR_ISIS_SPF, 
        "%s : ISIS initializing direct nbrs\n", ISIS_SPF);
    
    ITERATE_TED_NODE_NBRS_BEGIN(ted_spf_root, nbr, oif, nxt_hop_ip){

        /*No need to process any nbr which is not conneted via
         * Bi-Directional L3 link. */
        if (!ted_is_link_bidirectional(oif->link)) {

                tracer (ISIS_TR(spf_root), TR_ISIS_SPF, 
                    "%s : nbr %s is not birectional, skipping it\n", ISIS_SPF, nbr->node_name);
            continue;
        }

        /* Case 1 : When root and nbr both are non PNs*/
        if (!ted_spf_root->pn_no && !nbr->pn_no)
        {
                    /*Step 2.1 : Begin*/
                    nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr);
                    /*Populate nexthop array of directly connected nbrs of spf_root*/
                    if (oif->cost < nbr_spf_data->spf_metric)
                    {
                         tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : Nbr Node %s nexthops flushed :  %s\n",
                            ISIS_SPF, nbr->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                         nh_flush_nexthops(nbr_spf_data->nexthops);
                         nexthop = nh_create_new_nexthop(nbr->node_name,
                                                         oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr), PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex);
                         nexthop->oif->InterfaceLockDynamic();
                         nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
                         nbr_spf_data->spf_metric = oif->cost;
                         nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf));
                         tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : Nbr Node %s nexthops learned :  %s\n",
                            ISIS_SPF, nbr->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                    }
                    /*Step 2.1 : End*/

                    /*Step 2.2 : Begin*/
                    /*Cover the ECMP case*/
                    else if (oif->cost == nbr_spf_data->spf_metric)
                    {
                         nexthop = nh_create_new_nexthop(nbr->node_name,
                                                        oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr),
                                                         PROTO_ISIS);
                         
                         if (nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop)) {

                            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex);
                            nexthop->oif->InterfaceLockDynamic();
                            tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : Nbr Node %s nexthops learned :  %s\n",
                                ISIS_SPF, nbr->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                         }
                         else {
                            
                            tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : Nbr Node %s nexthops not learned :  %s, ECMP limit reached\n",
                                ISIS_SPF, nbr->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                            XFREE(nexthop);
                         }
                    }
        }

        /*Case 2 : When root is PN and Nbr is not PN*/
        else if (ted_spf_root->pn_no && !nbr->pn_no) {
            /* We never run SPF on PN as spf root*/
            assert(0);
        }

        /*Case 3 : When root and nbr both are PNs*/
        else if (ted_spf_root->pn_no && nbr->pn_no) {
            /* IGP topology never have 2 PNs adjacent to each other*/
            assert(0);
        }

        /* Case 4 : When root is non-PN and nbr is PN. */
        else if (!ted_spf_root->pn_no && nbr->pn_no) {

              uint32_t root_to_pn_cost = oif->cost;
              ted_intf_t *root_to_pn_oif = oif;
              nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr);
              nbr_spf_data->spf_metric = root_to_pn_cost;

              ITERATE_TED_NODE_NBRS_BEGIN(nbr, nbr_of_pn, oif2, nxt_hop_ip2){

                     tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : Initializing PN's %s direct nbr %s\n", 
                        ISIS_SPF, nbr->node_name, nbr_of_pn->node_name);
                        
                     if (!ted_is_link_bidirectional(oif2->link)){ 
                        tracer (ISIS_TR(spf_root), TR_ISIS_SPF, 
                            "%s : PN's %s direct nbr %s is not birectional, skipping it\n", ISIS_SPF,  
                            nbr->node_name, nbr_of_pn->node_name);
                        continue;
                     }

                    if (nbr_of_pn == ted_spf_root) {
                        tracer (ISIS_TR(spf_root), TR_ISIS_SPF, 
                            "%s : PN's %s direct nbr %s is self root, skipping it\n", ISIS_SPF,  
                            nbr->node_name, nbr_of_pn->node_name);
                        continue;
                    }

                    /*Step 2.1 : Begin*/
                    nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr_of_pn);
                    /*Populate nexthop array of directly connected nbrs of spf_root*/
                    if ( (root_to_pn_cost + oif2-> cost ) < nbr_spf_data->spf_metric)
                    {
                         tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops flushed :  %s\n",
                            ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));                        
                         nh_flush_nexthops(nbr_spf_data->nexthops);
                         nexthop = nh_create_new_nexthop(nbr_of_pn->node_name,
                                                        root_to_pn_oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip2, ip_addr), PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, root_to_pn_oif->ifindex);
                         nexthop->oif->InterfaceLockDynamic();
                         nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
                         tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s\n",
                            ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));                          
                         nbr_spf_data->spf_metric = root_to_pn_cost + oif2->cost;
                    }
                    /*Step 2.1 : End*/

                    /*Step 2.2 : Begin*/
                    /*Cover the ECMP case*/
                    else if ((root_to_pn_cost + oif2-> cost )== nbr_spf_data->spf_metric)
                    {
                         nexthop = nh_create_new_nexthop(nbr_of_pn->node_name,
                                                         oif2->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip2, ip_addr),
                                                         PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, root_to_pn_oif->ifindex);

                         if (nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop)) {

                            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex);
                            nexthop->oif->InterfaceLockDynamic();
                            tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s\n",
                                ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));  
                         }
                         else {
                            
                            tracer (ISIS_TR(spf_root), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s, ECMP limit reached\n",
                                ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf))); 
                            XFREE(nexthop);
                         }                 
                    }

             } ITERATE_TED_NODE_NBRS_END(nbr, nbr_of_pn, oif2, nxt_hop_ip2);
        }

        /*Step 2.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(ted_spf_root, nbr, oif, nxt_hop_ip);
}

static void
isis_spf_record_result (tracer_t *tr,
                                    ted_node_t *spf_root, 
                                    ted_node_t *processed_node){ /*Dequeued Node*/

    unsigned char log_buff[256];
    isis_spf_data_t *spf_root_spf_data;
    isis_spf_data_t *processed_node_spf_data;

    spf_root_spf_data = ISIS_NODE_SPF_DATA(spf_root);
    processed_node_spf_data = ISIS_NODE_SPF_DATA(processed_node);

    /*Step 5 : Begin*/
    /* We are here because the node taken off the PQ is some node in Graph
     * to which shortest path has been calculated. We are done with this node
     * hence record the spf result in spf_root's local data structure*/

    /*Record result*/
    /*This result must not be present already but due to transient TEDs, anything
        could happen, hence do not assert, just return*/
    assert (!isis_spf_lookup_spf_result_by_node(spf_root, processed_node) );

    isis_spf_result_t *spf_result = XCALLOC(0, 1, isis_spf_result_t);
    /*We record three things as a part of spf result for a node in 
     * topology : 
     * 1. The node itself
     * 2. the shortest path cost to reach the node
     * 3. The set of nexthops for this node*/
    spf_result->node = processed_node;
    spf_result->spf_metric = processed_node_spf_data->spf_metric;
    nh_union_nexthops_arrays(
            processed_node_spf_data->nexthops,
            spf_result->nexthops);

    tracer (tr, TR_ISIS_SPF,
        "%s : Result Recorded for node %s, "
            "Next hops : %s, spf_metric = %u\n", ISIS_SPF,
            processed_node->node_name,
            nh_nexthops_str(spf_result->nexthops, log_buff, sizeof(log_buff)),
            spf_result->spf_metric);

    /*Add the result Data structure for node which has been processed
     * to the spf result table (= linked list) in spf root*/
    init_glthread(&spf_result->spf_res_glue);
    glthread_add_next(&spf_root_spf_data->spf_result_head,
                                   &spf_result->spf_res_glue);

    /*Step 5 : End*/
}


static void
isis_spf_explore_nbrs(tracer_t *tr,
                                    ted_node_t *spf_root,           /*Only used for logging*/
                                    ted_node_t *curr_node,        /*Current Node being explored*/
                                    glthread_t *priority_lst){

    ted_intf_t *oif;
    ted_node_t *nbr;
    uint32_t nxt_hop_ip;
    unsigned char log_buf[256];

    isis_spf_data_t *curr_node_spf_data = ISIS_NODE_SPF_DATA(curr_node);
    isis_spf_data_t *nbr_node_spf_data;

    tracer (tr, TR_ISIS_SPF,
        "%s : Nbr Exploration Start for Node : %s\n", ISIS_SPF, curr_node->node_name);

    /*Step 6 : Begin*/
    /*Now Process the nbrs of the processed node, and evaluate if we have
     * reached them via shortest path cost.*/

    if (IS_BIT_SET( curr_node->flags, ISIS_LSP_PKT_F_OVERLOAD_BIT) &&
            spf_root != curr_node) {
        tracer (tr, TR_ISIS_SPF,
            "%s : Nbr Exploration Node : %s aborted, reason : Overloaded\n", 
            ISIS_SPF, curr_node->node_name);
        return;
    }

    ITERATE_TED_NODE_NBRS_BEGIN(curr_node, nbr, oif, nxt_hop_ip){
        
        tracer (tr, TR_ISIS_SPF,
            "%s : For Node %s , Processing nbr %s\n", ISIS_SPF,
                curr_node->node_name, 
                nbr->node_name);

        if(!ted_is_link_bidirectional(oif->link)) continue;

        nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);

        if (nbr_node_spf_data->is_spf_processed) {
            tracer (tr, TR_ISIS_SPF,
                "%s : Nbr node %s skipped, already processed\n", ISIS_SPF,
                 nbr_node_spf_data->node->node_name);
            continue;
        }

         tracer (tr, TR_ISIS_SPF,
            "%s : Testing Inequality : " 
                " spf_metric(%s, %u) + link cost(%u) < spf_metric(%s, %u)\n", ISIS_SPF,
                curr_node->node_name, 
                curr_node_spf_data->spf_metric, 
                oif->cost, nbr->node_name,
                nbr_node_spf_data->spf_metric);

        /*Step 6.1 : Begin*/
        /* We have just found that a nbr node is reachable via even better 
         * shortest path cost. Simply adjust the nbr's node's position in PQ
         * by removing (if present) and adding it back to PQ*/
        if (curr_node_spf_data->spf_metric + oif->cost < 
                nbr_node_spf_data->spf_metric) {

            tracer (tr, TR_ISIS_SPF,
                "%s : For Node %s , Primary Nexthops Flushed\n", ISIS_SPF,
                   nbr->node_name);

            /*Remove the obsolete Nexthops */
            nh_flush_nexthops(nbr_node_spf_data->nexthops);
            /*copy the new set of nexthops from predecessor node 
             * from which shortest path to nbr node is just explored*/
            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);
            /*Update shortest path cost of nbr node*/
            nbr_node_spf_data->spf_metric = curr_node_spf_data->spf_metric + oif->cost;

            tracer (tr, TR_ISIS_SPF,
                "%s : Primary Nexthops Copied "
                "from Node %s to Node %s, Next hops : %s\n", ISIS_SPF,
                    curr_node->node_name, 
                    nbr->node_name,
                    nh_nexthops_str(nbr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));

            /*If the nbr node is already present in PQ, remove it from PQ and it 
             * back so that it takes correct position in PQ as per new spf metric*/
            if(!IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                tracer (tr, TR_ISIS_SPF,
                    "%s : Node %s Already On priority Queue\n", ISIS_SPF,  nbr->node_name);
               
                remove_glthread(&nbr_node_spf_data->priority_thread_glue);
            }

             tracer (tr, TR_ISIS_SPF,
                "%s : Node %s inserted into priority Queue "
                        "with spf_metric = %u\n", ISIS_SPF,
                         nbr->node_name, nbr_node_spf_data->spf_metric);

            glthread_priority_insert(priority_lst, 
                    &nbr_node_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);
            /*Step 6.1 : End*/
        }
        /*Step 6.2 : Begin*/
        /*Cover the ECMP case. We have just explored an ECMP path to nbr node.
         * So, instead of replacing the obsolete nexthops of nbr node, We will
         * do union of old and new nexthops since both nexthops are valid. 
         * Remove Duplicates however*/
        else if(curr_node_spf_data->spf_metric + oif->cost == 
                    nbr_node_spf_data->spf_metric){

            tracer (tr, TR_ISIS_SPF,
                "%s : Primary Nexthops Union of Current Node"
                " %s(%s) with Nbr Node ", ISIS_SPF,
                curr_node->node_name, 
                nh_nexthops_str(curr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));
            tracer_disable_hdr_print (tr);
            tracer (tr, TR_ISIS_SPF,
                "%s(%s)\n",  nbr->node_name, 
                nh_nexthops_str(nbr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));

            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);

            /*If the nbr node is already present in PQ, remove it from PQ and it 
             * back so that it takes correct position in PQ as per new spf metric. This Code
                is required for topologies containing VLANs/PNs. Remove below step and
                build_dualswitch_topo( ) will fail to compute routes*/
            if(!IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                tracer (tr, TR_ISIS_SPF,
                    "%s : Node %s Already On priority Queue, removing it from PQ\n",
                     ISIS_SPF, nbr->node_name);
                remove_glthread(&nbr_node_spf_data->priority_thread_glue);
            }

            tracer (tr, TR_ISIS_SPF,
                "%s : Node %s inserted into priority Queue "
                        "with spf_metric = %u\n", ISIS_SPF,
                         nbr->node_name, nbr_node_spf_data->spf_metric);

            glthread_priority_insert(priority_lst, 
                    &nbr_node_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);

        }
        /*Step 6.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(curr_node, nbr, oif, nxt_hop_ip);
        
     tracer (tr, TR_ISIS_SPF,
        "%s : Node %s has been processed, nexthops %s\n", ISIS_SPF,
           curr_node->node_name, 
            nh_nexthops_str(curr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));
    /* We are done processing the curr_node, remove its nexthops to lower the
     * ref count*/
    nh_flush_nexthops(curr_node_spf_data->nexthops); 
    /*Step 6 : End*/
}

static void
 isis_initialize_topology_for_spf_run (ted_node_t *spf_root) {

     glthread_t *curr;
     ted_node_t *nbr;
     ted_intf_t *oif;
     uint32_t nxt_hop_ip;

     isis_spf_data_t *spf_data = ISIS_NODE_SPF_DATA(spf_root);
     isis_spf_data_t *curr_spf_data;

    glthread_t priority_lst;
    init_glthread(&priority_lst); 

    glthread_priority_insert(&priority_lst, 
            &spf_data->priority_thread_glue,
            isis_spf_comparison_fn, 
            isis_spf_data_offset_from_priority_thread_glue);

    while(!IS_GLTHREAD_LIST_EMPTY(&priority_lst)){

        curr = dequeue_glthread_first(&priority_lst);
        spf_data = isis_priority_thread_glue_to_spf_data(curr);

        if (spf_data->node == spf_root) {
             isis_init_node_spf_data(spf_root, true);
             spf_data = ISIS_NODE_SPF_DATA(spf_root);
             spf_data->spf_metric = 0;
        }
        else {
            isis_init_node_spf_data(spf_data->node, false);
        }

        ITERATE_TED_NODE_NBRS_BEGIN(spf_data->node, nbr, oif, nxt_hop_ip){

            curr_spf_data = ISIS_NODE_SPF_DATA(nbr);
            if ( curr_spf_data &&
                  (curr_spf_data->spf_metric == ISIS_INFINITE_METRIC ||
                 curr_spf_data->node == spf_root)){
                continue;
            }
           
            isis_init_node_spf_data(nbr, false);
            curr_spf_data = ISIS_NODE_SPF_DATA(nbr);

           glthread_priority_insert(&priority_lst, 
                    &curr_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);
            
        } ITERATE_TED_NODE_NBRS_END(spf_data->node, nbr, oif, nxt_hop_ip);
    }
 }

void
isis_compute_spf (node_t *spf_root);

void
isis_compute_spf (node_t *spf_root){

    ted_intf_t *oif;
    glthread_t *curr;
    uint32_t nxt_hop_ip;
    ted_node_t *node, *nbr;
    ted_node_t *ted_spf_root;
    isis_spf_data_t *curr_spf_data;
    isis_spf_data_t *spf_root_spf_data = NULL;
    isis_spf_data_t *nbr_node_spf_data = NULL;
    isis_node_info_t *node_info = ISIS_NODE_INFO(spf_root);

    if (!isis_is_protocol_enable_on_node(spf_root)) {
        return;
    }

    ted_spf_root = ted_lookup_node(
                                node_info->ted_db,
                                tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(spf_root)), 0);

    if (!ted_spf_root) return;

    tracer (ISIS_TR(spf_root), TR_ISIS_SPF,  "%s : Running Spf\n", ISIS_SPF);

    /*Step 1 : Begin*/
    /* Clear old spf Result list from spf_root, and clear
     * any nexthop data if any*/
    isis_init_node_spf_data(ted_spf_root, true);
    spf_root_spf_data = ISIS_NODE_SPF_DATA(ted_spf_root);
    spf_root_spf_data->spf_metric = 0;

    /* Iterate all Routers in the graph and initialize the required fields
     * i.e. init cost to INFINITE, remove any spf nexthop data if any
     * left from prev spf run
     * */
    isis_initialize_topology_for_spf_run (ted_spf_root);
    /*Step 1 : End*/
   
    isis_initialize_direct_nbrs(spf_root, ted_spf_root);

    /*Step 3 : Begin*/
    /* Initialize the Priority Queue. You can implement the PQ as a 
     * Min-Heap which would give best performance, but we have chosen
     * a linked list as Priority Queue*/
    glthread_t priority_lst;
    init_glthread(&priority_lst); 
    /*Insert spf_root as the only node into PQ to begin with*/
    glthread_priority_insert(&priority_lst, 
            &spf_root_spf_data->priority_thread_glue,
            isis_spf_comparison_fn, 
            isis_spf_data_offset_from_priority_thread_glue);
    /*Step 3 : End*/

    /*Iterate until the PQ go empty. Currently it has only spf_root*/
    while(!IS_GLTHREAD_LIST_EMPTY(&priority_lst)){

        /*Step 4 : Begin*/
        curr = dequeue_glthread_first(&priority_lst);
        curr_spf_data = isis_priority_thread_glue_to_spf_data(curr);
        curr_spf_data->is_spf_processed = true;

        tracer (ISIS_TR(spf_root), TR_ISIS_SPF, 
            "%s : Node %s taken out of priority queue\n", ISIS_SPF, curr_spf_data->node->node_name);

        /* if the current node that is removed from PQ is spf root itself. 
         * Then No need to rcord the result. Process nbrs and put them in PQ*/
        if(curr_spf_data->node == ted_spf_root){

            ITERATE_TED_NODE_NBRS_BEGIN(curr_spf_data->node, nbr, oif, nxt_hop_ip){

               if(!ted_is_link_bidirectional(oif->link)) continue;
                                
                nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);
                if(IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                    tracer (ISIS_TR(spf_root), TR_ISIS_SPF,
                        "%s : Processing Direct Nbr %s\n", ISIS_SPF, nbr->node_name);

                    glthread_priority_insert(&priority_lst, 
                            &nbr_node_spf_data->priority_thread_glue,
                            isis_spf_comparison_fn, 
                            isis_spf_data_offset_from_priority_thread_glue);

                    tracer (ISIS_TR(spf_root), TR_ISIS_SPF,
                        "%s : Direct Nbr %s added to priority Queue\n", ISIS_SPF, nbr->node_name);
                }
            } ITERATE_NODE_NBRS_END(curr_spf_data->node, nbr, oif, nxt_hop_ip);

            tracer (ISIS_TR(spf_root), TR_ISIS_SPF,
                "%s : Root %s Processing Finished\n", 
                    ISIS_SPF, curr_spf_data->node->node_name);

            continue;
        }
        /*Step 4 : End*/

        /*Step 5  : Begin
         *Record Result */
        isis_spf_record_result(ISIS_TR(spf_root), ted_spf_root, curr_spf_data->node);
        /*Step 5  : End*/

        /*Step 6 : Begin */
        isis_spf_explore_nbrs(ISIS_TR(spf_root), ted_spf_root, curr_spf_data->node, &priority_lst);
        /*Step 6 : End */
    }

    /*Step 7 : Begin*/ 
    /*Calculate final routing table from spf result of spf_root*/
    int count = isis_spf_install_routes(spf_root, ted_spf_root);
    /*Step 7 : End*/

    tracer (ISIS_TR(spf_root), TR_ISIS_SPF,
        "%s : Route Installation Count = %d\n", ISIS_SPF, count);
}

void
isis_show_spf_results (node_t *node){

    int i = 0, j = 0;
    glthread_t *curr;
    Interface *oif = NULL;
    ted_node_t *ted_node;
    isis_spf_result_t *res = NULL;

    if (!isis_is_protocol_enable_on_node (node)) return;

    ted_db_t *ted_db = ISIS_TED_DB(node);

    if (!ted_db) return;

    ted_node = ted_lookup_node(ted_db, 
                        tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(node)), 0);

    if (!ted_node) return;

    isis_spf_data_t *node_spf_data = ISIS_NODE_SPF_DATA(ted_node);

    cprintf("\nSPF run results for node = %s\n", ted_node->node_name);

    ITERATE_GLTHREAD_BEGIN(&node_spf_data->spf_result_head, curr){
        
        res = isis_spf_res_glue_to_spf_result(curr);

        cprintf("DEST : %-10s spf_metric : %-6u", res->node->node_name, res->spf_metric);
        cprintf(" Nxt Hop : ");

        j = 0;

        for( i = 0; i < MAX_NXT_HOPS; i++, j++){

            if(!res->nexthops[i]) continue;

            oif = res->nexthops[i]->oif;
            if (!oif) {
                oif = node_get_intf_by_ifindex(node, res->nexthops[i]->ifindex);
            }

            if (j == 0){
                cprintf("OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name.c_str(),
                        res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
            else{
                cprintf("                                              : "
                        "OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name.c_str(),
                        res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
        }
    }ITERATE_GLTHREAD_END(&node_spf_data->spf_result_head, curr)
}

static void
isis_run_spf(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size){

    node_t *node = (node_t *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    node_info->spf_job_task = NULL;

    ISIS_INCREMENT_NODE_STATS(node, spf_runs);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_spf_runs]);

    isis_compute_spf(node);
}

void
isis_schedule_spf_job (node_t *node, isis_event_type_t event) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    
    if (isis_is_protocol_admin_shutdown (node)) {
        tracer (ISIS_TR(node), TR_ISIS_SPF,
            "%s : spf job not scheduled, protocol is admin shutdown\n", ISIS_SPF);
        return;
    }
    
    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_spf_job_scheduled]);

    if (node_info->spf_job_task) {
        
        tracer (ISIS_TR(node), TR_ISIS_SPF | TR_ISIS_EVENTS,
            "%s : spf job already scheduled\n", ISIS_SPF);
        return;
    }
    
    isis_add_new_spf_log(node, event);
    
    node_info->spf_job_task =
        task_create_new_job (EV(node), node, isis_run_spf, 
                                            TASK_ONE_SHOT,
                                            TASK_PRIORITY_COMPUTE);

    if (node_info->spf_job_task) {
        
        tracer (ISIS_TR(node), TR_ISIS_SPF | TR_ISIS_EVENTS,
            "%s : New spf job successfully scheduled\n", ISIS_SPF);
    }
}

void
isis_add_new_spf_log(node_t *node, isis_event_type_t event) {

    isis_spf_log_t *spf_log;
    isis_node_info_t *node_info;

    if (isis_is_protocol_shutdown_in_progress(node) ||
         isis_is_protocol_admin_shutdown(node) ||
         !isis_is_protocol_enable_on_node(node)) {
        return;
    }

    node_info = ISIS_NODE_INFO(node);   
    spf_log = XCALLOC(0, 1, isis_spf_log_t);
    
    spf_log->timestamp = time(NULL);
    spf_log->event = event;
    init_glthread(&spf_log->glue);
    glthread_add_next(&node_info->spf_logc.head, &spf_log->glue);
    node_info->spf_logc.count++;

    if (node_info->spf_logc.count > ISIS_MAX_SPF_LOG_COUNT) {
        node_info->spf_logc.count = ISIS_MAX_SPF_LOG_COUNT;
        glthread_t *last_node = glthread_get_last(&node_info->spf_logc.head);
        spf_log = isis_glue_spf_log(last_node);
        remove_glthread(&spf_log->glue);
        XFREE(spf_log);
    }
}

void
isis_show_spf_logs(node_t *node) {

    int i = 0;
    glthread_t *curr;
    isis_spf_log_t *spf_log;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return;

     ITERATE_GLTHREAD_BEGIN(&node_info->spf_logc.head, curr) {

         spf_log = isis_glue_spf_log(curr);
         cprintf("%d. %s  %s\n", i, ctime(&spf_log->timestamp), isis_event_str(spf_log->event));
         i++;
     } ITERATE_GLTHREAD_END(&node_info->spf_logc.head, curr)
}

void
isis_init_spf_logc(node_t *node) {

    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);
    init_glthread(&node_info->spf_logc.head);
    node_info->spf_logc.count = 0;
}

void
isis_cleanup_spf_logc(node_t *node) {

    glthread_t *curr;
    isis_spf_log_t *spf_log;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    ITERATE_GLTHREAD_BEGIN(&node_info->spf_logc.head, curr) {

        spf_log = isis_glue_spf_log(curr);
        remove_glthread(&spf_log->glue);
        XFREE(spf_log);
    } ITERATE_GLTHREAD_END(&node_info->spf_logc.head, curr);
}

void
isis_spf_cleanup_spf_data (ted_node_t *ted_node) {

    glthread_t *curr;
    isis_spf_result_t *res;
    isis_spf_data_t *spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(ted_node);
    
    if (!spf_data) return;

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr) {
        res = isis_spf_res_glue_to_spf_result(curr);
        isis_free_spf_result(res);
    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);

    init_glthread(&spf_data->spf_result_head);
    remove_glthread(&spf_data->priority_thread_glue);
    nh_flush_nexthops(spf_data->nexthops);
    XFREE(spf_data);
    ISIS_NODE_SPF_DATA(ted_node) = NULL;
}
