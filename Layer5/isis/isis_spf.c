#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"
#include "isis_flood.h"
#include "isis_policy.h"

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
}

static int 
isis_spf_comparison_fn(void *data1, void *data2){

    isis_spf_data_t *spf_data_1 = (isis_spf_data_t *)data1;
    isis_spf_data_t *spf_data_2 = (isis_spf_data_t *)data2;

    if(spf_data_1->spf_metric < spf_data_2->spf_metric)
        return -1;
    if(spf_data_1->spf_metric > spf_data_2->spf_metric)
        return 1;
    return 0;
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
    isis_node_info_t *node_info;

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

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

        spf_result = isis_spf_res_glue_to_spf_result(curr);

        for (i = 0; i < MAX_NXT_HOPS; i++){

            nexthop = spf_result->nexthops[i];

            if (!nexthop) continue;

            if (isis_evaluate_policy(spf_root, 
                                                    node_info->import_policy,
                                                    spf_result->node->rtr_id, 32) == PFX_LST_DENY) {
                continue;
            }

            rt_table_add_route(rt_table, 
                    tcp_ip_covert_ip_n_to_p(spf_result->node->rtr_id, ip_addr), 32, 
                    nexthop->gw_ip, nexthop->oif, 
                    spf_result->spf_metric,
                    PROTO_ISIS);
            count++;
        }
    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
    return count;
}

void
isis_initialize_direct_nbrs (node_t *spf_root, ted_node_t *ted_spf_root){

    /*Initialize direct nbrs*/
    ted_node_t *nbr = NULL;
    uint32_t nxt_hop_ip ;
    char ip_addr[16];
    ted_intf_t *oif;
    nexthop_t *nexthop = NULL;
    isis_spf_data_t *nbr_spf_data;

    ITERATE_TED_NODE_NBRS_BEGIN(ted_spf_root, nbr, oif, nxt_hop_ip){

        /*No need to process any nbr which is not conneted via
         * Bi-Directional L3 link. This will remove any L2 Switch
         * present in topology as well.*/
        if (!ted_link_is_bidirectional(oif->link)) continue;

        /*Step 2.1 : Begin*/
        nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr);
        /*Populate nexthop array of directly connected nbrs of spf_root*/
        if (oif->cost < nbr_spf_data->spf_metric){
            nh_flush_nexthops(nbr_spf_data->nexthops);
            nexthop = nh_create_new_nexthop (oif->ifindex, 
                                tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr), PROTO_STATIC);
            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex);
            nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
            nbr_spf_data->spf_metric = oif->cost;
        }
        /*Step 2.1 : End*/

        /*Step 2.2 : Begin*/
        /*Cover the ECMP case*/
        else if (oif->cost == nbr_spf_data->spf_metric){
            nexthop = nh_create_new_nexthop (oif->ifindex,
                            tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr), 
                            PROTO_STATIC);
            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex);
            nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
        }
        /*Step 2.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(ted_spf_root, nbr, oif, nxt_hop_ip);
}

#define ISIS_SPF_LOGGING 0

static void
isis_spf_record_result (ted_node_t *spf_root, 
                                    ted_node_t *processed_node){ /*Dequeued Node*/

    isis_spf_data_t *spf_root_spf_data;
    isis_spf_data_t *processed_node_spf_data;

    spf_root_spf_data = ISIS_NODE_SPF_DATA(spf_root);
    processed_node_spf_data = ISIS_NODE_SPF_DATA(processed_node);

    /*Step 5 : Begin*/
    /* We are here because the node taken off the PQ is some node in Graph
     * to which shortest path has been calculated. We are done with this node
     * hence record the spf result in spf_root's local data structure*/

    /*Record result*/
    /*This result must not be present already*/
    assert (!isis_spf_lookup_spf_result_by_node(spf_root, processed_node));

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

    #if ISIS_SPF_LOGGING
    printf("root : %s : Event : Result Recorded for node %s, "
            "Next hops : %s, spf_metric = %u\n",
            spf_root->node_name, 
            processed_node->node_name,
            nh_nexthops_str(spf_result->nexthops),
            spf_result->spf_metric);
    #endif
    /*Add the result Data structure for node which has been processed
     * to the spf result table (= linked list) in spf root*/
    init_glthread(&spf_result->spf_res_glue);
    glthread_add_next(&spf_root_spf_data->spf_result_head,
                                   &spf_result->spf_res_glue);

    /*Step 5 : End*/
}


static void
isis_spf_explore_nbrs(ted_node_t *spf_root,           /*Only used for logging*/
                                    ted_node_t *curr_node,        /*Current Node being explored*/
                                    glthread_t *priority_lst){

    ted_intf_t *oif;
    ted_node_t *nbr;
    uint32_t nxt_hop_ip;

    isis_spf_data_t *curr_node_spf_data = ISIS_NODE_SPF_DATA(curr_node);
    isis_spf_data_t *nbr_node_spf_data;

    #if ISIS_SPF_LOGGING
    printf("root : %s : Event : Nbr Exploration Start for Node : %s\n",
            spf_root->node_name, curr_node->node_name);
    #endif
    /*Step 6 : Begin*/
    /*Now Process the nbrs of the processed node, and evaluate if we have
     * reached them via shortest path cost.*/

    if (IS_BIT_SET( curr_node->flags, ISIS_LSP_PKT_F_OVERLOAD_BIT) &&
            spf_root != curr_node) {
        #if ISIS_SPF_LOGGING
        printf("root : %s : Event : Nbr Exploration Node : %s aborted, reason : Overloaded\n",
                spf_root->node_name, curr_node->node_name);
        #endif
        return;
    }

    ITERATE_TED_NODE_NBRS_BEGIN(curr_node, nbr, oif, nxt_hop_ip){
        #if ISIS_SPF_LOGGING
        printf("root : %s : Event : For Node %s , Processing nbr %s\n",
                spf_root->node_name, curr_node->node_name, 
                nbr->node_name);
        #endif
        if(!ted_link_is_bidirectional(oif->link)) continue;

        nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);

        #if ISIS_SPF_LOGGING
        printf("root : %s : Event : Testing Inequality : " 
                " spf_metric(%s, %u) + link cost(%u) < spf_metric(%s, %u)\n",
                spf_root->node_name, curr_node->node_name, 
                curr_node_spf_data->spf_metric, 
                oif->cost, nbr->node_name,
                nbr_node_spf_data->spf_metric);
        #endif
        /*Step 6.1 : Begin*/
        /* We have just found that a nbr node is reachable via even better 
         * shortest path cost. Simply adjust the nbr's node's position in PQ
         * by removing (if present) and adding it back to PQ*/
        if (curr_node_spf_data->spf_metric + oif->cost < 
                nbr_node_spf_data->spf_metric) {

            #if ISIS_SPF_LOGGING
            printf("root : %s : Event : For Node %s , Primary Nexthops Flushed\n",
                    spf_root->node_name, nbr->node_name);
            #endif
            /*Remove the obsolete Nexthops */
            nh_flush_nexthops(nbr_node_spf_data->nexthops);
            /*copy the new set of nexthops from predecessor node 
             * from which shortest path to nbr node is just explored*/
            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);
            /*Update shortest path cost of nbr node*/
            nbr_node_spf_data->spf_metric = curr_node_spf_data->spf_metric + oif->cost;

            #if ISIS_SPF_LOGGING
            printf("root : %s : Event : Primary Nexthops Copied "
            "from Node %s to Node %s, Next hops : %s\n",
                    spf_root->node_name, curr_node->node_name, 
                    nbr->node_name, nh_nexthops_str(nbr_node_spf_data->nexthops));
            #endif
            /*If the nbr node is already present in PQ, remove it from PQ and it 
             * back so that it takes correct position in PQ as per new spf metric*/
            if(!IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){
                #if ISIS_SPF_LOGGING
                printf("root : %s : Event : Node %s Already On priority Queue\n",
                        spf_root->node_name, nbr->node_name);
                #endif
                remove_glthread(&nbr_node_spf_data->priority_thread_glue);
            }
            #if ISIS_SPF_LOGGING
            printf("root : %s : Event : Node %s inserted into priority Queue "
                        "with spf_metric = %u\n",
                         spf_root->node_name,  nbr->node_name, nbr_node_spf_data->spf_metric);
            #endif
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
        #if ISIS_SPF_LOGGING
            printf("root : %s : Event : Primary Nexthops Union of Current Node"
                    " %s(%s) with Nbr Node %s(%s)\n",
                    spf_root->node_name,  curr_node->node_name, 
                    nh_nexthops_str(curr_node_spf_data->nexthops),
                    nbr->node_name, nh_nexthops_str(nbr_node_spf_data->nexthops));
        #endif
            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);
        }
        /*Step 6.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(curr_node, nbr, oif, nxt_hop_ip);
        
    #if ISIS_SPF_LOGGING
    printf("root : %s : Event : Node %s has been processed, nexthops %s\n",
            spf_root->node_name, curr_node->node_name, 
            nh_nexthops_str(curr_node_spf_data->nexthops));
    #endif
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

static void
isis_compute_spf (node_t *spf_root){

    ted_node_t *node, *nbr;
    ted_node_t *ted_spf_root;
    glthread_t *curr;
    ted_intf_t *oif;
    uint32_t nxt_hop_ip;
    isis_spf_data_t *curr_spf_data;
    isis_spf_data_t *spf_root_spf_data = NULL;
    isis_spf_data_t *nbr_node_spf_data = NULL;
    isis_node_info_t *node_info = ISIS_NODE_INFO(spf_root);

    if (!isis_is_protocol_enable_on_node(spf_root)) {
        return;
    }

    ted_spf_root = ted_lookup_node(
                                node_info->ted_db,
                                tcp_ip_covert_ip_p_to_n (NODE_LO_ADDR(spf_root)));

    if (!ted_spf_root) return;

    #if ISIS_SPF_LOGGING
    printf("root : %s : Event : Running Spf\n", spf_root->node_name);
    #endif

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

        #if ISIS_SPF_LOGGING
        printf("root : %s : Event : Node %s taken out of priority queue\n",
                spf_root->node_name, curr_spf_data->node->node_name);
        #endif
        /* if the current node that is removed from PQ is spf root itself. 
         * Then No need to rcord the result. Process nbrs and put them in PQ*/
        if(curr_spf_data->node == ted_spf_root){

            ITERATE_TED_NODE_NBRS_BEGIN(curr_spf_data->node, nbr, oif, nxt_hop_ip){

                if(!ted_link_is_bidirectional(oif->link)) continue;
                
                nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);
                if(IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){
                    #if ISIS_SPF_LOGGING
                    printf("root : %s : Event : Processing Direct Nbr %s\n", 
                        spf_root->node_name, nbr->node_name);
                    #endif
                    glthread_priority_insert(&priority_lst, 
                            &nbr_node_spf_data->priority_thread_glue,
                            isis_spf_comparison_fn, 
                            isis_spf_data_offset_from_priority_thread_glue);

                    #if ISIS_SPF_LOGGING
                    printf("root : %s : Event : Direct Nbr %s added to priority Queue\n",
                            spf_root->node_name, nbr->node_name);
                    #endif
                }
            } ITERATE_NODE_NBRS_END(curr_spf_data->node, nbr, oif, nxt_hop_ip);

            #if ISIS_SPF_LOGGING
            printf("root : %s : Event : Root %s Processing Finished\n", 
                    spf_root->node_name, curr_spf_data->node->node_name);
            #endif
            continue;
        }
        /*Step 4 : End*/

        /*Step 5  : Begin
         *Record Result */
        isis_spf_record_result(ted_spf_root, curr_spf_data->node);
        /*Step 5  : End*/

        /*Step 6 : Begin */
        isis_spf_explore_nbrs(ted_spf_root, curr_spf_data->node, &priority_lst);
        /*Step 6 : End */
    }

    /*Step 7 : Begin*/ 
    /*Calculate final routing table from spf result of spf_root*/
    int count = isis_spf_install_routes(spf_root, ted_spf_root);
    /*Step 7 : End*/

    #if ISIS_SPF_LOGGING
    printf("root : %s : Event : Route Installation Count = %d\n", 
            spf_root->node_name, count);
    #endif
}

static void
isis_show_spf_results(node_t *node, ted_node_t *ted_node){

    int i = 0, j = 0;
    glthread_t *curr;
    interface_t *oif = NULL;
    isis_spf_result_t *res = NULL;
    isis_spf_data_t *node_spf_data = ISIS_NODE_SPF_DATA(ted_node);

    printf("\nSPF run results for node = %s\n", ted_node->node_name);

    ITERATE_GLTHREAD_BEGIN(&node_spf_data->spf_result_head, curr){
        
        res = isis_spf_res_glue_to_spf_result(curr);

        printf("DEST : %-10s spf_metric : %-6u", res->node->node_name, res->spf_metric);
        printf(" Nxt Hop : ");

        j = 0;

        for( i = 0; i < MAX_NXT_HOPS; i++, j++){

            if(!res->nexthops[i]) continue;

            oif = res->nexthops[i]->oif;
            if (!oif) {
                oif = node_get_intf_by_ifindex(node, res->nexthops[i]->ifindex);
            }

            if (j == 0){
                printf("OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name,
                        res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
            else{
                printf("                                              : "
                        "OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name,
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
isis_schedule_spf_job(node_t *node, isis_event_type_t event) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node) ||
         isis_is_reconciliation_in_progress(node)) {
        return;
    }
    
    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_spf_job_scheduled]);

    isis_add_new_spf_log(node, event);

    if (node_info->spf_job_task) {
        
        sprintf(tlb, "%s : spf job already scheduled\n", ISIS_SPF);
        tcp_trace(node, 0, tlb);
        return;
    }
    
    node_info->spf_job_task =
        task_create_new_job(EV(node), node, isis_run_spf, TASK_ONE_SHOT);
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
         printf("%d. %s  %s\n", i, ctime(&spf_log->timestamp), isis_event_str(spf_log->event));
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