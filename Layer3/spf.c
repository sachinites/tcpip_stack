/*
 * =====================================================================================
 *
 *       Filename:  spf.c
 *
 *    Description:  This file implements the routing table construction algorithm
 *
 *        Version:  1.0
 *        Created:  01/09/2020 10:49:45 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the TCPIP-STACK distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 *        Public License as published by the Free Software Foundation, version 3.
 *        
 *        This program is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *        General Public License for more details.
 *
 *        visit website : https://csepracticals.wixsite.com/csepracticals for more courses and projects
 *                                  
 * =====================================================================================
 */
#include <stdio.h>
#include <stdint.h>
#include "../utils.h"
#include "../gluethread/glthread.h"
#include "../graph.h"
#include "../net.h"
#include "../CommandParser/libcli.h"
#include "../CommandParser/cmdtlv.h"
#include "../cmdcodes.h"
#include "layer3.h"

#define INFINITE_METRIC     0xFFFFFFFF

#define SPF_METRIC(nodeptr) (nodeptr->spf_data->spf_metric)

/*Import global variable*/
extern graph_t *topo;

typedef struct spf_data_{

    /*Final spf result stored in this
     * list*/
    node_t *node; /*back pointer to owning node*/
    glthread_t spf_result_head;

    /*Temp fields used for calculations*/
    uint32_t spf_metric;
    glthread_t priority_thread_glue;
    nexthop_t *nexthops[MAX_NXT_HOPS];
} spf_data_t;
GLTHREAD_TO_STRUCT(priority_thread_glue_to_spf_data, 
    spf_data_t, priority_thread_glue);

#define spf_data_offset_from_priority_thread_glue \
    ((size_t)&(((spf_data_t *)0)->priority_thread_glue))

typedef struct spf_result_{

    node_t *node;
    uint32_t spf_metric;
    nexthop_t *nexthops[MAX_NXT_HOPS];
    glthread_t spf_res_glue;
} spf_result_t;
GLTHREAD_TO_STRUCT(spf_res_glue_to_spf_result, 
    spf_result_t, spf_res_glue);

static inline bool_t
is_nexthop_empty(nexthop_t *nexthop){

    return nexthop->oif == NULL;
}

void
spf_flush_nexthops(nexthop_t **nexthop){

    int i = 0;

    if(!nexthop) return;

    for( ; i < MAX_NXT_HOPS; i++){

        if(nexthop[i]){
            assert(nexthop[i]->ref_count);
            nexthop[i]->ref_count--;
            if(nexthop[i]->ref_count == 0){
                free(nexthop[i]);
            }
            nexthop[i] = NULL;
        }
    }
}

static inline void
free_spf_result(spf_result_t *spf_result){

    spf_flush_nexthops(spf_result->nexthops);
    remove_glthread(&spf_result->spf_res_glue);
    free(spf_result);
}

static void
init_node_spf_data(node_t *node, bool_t delete_spf_result){

    if(!node->spf_data){
        node->spf_data = calloc(1, sizeof(spf_data_t));
        init_glthread(&node->spf_data->spf_result_head);
        node->spf_data->node = node;
    }
    else if(delete_spf_result){

        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&node->spf_data->spf_result_head, curr){

            spf_result_t *res = spf_res_glue_to_spf_result(curr);
            free_spf_result(res);
        } ITERATE_GLTHREAD_END(&node->spf_data->spf_result_head, curr);
        init_glthread(&node->spf_data->spf_result_head);
    }

    SPF_METRIC(node) = INFINITE_METRIC;
    remove_glthread(&node->spf_data->priority_thread_glue);
    spf_flush_nexthops(node->spf_data->nexthops);
}

static nexthop_t *
create_new_nexthop(interface_t *oif){

    nexthop_t *nexthop = calloc(1, sizeof(nexthop_t));
    nexthop->oif = oif;
    interface_t *other_intf = &oif->link->intf1 == oif ?    \
        &oif->link->intf2 : &oif->link->intf1;
    if(!other_intf){
        free(nexthop);
        return NULL;
    }

    strncpy(nexthop->gw_ip, IF_IP(other_intf), 16);
    nexthop->ref_count = 0;
    return nexthop;
}

static bool_t 
spf_insert_new_nexthop(nexthop_t **nexthop_arry, 
                       nexthop_t *nxthop){

    int i = 0;

    for( ; i < MAX_NXT_HOPS; i++){
        if(nexthop_arry[i]) continue;
        nexthop_arry[i] = nxthop;
        nexthop_arry[i]->ref_count++;
        return TRUE;
    }
    return FALSE;
}

static bool_t
spf_is_nexthop_exist(nexthop_t **nexthop_array, nexthop_t *nxthop){

    int i = 0;
    for( ; i < MAX_NXT_HOPS; i++){
        
        if(!nexthop_array[i])
            return FALSE;

        if(nexthop_array[i]->oif == nxthop->oif)
            return TRUE;
    }
    return FALSE;
}

/*Copy all nexthops of src to dst, do not copy which are already
 * present*/
static int
spf_union_nexthops_arrays(nexthop_t **src, nexthop_t **dst){

    int i = 0;
    int j = 0;
    int copied_count = 0;

    while(j < MAX_NXT_HOPS && dst[j]){
        j++;
    }

    if(j == MAX_NXT_HOPS) return 0;

    for(; i < MAX_NXT_HOPS && j < MAX_NXT_HOPS; i++, j++){

        if(src[i] && spf_is_nexthop_exist(dst, src[i]) == FALSE){
            dst[j] = src[i];
            dst[j]->ref_count++;
            copied_count++;
        }
    }
    return copied_count;
}

static int 
spf_comparison_fn(void *data1, void *data2){

    spf_data_t *spf_data_1 = (spf_data_t *)data1;
    spf_data_t *spf_data_2 = (spf_data_t *)data2;

    if(spf_data_1->spf_metric < spf_data_2->spf_metric)
        return -1;
    if(spf_data_1->spf_metric > spf_data_2->spf_metric)
        return 1;
    return 0;
}

static spf_result_t *
spf_lookup_spf_result_by_node(node_t *spf_root, node_t *node){

    glthread_t *curr;
    spf_result_t *spf_result;
    spf_data_t *curr_spf_data;

    ITERATE_GLTHREAD_BEGIN(&spf_root->spf_data->spf_result_head, curr){

        spf_result = spf_res_glue_to_spf_result(curr);
        if(spf_result->node == node)
            return spf_result;
    } ITERATE_GLTHREAD_END(&spf_root->spf_data->spf_result_head, curr);
    return NULL;
}

static char *
nexthops_str(nexthop_t **nexthops){

    static char buffer[256];
    memset(buffer, 0 , 256);

    int i = 0;

    for( ; i < MAX_NXT_HOPS; i++){

        if(!nexthops[i]) continue;
        snprintf(buffer, 256, "%s ", nexthop_node_name(nexthops[i]));
    }
    return buffer;
}

static int
spf_install_routes(node_t *spf_root){

    rt_table_t *rt_table = 
        NODE_RT_TABLE(spf_root);

    /*Clear all routes except direct routes*/
    clear_rt_table(rt_table);

    /* Now iterate over result list and install routes for
     * loopback address of all routers*/

    int i = 0;
    int count = 0; /*no of routes installed*/
    glthread_t *curr;
    spf_result_t *spf_result;
    nexthop_t *nexthop = NULL;

    ITERATE_GLTHREAD_BEGIN(&spf_root->spf_data->spf_result_head, curr){

        spf_result = spf_res_glue_to_spf_result(curr);
        for(i = 0; i < MAX_NXT_HOPS; i++){
            nexthop = spf_result->nexthops[i];
            if(!nexthop) continue;
            rt_table_add_route(rt_table, NODE_LO_ADDR(spf_result->node), 32, 
                    nexthop->gw_ip, nexthop->oif);
            count++;
        }
    } ITERATE_GLTHREAD_END(&spf_root->spf_data->spf_result_head, curr);
    return count;
}

#define SPF_LOGGING 0

void
compute_spf(node_t *spf_root){

    node_t *node;
    glthread_t *curr;
    spf_data_t *curr_spf_data;

    #if SPF_LOGGING
    printf("root : %s : Event : Running Spf\n", spf_root->node_name);
    #endif

    init_node_spf_data(spf_root, TRUE);
    SPF_METRIC(spf_root) = 0;

    /*Iterate all Routers in the graph and initialize the requiref fields*/
    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        if(node == spf_root) continue;
        init_node_spf_data(node, FALSE);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);


    /*Initialize direct nbrs*/
    node_t *nbr = NULL;
    char *nxt_hop_ip = NULL;
    interface_t *oif = NULL;
    nexthop_t *nexthop = NULL;

    ITERATE_NODE_NBRS_BEGIN(spf_root, nbr, oif, nxt_hop_ip){

        if(!is_interface_l3_bidirectional(oif)) continue;

        if(get_link_cost(oif) < SPF_METRIC(nbr)){
            spf_flush_nexthops(nbr->spf_data->nexthops);
            nexthop = create_new_nexthop(oif);
            spf_insert_new_nexthop(nbr->spf_data->nexthops, nexthop);
            SPF_METRIC(nbr) = get_link_cost(oif);
        }
        else if(get_link_cost(oif) == SPF_METRIC(nbr)){
            nexthop = create_new_nexthop(oif);
            spf_insert_new_nexthop(nbr->spf_data->nexthops, nexthop);
        }
    } ITERATE_NODE_NBRS_END(spf_root, nbr, oif, nxt_hop_ip);


    glthread_t priority_lst;
    init_glthread(&priority_lst); 

    glthread_priority_insert(&priority_lst, 
            &spf_root->spf_data->priority_thread_glue,
            spf_comparison_fn, 
            spf_data_offset_from_priority_thread_glue);

    while(!IS_GLTHREAD_LIST_EMPTY(&priority_lst)){

        curr = dequeue_glthread_first(&priority_lst);
        curr_spf_data = priority_thread_glue_to_spf_data(curr);

        #if SPF_LOGGING
        printf("root : %s : Event : Node %s taken out of priority queue\n",
                spf_root->node_name, curr_spf_data->node->node_name);
        #endif
        /* if the current node is spf root itself. No need to rcord the result.
         * Process nbrs*/
        if(curr_spf_data->node == spf_root){

            ITERATE_NODE_NBRS_BEGIN(curr_spf_data->node, nbr, oif, nxt_hop_ip){

                if(!is_interface_l3_bidirectional(oif)) continue;
                #if SPF_LOGGING
                printf("root : %s : Event : Processing Direct Nbr %s\n", 
                        spf_root->node_name, nbr->node_name);
                #endif
                assert(IS_GLTHREAD_LIST_EMPTY(&nbr->spf_data->priority_thread_glue));
                glthread_priority_insert(&priority_lst, 
                        &nbr->spf_data->priority_thread_glue,
                        spf_comparison_fn, 
                        spf_data_offset_from_priority_thread_glue);
                #if SPF_LOGGING
                printf("root : %s : Event : Direct Nbr %s added to priority Queue\n",
                        spf_root->node_name, nbr->node_name);
                #endif
            }ITERATE_NODE_NBRS_END(curr_spf_data->node, nbr, oif, nxt_hop_ip);
            #if SPF_LOGGING
            printf("root : %s : Event : Root %s Processing Finished\n", 
                    spf_root->node_name, curr_spf_data->node->node_name);
            #endif
            continue;
        }

        /*Record result*/
        assert(!spf_lookup_spf_result_by_node(spf_root, curr_spf_data->node));
        spf_result_t *spf_result = calloc(1, sizeof(spf_result_t));
        spf_result->node = curr_spf_data->node;
        spf_result->spf_metric = curr_spf_data->spf_metric;
        spf_union_nexthops_arrays(curr_spf_data->nexthops,
                spf_result->nexthops);
        #if SPF_LOGGING
        printf("root : %s : Event : Result Recorded for node %s, Next hops : %s, spf_metric = %u\n",
                spf_root->node_name, curr_spf_data->node->node_name, nexthops_str(spf_result->nexthops),
                spf_result->spf_metric);
        #endif
        init_glthread(&spf_result->spf_res_glue);
        glthread_add_next(&spf_root->spf_data->spf_result_head,
                &spf_result->spf_res_glue);

        #if SPF_LOGGING
        printf("root : %s : Event : Nbr Exploration Start for Node : %s\n",
                spf_root->node_name, curr_spf_data->node->node_name);
        #endif
        ITERATE_NODE_NBRS_BEGIN(curr_spf_data->node, nbr, oif, nxt_hop_ip){
            #if SPF_LOGGING
            printf("root : %s : Event : For Node %s , Processing nbr %s\n",
                    spf_root->node_name, curr_spf_data->node->node_name, 
                    nbr->node_name);
            printf("root : %s : Event : Testing Inequality : " 
                    " spf_metric(%s, %u) + link cost(%u) < spf_metric(%s, %u)\n",
                    spf_root->node_name, curr_spf_data->node->node_name, 
                    curr_spf_data->spf_metric, 
                    get_link_cost(oif), nbr->node_name, nbr->spf_data->spf_metric);
            #endif

            if(SPF_METRIC(curr_spf_data->node) + get_link_cost(oif) < 
                    SPF_METRIC(nbr)){

                #if SPF_LOGGING
                printf("root : %s : Event : For Node %s , Primary Nexthops Flushed\n",
                        spf_root->node_name, nbr->node_name);
                #endif
                spf_flush_nexthops(nbr->spf_data->nexthops);
                spf_union_nexthops_arrays(curr_spf_data->nexthops,
                        nbr->spf_data->nexthops);
                SPF_METRIC(nbr) = SPF_METRIC(curr_spf_data->node) + get_link_cost(oif);
                
                #if SPF_LOGGING
                printf("root : %s : Event : Primary Nexthops Copied from Node %s to Node %s, Next hops : %s\n",
                        spf_root->node_name, curr_spf_data->node->node_name, nbr->node_name, nexthops_str(nbr->spf_data->nexthops));
                #endif
                if(!IS_GLTHREAD_LIST_EMPTY(&nbr->spf_data->priority_thread_glue)){
                    #if SPF_LOGGING
                    printf("root : %s : Event : Node %s Already On priority Queue\n",
                            spf_root->node_name, nbr->node_name);
                    #endif
                    remove_glthread(&nbr->spf_data->priority_thread_glue);
                }
                #if SPF_LOGGING
                printf("root : %s : Event : Node %s inserted into priority Queue with spf_metric = %u\n",
                        spf_root->node_name,  nbr->node_name, nbr->spf_data->spf_metric);
                #endif
                glthread_priority_insert(&priority_lst, 
                        &nbr->spf_data->priority_thread_glue,
                        spf_comparison_fn, 
                        spf_data_offset_from_priority_thread_glue);
            }
            else if(SPF_METRIC(curr_spf_data->node) + get_link_cost(oif) == 
                    SPF_METRIC(nbr)){
                #if SPF_LOGGING
                printf("root : %s : Event : Primary Nexthops Union of Current Node"
                        " %s(%s) with Nbr Node %s(%s)\n",
                        spf_root->node_name,  curr_spf_data->node->node_name, 
                        nexthops_str(curr_spf_data->nexthops),
                        nbr->node_name, nexthops_str(nbr->spf_data->nexthops));
                #endif
                spf_union_nexthops_arrays(curr_spf_data->nexthops,
                        nbr->spf_data->nexthops);
            }
        } ITERATE_NODE_NBRS_END(curr_spf_data->node, nbr, oif, nxt_hop_ip);
        spf_flush_nexthops(curr_spf_data->nexthops);
        #if SPF_LOGGING
        printf("root : %s : Event : Node %s has been processed, nexthops %s",
                spf_root->node_name, curr_spf_data->node->node_name, 
                nexthops_str(curr_spf_data->nexthops));
        #endif
    } 
    int count = spf_install_routes(spf_root);
    #if SPF_LOGGING
    printf("root : %s : Event : Route Installation Count = %d\n", 
            spf_root->node_name, count);
    #endif
}

static void
show_spf_results(node_t *node){

    int i = 0, j = 0;
    glthread_t *curr;
    interface_t *oif = NULL;
    spf_result_t *res = NULL;

    printf("\nSPF run results for node = %s\n", node->node_name);

    ITERATE_GLTHREAD_BEGIN(&node->spf_data->spf_result_head, curr){
        
        res = spf_res_glue_to_spf_result(curr);

        printf("DEST : %-10s spf_metric : %-6u", res->node->node_name, res->spf_metric);
        printf(" Nxt Hop : ");

        j = 0;

        for( i = 0; i < MAX_NXT_HOPS; i++, j++){

            if(!res->nexthops[i]) continue;

            oif = res->nexthops[i]->oif;
            if(j == 0){
                printf("%-8s       OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        nexthop_node_name(res->nexthops[i]),
                        oif->if_name, res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
            else{
                printf("                                              : "
                        "%-8s       OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        nexthop_node_name(res->nexthops[i]),
                        oif->if_name, res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
        }
    }ITERATE_GLTHREAD_END(&node->spf_data->spf_result_head, curr)
}

int
show_spf_results_handler(param_t *param, ser_buff_t *tlv_buf, 
                         op_mode enable_or_disable){

    int CMDCODE;
    node_t *node;
    char *node_name;
    tlv_struct_t *tlv = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

    switch(CMDCODE){
        case CMDCODE_SHOW_SPF_RESULTS:
            show_spf_results(node);        
            break;
        default:
            break;
    }

    return 0;
}

void
compute_spf_all_routers(graph_t *topo){

    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node_t *node = graph_glue_to_node(curr);
        compute_spf(node);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
}
