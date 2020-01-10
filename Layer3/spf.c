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
#include <stdint.h>
#include "../LinkedList/LinkedListApi.h"
#include "../graph.h"

#define INFINITE_METRIC     0xFFFFFFFF
#define MAX_NXT_HOPS        4

typedef struct spf_data_{

    ll_t *spf_result;
    glthread_t priority_thread_glue;

    /*Temp fields used for calculations*/
    uint32_t spf_metric;
} spf_data_t;

typedef struct nexthop_{

    char gw_ip[16];
    interface_t *oif;
    uint32_t ref_count;
} nexthop_t;

typedef struct spf_result_{

    node_t *node;
    uint32_t spf_metric;
    nexthop_t *nexthops[MAX_NXT_HOPS];
} spf_result_t;

static inline bool_t
is_nexthop_empty(nexthop_t *nexthop){

    return nexthop->oif == NULL;
}

static void
spf_result_delete_nexthops(spf_result_t *spf_result){

    int i  = 0;
    for( ; i < MAX_NXT_HOPS; i++){
        if(spf_result->nexthops[i]){
            spf_result->nexthops[i]->ref_count--;
            if(spf_result->nexthops[i]->ref_count == 0){
                free(spf_result->nexthops[i]);
                spf_result->nexthops[i] = NULL;
            }
        }
    }
}

static void
free_spf_result(spf_result_t *spf_result){

    spf_result_delete_nexthops(spf_result);
    free(spf_result);
}

static void
init_node_spf_data(node_t *node){

    if(!spf_root->spf_data){
        spf_root->spf_data = calloc(1, sizeof(spf_data_t));
        spf_root->spf_data->spf_result = init_singly_ll();
    }
    else{
        singly_ll_node_t *list_node;
        ITERATE_LIST_BEGIN(spf_root->spf_data->spf_result, list_node){

            spf_result_t *res = list_node->data;
            free_spf_result(res);
        } ITERATE_LIST_END;
        delete_singly_ll(spf_root->spf_data->spf_result);
    }

    remove_glthread(&spf_root->spf_data->priority_thread_glue);
    node->spf_data->spf_metric = INFINITE_METRIC;
}

static void
init_spf(node_t *spf_root){

    node_t *node;

    init_node_spf_data(spf_root);
    spf_root->spf_data->spf_metric = 0;

    /*Iterate all Routers in the graph and initialize the requiref fields*/
    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

        node = graph_glue_to_node(curr);
        if(node == spf_root) continue;
        node->spf_data->spf_metric = INFINITE_METRIC;
    } ITERATE_GLTHREAD_END(&graph->node_list, curr);
}
