/*
 * =====================================================================================
 *
 *       Filename:  graph.h
 *
 *    Description:  This file contains the definition of all structures required to create a NetworkGraph
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 02:17:17  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

/* Visit my Website for more wonderful assignments and projects :
 * https://csepracticals.wixsite.com/csepracticals
 * if above URL dont work, then try visit : https://csepracticals.com*/

#ifndef __GRAPH__
#define __GRAPH__

#include <assert.h>
#include "gluethread/glthread.h"


#define NODE_NAME_SIZE   16
#define IF_NAME_SIZE     16
#define MAX_INTF_PER_NODE   10

/*Forward Declarations*/
typedef struct node_ node_t;
typedef struct link_ link_t;


typedef struct interface_ {

    char if_name[IF_NAME_SIZE];
    struct node_ *att_node;
    struct link_ *link;
} interface_t;

struct link_ {

    interface_t intf1;
    interface_t intf2;
    unsigned int cost;
}; 

struct node_ {

    char node_name[NODE_NAME_SIZE];
    interface_t *intf[MAX_INTF_PER_NODE];
    glthread_t graph_glue;
};
GLTHREAD_TO_STRUCT(graph_glue_to_node, node_t, graph_glue);

typedef struct graph_{

    char topology_name[32];
    glthread_t node_list; 
} graph_t;

node_t *
create_graph_node(graph_t *graph, char *node_name);

graph_t *
create_new_graph(char *topology_name);

void
insert_link_between_two_nodes(node_t *node1, 
                             node_t *node2,
                             char *from_if_name, 
                             char *to_if_name, 
                             unsigned int cost);

/*Helper functions*/
static inline node_t *
get_nbr_node(interface_t *interface){

    assert(interface->att_node);
    assert(interface->link);
    
    link_t *link = interface->link;
    if(&link->intf1 == interface)
        return link->intf2.att_node;
    else
        return link->intf1.att_node;
}

static inline int
get_node_intf_available_slot(node_t *node){

    int i ;
    for( i = 0 ; i < MAX_INTF_PER_NODE; i++){
        if(node->intf[i])
            continue;
        return i;
    }
    return -1;
}

/*Display Routines*/
void dump_graph(graph_t *graph);
void dump_node(node_t *node);
void dump_interface(interface_t *interface);


#endif /* __NW_GRAPH_ */
