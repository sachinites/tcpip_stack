/*
 * =====================================================================================
 *
 *       Filename:  testapp.c
 *
 *    Description:  This file represents the Test application to test graph topology creation
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 04:41:41  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2017), Current : Juniper Networks(Apr 2017 - Present)
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
 * www.csepracticals.com
 * if above URL dont work, then try visit : https://www.csepracticals.com*/

#include <stdio.h>
#include "graph.h"
#include "CLIBuilder/libcli.h"
#include "EventDispatcher/event_dispatcher.h"

extern void init_tcp_ip_stack();

extern graph_t *build_first_topo(void);
extern graph_t *build_simple_l2_switch_topo(void);
extern graph_t *build_square_topo(void);
extern graph_t *build_linear_topo(void);
extern graph_t *build_dualswitch_topo(void);
extern graph_t *parallel_links_topology(void);
extern graph_t *cross_link_topology(void);
extern graph_t *standalone_node_topology(void);

extern void nw_init_cli();

/* Memory Init Imports */
extern void mm_init();
extern void nfc_mem_init ();
extern void event_dispatcher_mem_init(); 
extern void layer2_mem_init();
extern void layer3_mem_init();
extern void layer4_mem_init();
/* Layer 5*/
extern void spf_algo_mem_init(); 
extern void isis_mem_init();
extern void ted_mem_init();
extern void tcp_stack_miscellaneous_mem_init();

graph_t *topo = NULL;
extern event_dispatcher_t gev_dis;

static void
tcp_ip_stack_pre_topology_create_initializations(void) {

    nw_init_cli();
    mm_init();
    nfc_mem_init();
    event_dispatcher_mem_init();
    layer2_mem_init();
    layer3_mem_init();
    layer4_mem_init();
    spf_algo_mem_init();
    isis_mem_init();
    ted_mem_init();
    /* Initialize the Scheduler before topology creation, as node
        can fire certain jobs during initialization as well */
    event_dispatcher_init(&gev_dis, "Global");
    tcp_stack_miscellaneous_mem_init();
}

int 
main(int argc, char **argv){
    
    (void )argc; (void) argv;
    libcli_init ();
    tcp_ip_stack_pre_topology_create_initializations();
    topo = build_dualswitch_topo();
    init_tcp_ip_stack();
    libcli_init_done ();
    cli_start_shell(); 
    return 0;
}
