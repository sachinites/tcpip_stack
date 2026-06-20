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
#include <stdlib.h> 
#include <rte_eal.h>
#include "router_init.h"
#include "CLIBuilder/libcli.h"
#include "libs/EventDispatcher/event_dispatcher.h"

extern void init_tcp_ip_stack();

extern graph_t *build_first_topo(void);
extern graph_t *build_simple_l2_switch_topo(void);
extern graph_t *build_square_topo(void);
extern graph_t *build_linear_topo(void);
extern graph_t *build_dualswitch_topo(void);
extern graph_t *parallel_links_topology(void);
extern graph_t *cross_link_topology(void);
extern graph_t *standalone_node_topology(void);
extern graph_t *vlan_extension_topo(void);
extern graph_t *build_inter_vlan_routing_topo(void);
extern graph_t *build_vxlan_topo(void);
extern graph_t *evpn_spine_leaf(void) ;
extern graph_t *Linux_Router_topology(void) ;

extern void nw_init_cli();
extern void std_lib_init (int (*)(const char *format, ...)) ;

/* Memory Init Imports */
extern void mm_init();

/* Layer 5*/

graph_t *topo = NULL;
extern event_dispatcher_t gev_dis;
extern int cprintf (const char* format, ...) ;
extern bool LinuxRtr;

static void
tcp_ip_stack_pre_topology_create_initializations(void) {

    nw_init_cli();
    mm_init();

    srand((unsigned int) time(NULL));

    /* Initialize the Scheduler before topology creation, as node
        can fire certain jobs during initialization as well */
    event_dispatcher_init(&gev_dis, "Global");
}

int 
main(int argc, char **argv){
    
    (void )argc; (void) argv;

    rte_eal_init(argc, argv);

    libcli_init ();
    std_lib_init(cprintf);

    tcp_ip_stack_pre_topology_create_initializations();

    topo = LinuxRtr ? Linux_Router_topology() : \
                      build_dualswitch_topo();
                      
    init_tcp_ip_stack();
    libcli_init_done ();
    cli_start_shell(); 

    /* Never Reach here */
    rte_eal_cleanup();

    return 0;
}
