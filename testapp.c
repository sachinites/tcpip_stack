/*
 * =====================================================================================
 *
 *       Filename:  testapp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  09/25/2021 04:02:39 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include "graph.h"
#include <stdio.h>
#include "CommandParser/libcli.h"

extern void init_tcp_ip_stack();

extern graph_t *build_first_topo();
extern graph_t *build_simple_l2_switch_topo();
extern graph_t *build_square_topo();
extern graph_t *build_linear_topo();
extern graph_t *build_dualswitch_topo();
extern graph_t *parallel_links_topology();
extern graph_t *cross_link_topology();

extern void nw_init_cli();

graph_t *topo = NULL;

int 
main(int argc, char **argv){

    nw_init_cli();
    topo = cross_link_topology();
    init_tcp_ip_stack();
    start_shell(); 
    return 0;
}
