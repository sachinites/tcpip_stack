/*
 * =====================================================================================
 *
 *       Filename:  topologies.c
 *
 *    Description:  This file contains all topologies that we need to build
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 04:29:37  IST
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

#include "graph.h"
#include "Layer2/layer2.h"
#include "comm.h"
#include <unistd.h>

extern void
network_start_pkt_receiver_thread(graph_t *topo);

graph_t *
build_first_topo(){

#if 0

                          +----------+
                      0/4 |          |0/0
         +----------------+   R0_re  +---------------------------+
         |     40.1.1.1/24| 122.1.1.0|20.1.1.1/24                |
         |                +----------+                           |
         |                                                       |
         |                                                       |
         |                                                       |
         |40.1.1.2/24                                            |20.1.1.2/24
         |0/5                                                    |0/1
     +---+---+                                              +----+-----+
     |       |0/3                                        0/2|          |
     | R2_re +----------------------------------------------+    R1_re |
     |       |30.1.1.2/24                        30.1.1.1/24|          |
     +-------+                                              +----------+

#endif


    graph_t *topo = create_new_graph("Hello World Generic Graph");
    node_t *R0_re = create_graph_node(topo, "R0_re");
    node_t *R1_re = create_graph_node(topo, "R1_re");
    node_t *R2_re = create_graph_node(topo, "R2_re");

    insert_link_between_two_nodes(R0_re, R1_re, "eth0/0", "eth0/1", 1);
    insert_link_between_two_nodes(R1_re, R2_re, "eth0/2", "eth0/3", 1);
    insert_link_between_two_nodes(R0_re, R2_re, "eth0/4", "eth0/5", 1);

    node_set_device_type(R0_re, L3_ROUTER);
    node_set_loopback_address(R0_re, "122.1.1.0");
    node_set_intf_ip_address(R0_re, "eth0/4", "40.1.1.1", 24);
    node_set_intf_ip_address(R0_re, "eth0/0", "20.1.1.1", 24);
    
    node_set_device_type(R1_re, L3_ROUTER);
    node_set_loopback_address(R1_re, "122.1.1.1");
    node_set_intf_ip_address(R1_re, "eth0/1", "20.1.1.2", 24);
    node_set_intf_ip_address(R1_re, "eth0/2", "30.1.1.1", 24);

    node_set_device_type(R2_re, L3_ROUTER);
    node_set_loopback_address(R2_re, "122.1.1.2");
    node_set_intf_ip_address(R2_re, "eth0/3", "30.1.1.2", 24);
    node_set_intf_ip_address(R2_re, "eth0/5", "40.1.1.2", 24);

    network_start_pkt_receiver_thread(topo);

    sleep(2);

    /*Testing communication*/
    char data[32];
    strncpy(data, "test data\0", 32);
    interface_t *oif = get_node_if_by_name(R0_re, "eth0/0");
    assert(oif);
    printf("Msg to be sent is %s\n", data);
    send_pkt_out(data, strlen(data), oif);
    // while(1){
    // send_pkt_flood(R0_re, data, strlen(data));
    // send_pkt_flood(R1_re, data, strlen(data));
    // send_pkt_flood(R2_re, data, strlen(data));
    // }
    return topo;
}


graph_t *
build_linear_topo()
{
    graph_t *topo = create_new_graph("Linear Topo");
    node_t *H1 = create_graph_node(topo, "H1");
    node_t *H2 = create_graph_node(topo, "H2");
    node_t *H3 = create_graph_node(topo, "H3");

    insert_link_between_two_nodes(H1, H2, "eth0/1", "eth0/2", 1);
    insert_link_between_two_nodes(H2, H3, "eth0/3", "eth0/4", 1);

    node_set_loopback_address(H1, "122.1.1.1");
    node_set_intf_ip_address(H1, "eth0/1", "10.1.1.1", 24);
    node_set_intf_ip_address(H2, "eth0/2", "10.1.1.2", 24);
    
    
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_intf_ip_address(H2, "eth0/3", "20.1.1.1", 24);

   
    node_set_loopback_address(H3, "122.1.1.3");
    node_set_intf_ip_address(H3, "eth0/4", "20.1.1.2", 24);
    network_start_pkt_receiver_thread(topo);

}

graph_t *
build_simple_l2_switch_topo(){

#if 0             
                                       +-----------+
                                       |  H4       |
                                       | 122.1.1.4 |
                                       +----+------+
                                            |eth0/7 - 10.1.1.3/24       
                                            |       
                                            |eth0/1
                                       +----+----+                        +--------+
       +---------+                     |         |                        |        |
       |         |10.1.1.2/24          |   L2Sw  |eth0/2       10.1.1.1/24|  H3    |
       |  H1     +---------------------+         +------------------------+122.1.1.3|
       |122.1.1.1|eth0/5         eth0/4|         |                 eth0/6 |        |
       + --------+                     |         |                        |        |
                                       +----+----+                        +--------+
                                            |eth0/3     
                                            |
                                            |
                                            |
                                            |10.1.1.4/24
                                            |eth0/8
                                      +----++------+
                                      |            |
                                      |   H2       |
                                      |122.1.1.2   |
                                      |            |
                                      +------------+

#endif


    graph_t *topo = create_new_graph("Simple L2 Switch Demo graph");
    node_t *H1 = create_graph_node(topo, "H1");
    node_t *H2 = create_graph_node(topo, "H2");
    node_t *H3 = create_graph_node(topo, "H3");
    node_t *H4 = create_graph_node(topo, "H4");
    node_t *L2SW = create_graph_node(topo, "L2SW");

    insert_link_between_two_nodes(H1, L2SW, "eth0/5", "eth0/4", 1);
    insert_link_between_two_nodes(H2, L2SW, "eth0/8", "eth0/3", 1);
    insert_link_between_two_nodes(H3, L2SW, "eth0/6", "eth0/2", 1);
    insert_link_between_two_nodes(H4, L2SW, "eth0/7", "eth0/1", 1);

    node_set_loopback_address(H1, "122.1.1.1");
    node_set_intf_ip_address(H1, "eth0/5", "10.1.1.2", 24);
    
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_intf_ip_address(H2, "eth0/8", "10.1.1.4", 24);

    node_set_loopback_address(H3, "122.1.1.3");
    node_set_intf_ip_address(H3, "eth0/6", "10.1.1.1", 24);
    
    node_set_loopback_address(H4, "122.1.1.4");
    node_set_intf_ip_address(H4, "eth0/7", "10.1.1.3", 24);
    
    node_set_intf_l2_mode(L2SW, "eth0/1", ACCESS);
    node_set_intf_l2_mode(L2SW, "eth0/2", TRUNK);
    node_set_intf_l2_mode(L2SW, "eth0/3", ACCESS);
    node_set_intf_l2_mode(L2SW, "eth0/4", TRUNK);

    node_set_intf_vlan_membsership(L2SW, "eth0/1", 1);
    node_set_intf_vlan_membsership(L2SW, "eth0/2", 2);
    node_set_intf_vlan_membsership(L2SW, "eth0/3", 3);
    node_set_intf_vlan_membsership(L2SW, "eth0/4", 4);
    //network_start_pkt_receiver_thread(topo);

    return topo;
}

graph_t *
build_dualswitch_topo(){

#if 0
                                    +---------+                               +----------+
                                    |         |                               |          |
                                    |  H2     |                               |  H5      |
                                    |122.1.1.2|                               |122.1.1.5 |                                           
                                    +---+-----+                               +-----+----+                                           
                                        |10.1.1.2/24                                +10.1.1.5/24                                                
                                        |eth0/3                                     |eth0/8                                                
                                        |                                           |                                                
                                        |eth0/7,AC,V10                              |eth0/9,AC,V10                                                
                                  +-----+----+                                +-----+---+                                            
                                  |          |                                |         |                                            
   +------+---+                   |          |                                |         |                         +--------+         
   |  H1      |10.1.1.1/24        |   L2SW1  |eth0/5                    eth0/7| L2SW2   |eth0/10           eth0/11|  H6    |         
   |122.1.1.1 +-------------------|          |+-------------------------------|         +-------------+----------+122.1.1.6|         
   +------+---+ eth0/1      eth0/2|          |TR,V10,V11            TR,V10,V11|         |AC,V10        10.1.1.6/24|        |         
                            AC,V10|          |                                |         |                         +-+------+         
                                  +-----+----+                                +----+----+                                            
                                        |eth0/6                                    |eth0/12     
                                        |AC,V11                                    |AC,V11 
                                        |                                          |  
                                        |                                          |  
                                        |                                          |  
                                        |                                          |eth0/11
                                        |eth0/4                                    |10.1.1.4/24  
                                        |10.1.1.3/24                             +--+-----+
                                   +----+---+|                                   | H4     |
                                   |  H3     |                                   |        |
                                   |122.1.1.3|                                   |122.1.1.4|
                                   +--------+|                                   +--------+
#endif

    graph_t *topo = create_new_graph("Dual Switch Topo");
    node_t *H1 = create_graph_node(topo, "H1");
    node_set_loopback_address(H1, "122.1.1.1");
    node_t *H2 = create_graph_node(topo, "H2");
    node_set_loopback_address(H2, "122.1.1.2");
    node_t *H3 = create_graph_node(topo, "H3");
    node_set_loopback_address(H3, "122.1.1.3");
    node_t *H4 = create_graph_node(topo, "H4");
    node_set_loopback_address(H4, "122.1.1.4");
    node_t *H5 = create_graph_node(topo, "H5");

    node_set_loopback_address(H5, "122.1.1.5");
    node_t *H6 = create_graph_node(topo, "H6");
    node_set_loopback_address(H6, "122.1.1.6");
    node_t *L2SW1 = create_graph_node(topo, "L2SW1");
    node_t *L2SW2 = create_graph_node(topo, "L2SW2");
    
    insert_link_between_two_nodes(H1, L2SW1, "eth0/1", "eth0/2", 1);
    insert_link_between_two_nodes(H2, L2SW1, "eth0/3", "eth0/7", 1);
    insert_link_between_two_nodes(H3, L2SW1, "eth0/4", "eth0/6", 1);
    insert_link_between_two_nodes(L2SW1, L2SW2, "eth0/5", "eth0/7", 1);
    insert_link_between_two_nodes(H5, L2SW2, "eth0/8", "eth0/9", 1);
    insert_link_between_two_nodes(H4, L2SW2, "eth0/11", "eth0/12", 1);
    insert_link_between_two_nodes(H6, L2SW2, "eth0/11", "eth0/10", 1);

    node_set_intf_ip_address(H1, "eth0/1",  "10.1.1.1", 24);
    node_set_intf_ip_address(H2, "eth0/3",  "10.1.1.2", 24);
    node_set_intf_ip_address(H3, "eth0/4",  "10.1.1.3", 24);
    node_set_intf_ip_address(H4, "eth0/11", "10.1.1.4", 24);
    node_set_intf_ip_address(H5, "eth0/8",  "10.1.1.5", 24);
    node_set_intf_ip_address(H6, "eth0/11", "10.1.1.6", 24);

    node_set_intf_l2_mode(L2SW1, "eth0/2", ACCESS);
    node_set_intf_vlan_membsership(L2SW1, "eth0/2", 10);
    node_set_intf_l2_mode(L2SW1, "eth0/7", ACCESS);
    node_set_intf_vlan_membsership(L2SW1, "eth0/7", 10);
    node_set_intf_l2_mode(L2SW1, "eth0/5", TRUNK);
    node_set_intf_vlan_membsership(L2SW1, "eth0/5", 10);
    node_set_intf_vlan_membsership(L2SW1, "eth0/5", 11);
    node_set_intf_l2_mode(L2SW1, "eth0/6", ACCESS);
    node_set_intf_vlan_membsership(L2SW1, "eth0/6", 11);

    node_set_intf_l2_mode(L2SW2, "eth0/7", TRUNK);
    node_set_intf_vlan_membsership(L2SW2, "eth0/7", 10);
    node_set_intf_vlan_membsership(L2SW2, "eth0/7", 11);
    node_set_intf_l2_mode(L2SW2, "eth0/9", ACCESS);
    node_set_intf_vlan_membsership(L2SW2, "eth0/9", 10);
    node_set_intf_l2_mode(L2SW2, "eth0/10", ACCESS);
    node_set_intf_vlan_membsership(L2SW2, "eth0/10", 10);
    node_set_intf_l2_mode(L2SW2, "eth0/12", ACCESS);
    node_set_intf_vlan_membsership(L2SW2, "eth0/12", 11);

    network_start_pkt_receiver_thread(topo);

    return topo;
}

