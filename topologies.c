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
 * www.csepracticals.com
 * if above URL dont work, then try visit : https://www.csepracticals.com*/

#include "utils.h"
#include "graph.h"
#include "comm.h"
#include "Layer2/layer2.h"
#include "Interface/InterfaceUApi.h"

graph_t *build_first_topo(void);
graph_t *build_simple_l2_switch_topo(void);
graph_t *build_square_topo(void);
graph_t *build_linear_topo(void);
graph_t *build_dualswitch_topo(void);
graph_t *parallel_links_topology(void);
graph_t *cross_link_topology(void);
graph_t *standalone_node_topology(void);
graph_t *vlan_extension_topo(void);

graph_t *standalone_node_topology(void) {

    graph_t *topo = create_new_graph("Stand-Alone Topo");
    node_t *R0 = create_graph_node(topo, (const c_string)"R0");
    node_set_loopback_address(R0, "122.1.1.1");
    return topo;
    node_t *R1 = create_graph_node(topo, (const c_string)"R1");
    node_set_loopback_address(R1, "122.1.1.2");
    insert_link_between_two_nodes(R0, R1, "eth0", "eth0", 10);
    node_set_intf_ip_address(R0, "eth0", "10.1.1.1", 24);
    node_set_intf_ip_address(R1, "eth0", "10.1.1.2", 24);
    return topo;
}

graph_t *
build_first_topo(void){

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
    node_t *R0_re = create_graph_node(topo, (const c_string)"R0_re");
    node_t *R1_re = create_graph_node(topo, (const c_string)"R1_re");
    node_t *R2_re = create_graph_node(topo, (const c_string)"R2_re");

    insert_link_between_two_nodes(R0_re, R1_re, "eth0", "eth1", 5);
    insert_link_between_two_nodes(R1_re, R2_re, "eth2", "eth3", 4);
    insert_link_between_two_nodes(R0_re, R2_re, "eth4", "eth5", 9);

    node_set_loopback_address(R0_re, "122.1.1.0");

    node_set_intf_ip_address(R0_re, "eth4", "40.1.1.1", 24);
    node_set_intf_ip_address(R0_re, "eth0", "20.1.1.1", 24);
    
    node_set_loopback_address(R1_re, "122.1.1.1");

    node_set_intf_ip_address(R1_re, "eth1", "20.1.1.2", 24);
    node_set_intf_ip_address(R1_re, "eth2", "30.1.1.1", 24);

    node_set_loopback_address(R2_re, "122.1.1.2");

    node_set_intf_ip_address(R2_re, "eth3", "30.1.1.2", 24);
    node_set_intf_ip_address(R2_re, "eth5", "40.1.1.2", 24);

    return topo;
}

graph_t *
build_inter_vlan_routing_topo(void){

#if 0             
                                       +-----------+
                                       |  H4       |
                                       | 122.1.1.4 |
                                       +----+------+
                                            |eth0/7 - 13.1.1.2/24       
                                            |
				            |
				            |v13	    
                                            |eth0/1
                                       +----+----+                        +--------+
       +---------+                     |         |                        |        |
       |         |10.1.1.2/24          |   L3SW  |eth0/2       12.1.1.2/24|  H3    |
       |  H1     +---------------------+         +------------------------+122.1.1.3|
       |122.1.1.1|eth0/5         eth0/4|         | v12             eth0/6 |        |
       + --------+                v10  |         |                        |        |
                                       +----+----+                        +--------+
                                            |eth0/3     
                                            | v11
                                            |
                                            |
                                            |11.1.1.2/24
                                            |eth0/8
                                      +----++------+
                                      |            |
                                      |   H2       |
                                      |122.1.1.2   |
                                      |            |
                                      +------------+


Configs :
==========
config node H1 route 0.0.0.0 0 10.1.1.1 eth5
config node H2 route 0.0.0.0 0 11.1.1.1 eth8
config node H3 route 0.0.0.0 0 12.1.1.1 eth6
config node H4 route 0.0.0.0 0 13.1.1.1 eth7
config node L3SW interface vlan 10 ip-address 10.1.1.1 24
config node L3SW interface vlan 11 ip-address 11.1.1.1 24
config node L3SW interface vlan 12 ip-address 12.1.1.1 24
config node L3SW interface vlan 13 ip-address 13.1.1.1 24

Test
====
run node H1 ping 10.1.1.1
run node H1 ping 11.1.1.1
run node H1 ping 12.1.1.1
run node H1 ping 13.1.1.1
run node H1 ping 11.1.1.2
run node H1 ping 12.1.1.2
run node H1 ping 13.1.1.2

#endif


    graph_t *topo = create_new_graph("Inter Vlan Routing Topology");
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");
    node_t *H3 = create_graph_node(topo, (const c_string)"H3");
    node_t *H4 = create_graph_node(topo, (const c_string)"H4");
    node_t *L3SW = create_graph_node(topo, (const c_string)"L3SW");

    insert_link_between_two_nodes(H1, L3SW, "eth5", "eth4", 1);
    insert_link_between_two_nodes(H2, L3SW, "eth8", "eth3", 1);
    insert_link_between_two_nodes(H3, L3SW, "eth6", "eth2", 1);
    insert_link_between_two_nodes(H4, L3SW, "eth7", "eth1", 1);

    node_set_loopback_address(H1, "122.1.1.1");
    node_set_intf_ip_address(H1, "eth5", "10.1.1.2", 24);
    
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_intf_ip_address(H2, "eth8", "11.1.1.2", 24);

    node_set_loopback_address(H3, "122.1.1.3");
    node_set_intf_ip_address(H3, "eth6", "12.1.1.2", 24);
    
    node_set_loopback_address(H4, "122.1.1.4");
    node_set_intf_ip_address(H4, "eth7", "13.1.1.2", 24);
    
    node_set_intf_switchport(L3SW, "eth1");
    node_set_intf_switchport(L3SW, "eth2");
    node_set_intf_switchport(L3SW, "eth3");
    node_set_intf_switchport(L3SW, "eth4");

    node_set_intf_vlan_membership(L3SW, "eth1", 13, false);
    node_set_intf_vlan_membership(L3SW, "eth2", 12, false);
    node_set_intf_vlan_membership(L3SW, "eth3", 11, false);
    node_set_intf_vlan_membership(L3SW, "eth4", 10, false);
    return topo;
}


graph_t *
build_simple_l2_switch_topo(void){

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
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");
    node_t *H3 = create_graph_node(topo, (const c_string)"H3");
    node_t *H4 = create_graph_node(topo, (const c_string)"H4");
    node_t *L2SW = create_graph_node(topo, (const c_string)"L2SW");

    insert_link_between_two_nodes(H1, L2SW, "eth5", "eth4", 1);
    insert_link_between_two_nodes(H2, L2SW, "eth8", "eth3", 1);
    insert_link_between_two_nodes(H3, L2SW, "eth6", "eth2", 1);
    insert_link_between_two_nodes(H4, L2SW, "eth7", "eth1", 1);

    node_set_loopback_address(H1, "122.1.1.1");
    node_set_intf_ip_address(H1, "eth5", "10.1.1.2", 24);
    
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_intf_ip_address(H2, "eth8", "10.1.1.4", 24);

    node_set_loopback_address(H3, "122.1.1.3");
    node_set_intf_ip_address(H3, "eth6", "10.1.1.1", 24);
    
    node_set_loopback_address(H4, "122.1.1.4");
    node_set_intf_ip_address(H4, "eth7", "10.1.1.3", 24);
    
    node_set_intf_switchport(L2SW, "eth1");
    node_set_intf_switchport(L2SW, "eth2");
    node_set_intf_switchport(L2SW, "eth3");
    node_set_intf_switchport(L2SW, "eth4");

    node_set_intf_vlan_membership(L2SW, "eth1", 10, false);
    node_set_intf_vlan_membership(L2SW, "eth2", 10, false);
    node_set_intf_vlan_membership(L2SW, "eth3", 10, false);
    node_set_intf_vlan_membership(L2SW, "eth4", 10, false);
    return topo;
}




graph_t *
build_square_topo(void){

#if 0     

  +-----------+                      +--------+                            +--------+
  |           |eth0/0     10.1.1.2/24|        | eth0/2               eth0/3|        |
  | R1        +----------------------|  R2    +----------------------------+   R3   |
  |122.1.1.1  |10.1.1.1/24     eth0/1|122.1.1.2|  20.1.1.1/24   20.1.1.2/24| 122.1.1.3|
  +---+--+----+                      |        |                            +-       +
         |eth0/7                     +--------+                            +----+---+
         | 40.1.1.2/24                                                          | eth0/4   
         |                                                                      |30.1.1.1/24
         |                                                                      |
         |                                                                      |
         |                                                                      |
         |                                                                      |
         |                                                                      |
         |                          +-----------+                               |
         |                          |           |                               |
         |                  eth0/6  |  R4       |                               |
         +--------------------------+ 122.1.1.4 |                               |
                         40.1.1.1/24|           +-------------------------------+
                                    |           |eth0/5
                                    +-----------+30.1.1.2/24

config node R1 route /
122.1.1.2 32 10.1.1.2 eth0/0
122.1.1.3 32 10.1.1.2 eth0/0
122.1.1.4 32 40.1.1.1 eth0/7
cd
conf node R2 route 122.1.1.3 32 20.1.1.2 eth0/2
run node R1 ping 122.1.1.3


#endif

    graph_t *topo = create_new_graph("square Topo");
    node_t *R1 = create_graph_node(topo, (const c_string)"R1");
    node_t *R2 = create_graph_node(topo, (const c_string)"R2");
    node_t *R3 = create_graph_node(topo, (const c_string)"R3");
    node_t *R4 = create_graph_node(topo, (const c_string)"R4");

    insert_link_between_two_nodes(R1, R2, "eth0", "eth1", 1);
    insert_link_between_two_nodes(R2, R3, "eth2", "eth3", 1);
    insert_link_between_two_nodes(R3, R4, "eth4", "eth5", 1);
    insert_link_between_two_nodes(R4, R1, "eth6", "eth7", 1);

    node_set_loopback_address(R1, "122.1.1.1");
    node_set_intf_ip_address(R1, "eth0", "10.1.1.1", 24);
    node_set_intf_ip_address(R1, "eth7", "40.1.1.2", 24);
    
    node_set_loopback_address(R2, "122.1.1.2");
    node_set_intf_ip_address(R2, "eth1", "10.1.1.2", 24);
    node_set_intf_ip_address(R2, "eth2", "20.1.1.1", 24);

    node_set_loopback_address(R3, "122.1.1.3");
    node_set_intf_ip_address(R3, "eth3", "20.1.1.2", 24);
    node_set_intf_ip_address(R3, "eth4", "30.1.1.1", 24);
    
    node_set_loopback_address(R4, "122.1.1.4");
    node_set_intf_ip_address(R4, "eth5", "30.1.1.2", 24);
    node_set_intf_ip_address(R4, "eth6", "40.1.1.1", 24);
    
    return topo;
}

#if 0

  H1 -eth1--------------eth1- H2 -eth2----------------eth1-H3 -eth2----------------eth1- H4
 
#endif 

graph_t *
build_linear_topo(void){

    graph_t *topo = create_new_graph("Linear Topo");
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");
    node_t *H3 = create_graph_node(topo, (const c_string)"H3");
    node_t *H4 = create_graph_node(topo, (const c_string)"H4");
    
    insert_link_between_two_nodes(H1, H2, "eth1", "eth1", 1);
    insert_link_between_two_nodes(H2, H3, "eth2", "eth1", 1);
    insert_link_between_two_nodes(H3, H4, "eth2", "eth1", 1);

    node_set_loopback_address(H1, "122.1.1.1");
    node_set_v6_loopback_address(H1, "2000::1");
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_v6_loopback_address(H2, "2000::2");
    node_set_loopback_address(H3, "122.1.1.3");
    node_set_v6_loopback_address(H3, "2000::3");
    node_set_loopback_address(H4, "122.1.1.4");
    node_set_v6_loopback_address(H4, "2000::4");

    node_set_intf_ip_address(H1, "eth1", "10.1.1.1", 24);
    node_set_intf_ip_address(H2, "eth1", "10.1.1.2", 24);
    node_set_intf_ip_address(H2, "eth2", "20.1.1.2", 24);
    node_set_intf_ip_address(H3, "eth1", "20.1.1.1", 24);
    node_set_intf_ip_address(H3, "eth2", "30.1.1.2", 24);
    node_set_intf_ip_address(H4, "eth1", "30.1.1.1", 24);

    return topo;
}

graph_t *
build_dualswitch_topo(void){

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
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_set_loopback_address(H1, "122.1.1.1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");
    node_set_loopback_address(H2, "122.1.1.2");
    node_t *H3 = create_graph_node(topo, (const c_string)"H3");
    node_set_loopback_address(H3, "122.1.1.3");
    node_t *H4 = create_graph_node(topo, (const c_string)"H4");
    node_set_loopback_address(H4, "122.1.1.4");
    node_t *H5 = create_graph_node(topo, (const c_string)"H5");
    node_set_loopback_address(H5, "122.1.1.5");
    node_t *H6 = create_graph_node(topo, (const c_string)"H6");
    node_set_loopback_address(H6, "122.1.1.6");

    node_t *L2SW1 = create_graph_node(topo, (const c_string)"L2SW1");
    node_t *L2SW2 = create_graph_node(topo, (const c_string)"L2SW2");
    
    insert_link_between_two_nodes(H1, L2SW1, "eth1", "eth2", 1);
    insert_link_between_two_nodes(H2, L2SW1, "eth3", "eth7", 1);
    insert_link_between_two_nodes(H3, L2SW1, "eth4", "eth6", 1);
    insert_link_between_two_nodes(L2SW1, L2SW2, "eth5", "eth7", 1);
    insert_link_between_two_nodes(H5, L2SW2, "eth8", "eth9", 1);
    insert_link_between_two_nodes(H4, L2SW2, "eth11", "eth12", 1);
    insert_link_between_two_nodes(H6, L2SW2, "eth11", "eth10", 1);

    node_set_intf_ip_address(H1, "eth1",  "10.1.1.1", 24);
    node_set_intf_ip_address(H2, "eth3",  "10.1.1.2", 24);
    node_set_intf_ip_address(H3, "eth4",  "10.1.1.3", 24);
    node_set_intf_ip_address(H4, "eth11", "10.1.1.4", 24);
    node_set_intf_ip_address(H5, "eth8",  "10.1.1.5", 24);
    node_set_intf_ip_address(H6, "eth11", "10.1.1.6", 24);

    node_set_intf_switchport(L2SW1, "eth2");
    node_set_intf_vlan_membership(L2SW1, "eth2", 10, false);
    node_set_intf_switchport(L2SW1, "eth7");
    node_set_intf_vlan_membership(L2SW1, "eth7", 10, false);
    node_set_intf_switchport(L2SW1, "eth5");
    node_set_intf_vlan_membership(L2SW1, "eth5", 10, true);
    node_set_intf_switchport(L2SW1, "eth6");
    node_set_intf_vlan_membership(L2SW1, "eth6", 10, false);

    node_set_intf_switchport(L2SW2, "eth7");
    node_set_intf_vlan_membership(L2SW2, "eth7", 10, true);
    node_set_intf_switchport(L2SW2, "eth9");
    node_set_intf_vlan_membership(L2SW2, "eth9", 10, false);
    node_set_intf_switchport(L2SW2, "eth10");
    node_set_intf_vlan_membership(L2SW2, "eth10", 10, false);
    node_set_intf_switchport(L2SW2, "eth12");
    node_set_intf_vlan_membership(L2SW2, "eth12", 10, false);

    return topo;
}

graph_t *
parallel_links_topology(void){

/*
    +--------------+0/0 10.1.1.1        1                            10.1.1.2 0/5+----------------+
    |              +------------------------------------------------------------++                |
    |              |                                                             |                |
    |              |0/1 20.1.1.1        1                            20.1.1.2 0/6|                |
    |    R0        +-------------------------------------------------------------+    R1          |
    |  122.1.1.1   |                                                             |   122.1.1.2    |
    |              |0/2 30.1.1.1        1                            30.1.1.2 0/7|                |
    +              +-------------------------------------------------------------+                |
    |              |                                                             |                |
    +              +0/3 40.1.1.1        1                            40.1.1.2 0/8+                +
    |              |+-------------++---------------------------------------------+                |
    |              |                                                             |                |
    |              |0/4 50.1.1.1        1                            50.1.1.2 0/9|                |
    |              |+-------------+----------------------------------------------+                |
    |              |                                                             |                |
    +--------------+                                                             +----------------+
                                                                                 
                                                                                 
*/
    graph_t *topo = create_new_graph("Parallel Links Topology"); 

    node_t *R0 = create_graph_node(topo, (const c_string)"R0");
    node_t *R1 = create_graph_node(topo, (const c_string)"R1");

    insert_link_between_two_nodes(R0, R1, "eth0", "eth5", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R0, R1, "eth1", "eth6", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R0, R1, "eth2", "eth7", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R0, R1, "eth3", "eth8", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R0, R1, "eth4", "eth9", INTF_METRIC_DEFAULT);

    node_set_loopback_address(R0, "122.1.1.1");
    node_set_loopback_address(R1, "122.1.1.2");

    node_set_intf_ip_address(R0, "eth0", "10.1.1.1", 24);
    node_set_intf_ip_address(R0, "eth1", "20.1.1.1", 24);
    node_set_intf_ip_address(R0, "eth2", "30.1.1.1", 24);
    node_set_intf_ip_address(R0, "eth3", "40.1.1.1", 24);
    node_set_intf_ip_address(R0, "eth4", "50.1.1.1", 24);

    node_set_intf_ip_address(R1, "eth5", "10.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth6", "20.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth7", "30.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth8", "40.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth9", "50.1.1.2", 24);

    return topo;
}


graph_t *
cross_link_topology(void){

/*                                                +--------+-+
                   +---------+                    | R2       |
               eth1| R1      |eth2     20.1.1.2/24|122.1.1.2 |eth8      
       +-----------+122.1.1.1+--------------------+          +------------------+
       |10.1.1.2/24|         |20.1.1.1/24     eth3|          |50.1.1.1/24       |
       |           +---------+                    +-----+--+-+                  +
       +                                         eth4/  |eth7                   |
       |10.1.1.1/24                      30.1.1.1/24/   |40.1.1.2/24            |
       |eth0                                       /    |                  eth9 |50.1.1.2/24
   +---+---+--+                                   /     |                  +----+-----+
   |          |                                  /      |                  |    R3    |
   | R0       |                                 /       |                  | 122.1.1.3|
   |122.1.1.0 |                                /        |                  |          |
   |          |                               /         |                  +----+-----+
   +---+---+--|               ---------------/          |                       |eth10
       |eth14                /                          |                       |60.1.1.1/24
       |80.1.1.1/24         /                           |                       |
       |                   /                            |                       |
       |                  /                        eth6 |40.1.1.1/24            |
       |             eth5/30.1.1.2/24             +-----+----+                  |
       |           +----/----+                    |   R4     |                  |
       |      eth15|   R5    |eth12    70.1.1.2/24|122.1.1.4 |eth11             |
       +-----------+122.1.1.5|+-------------------+          +------------------+
        80.1.1.2/24|         |70.1.1.1/24    eth13|          |60.1.1.2/24
                  -+---------+                    +----------+

*/
    graph_t *topo = create_new_graph("Cross Links Topology"); 

    node_t *R0 = create_graph_node(topo, (const c_string)"R0");
    node_t *R1 = create_graph_node(topo, (const c_string)"R1");
    node_t *R2 = create_graph_node(topo, (const c_string)"R2");
    node_t *R3 = create_graph_node(topo, (const c_string)"R3");
    node_t *R4 = create_graph_node(topo, (const c_string)"R4");
    node_t *R5 = create_graph_node(topo, (const c_string)"R5");

    insert_link_between_two_nodes(R0, R1, "eth0",  "eth1",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R0, R5, "eth14", "eth15", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R1, R2, "eth2",  "eth3",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R2, R3, "eth8",  "eth9",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R2, R4, "eth7",  "eth6",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R2, R5, "eth4",  "eth5",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R3, R4, "eth10", "eth11", INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R4, R5, "eth13", "eth12", INTF_METRIC_DEFAULT);    

    node_set_loopback_address(R0, "122.1.1.0");
    node_set_loopback_address(R1, "122.1.1.1");
    node_set_loopback_address(R2, "122.1.1.2");
    node_set_loopback_address(R3, "122.1.1.3");
    node_set_loopback_address(R4, "122.1.1.4");
    node_set_loopback_address(R5, "122.1.1.5");

    node_set_intf_ip_address(R0, "eth0", "10.1.1.1", 24);
    node_set_intf_ip_address(R0, "eth14","80.1.1.1", 24);

    node_set_intf_ip_address(R1, "eth1", "10.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth2", "20.1.1.1", 24); 

    node_set_intf_ip_address(R2, "eth3", "20.1.1.2", 24);
    node_set_intf_ip_address(R2, "eth8", "50.1.1.1", 24);
    node_set_intf_ip_address(R2, "eth4", "30.1.1.1", 24);
    node_set_intf_ip_address(R2, "eth7", "40.1.1.2", 24);

    node_set_intf_ip_address(R3, "eth9", "50.1.1.2", 24);
    node_set_intf_ip_address(R3, "eth10","60.1.1.1", 24);

    node_set_intf_ip_address(R4, "eth6", "40.1.1.1", 24);
    node_set_intf_ip_address(R4, "eth11","60.1.1.2", 24);
    node_set_intf_ip_address(R4, "eth13","70.1.1.2", 24);

    node_set_intf_ip_address(R5, "eth5", "30.1.1.2", 24);
    node_set_intf_ip_address(R5, "eth12","70.1.1.1", 24);
    node_set_intf_ip_address(R5, "eth15","80.1.1.2", 24);

    return topo;
}


#ifdef vlan_extension_topo

vlan_extension_topo Demo : 

config node R1 interface tunnel 2
config node R1 interface tunnel 2 tunnel-source 100.1.1.1
config node R1 interface tunnel 2 tunnel-destination 100.1.1.2
config node R1 interface tunnel 2 ip-address 192.168.0.1 24

config node R1 interface vlan 10
config node R1 transport-service-profile tsp10
config node R1 transport-service-profile tsp10 vlan 10

config node R1 interface virtual-port vp1 
config node R1 interface virtual-port vp1 transport-service-profile tsp10
config node R1 interface virtual-port vp1 overlay-tunnel tunnel2

config node R1 route 100.1.1.2 32 20.1.1.2 eth1


config node R2 interface tunnel 2
config node R2 interface tunnel 2 tunnel-source 100.1.1.2
config node R2 interface tunnel 2 tunnel-destination 100.1.1.1
config node R2 interface tunnel 2 ip-address 192.168.0.2 24

config node R2 interface vlan 10
config node R2 transport-service-profile tsp10
config node R2 transport-service-profile tsp10 vlan 10

config node R2 interface virtual-port vp1 
config node R2 interface virtual-port vp1 transport-service-profile tsp10
config node R2 interface virtual-port vp1 overlay-tunnel tunnel2

config node R2 route 100.1.1.1 32 20.1.1.1 eth1

run node H1 ping 10.1.1.2

                             +-------------GRE-Tunnel----------+
                             |                                 |
                             |                                 |
                             v                                 v
                                                               
                         +---+-----+                     +----------+
                  v10,acc|         |20.1.1.1         eth1|          |v10,acc
       +-----------+-----|   R1    +---------------------+   R2     +--------------+
       |             eth0|100.1.1.1|eth1         20.1.1.2|100.1.1.2 |eth0          |eth0
       |                 +---------+                     +----------+              |10.1.1.2/24
   eth0|10.1.1.1/24                                                           +---+-----+
   +---+----+                                                                 |  H2     |
   +   H1   |                                                                 |122.1.1.2+       
   |122.1.1.1                                                                 +---------+
   +--------+

#endif                                                                 

graph_t *
vlan_extension_topo(void) {

    graph_t *topo = create_new_graph("Vlan Extension Over GRE Topo"); 

    node_t *R1 = create_graph_node(topo, (const c_string)"R1");
    node_t *R2 = create_graph_node(topo, (const c_string)"R2");
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");

    insert_link_between_two_nodes(R1, R2, "eth1",  "eth1",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R1, H1, "eth0",  "eth0",  INTF_METRIC_DEFAULT);
    insert_link_between_two_nodes(R2, H2, "eth0",  "eth0",  INTF_METRIC_DEFAULT);

    interface_loopback_create (H1, 0);
    
    node_set_loopback_address(H1, "122.1.1.1");
    node_set_loopback_address(H2, "122.1.1.2");
    node_set_loopback_address(R1, "100.1.1.1");
    node_set_loopback_address(R2, "100.1.1.2");

    node_set_intf_ip_address(H1, "eth0", "10.1.1.1", 24);
    node_set_intf_ip_address(H2, "eth0", "10.1.1.2", 24);
    node_set_intf_ip_address(R1, "eth1", "20.1.1.1" , 24);
    node_set_intf_ip_address(R2, "eth1", "20.1.1.2" , 24);

    node_set_intf_switchport(R1, "eth0");
    node_set_intf_vlan_membership(R1, "eth0", 10, false);
    node_set_intf_switchport(R2, "eth0");
    node_set_intf_vlan_membership(R2, "eth0", 10, false);

    return topo;
}


graph_t *
build_vxlan_topo(void){

#if 0
                          +------------+
                          +    H3      |
                          |            |
                          +----+-------+
                               |192.168.0.30
			       |
			       |
			       |
			       |eth1
                               |v20
                          +----+-----+
                      eth4|          |eth0
         +----------------+   R0_re  +---------------------------+
         |     40.1.1.1/24| 122.1.1.0|20.1.1.1/24                |
         |                +----------+                           |
         |                                                       |
         |                                                       |
	 |                                                       |
	 |                                                       |
         |                                                       |
         |40.1.1.2/24                                            |20.1.1.2/24
         |0/5                                                    |0/1
     +---+---+                                              +----+-----+
     |       |0/3                                        0/2|          |
     | R1_re +----------------------------------------------+    R2_re |
     |       |30.1.1.2/24                        30.1.1.1/24|          |
     +--|----+                                              +----|-----+
        |eth1                                                    |eth3
        |v10                                                     |v10
	|                                                        |
	|                                                        |
	|                                                        |
	|192.168.0.10                                            |192.168.0.20
   |--------|                                                |---------|
   |        |                                                |         |
   |  H1    |                                                |   H2    |
   |        |                                                |         |
   |--------|                                                |---------|

config node R0_re route 122.1.1.1 32 40.1.1.2 eth4 
config node R0_re route 122.1.1.2 32 20.1.1.2 eth0 
config node R1_re route 122.1.1.0 32 40.1.1.1 eth5 
config node R1_re route 122.1.1.2 32 30.1.1.1 eth3 
config node R2_re route 122.1.1.0 32 20.1.1.1 eth1 
config node R2_re route 122.1.1.1 32 30.1.1.2 eth2 

config node R0_re interface vlan 20 ip-address 192.168.0.30 24
config node R0_re interface vlan 20 vni 5010
config node R0_re interface nve nve1 member l2vni 5010
config node R0_re mac-table install 20 ff:ff:ff:ff:ff:ff nve1 122.1.1.1
config node R0_re mac-table install 20 ff:ff:ff:ff:ff:ff nve1 122.1.1.2

config node R1_re interface vlan 10 ip-address 192.168.0.1 24
config node R1_re interface vlan 10 vni 5010
config node R1_re interface nve nve1 member l2vni 5010
config node R1_re mac-table install 10 ff:ff:ff:ff:ff:ff nve1 122.1.1.0
config node R1_re mac-table install 10 ff:ff:ff:ff:ff:ff nve1 122.1.1.2

config node R2_re interface vlan 10 ip-address 192.168.0.1 24
config node R2_re interface vlan 10 vni 5010
config node R2_re interface nve nve1 member l2vni 5010
config node R2_re mac-table install 10 ff:ff:ff:ff:ff:ff nve1 122.1.1.0
config node R2_re mac-table install 10 ff:ff:ff:ff:ff:ff nve1 122.1.1.1

#endif


    graph_t *topo = create_new_graph("Hello World Generic Graph");
    node_t *R0_re = create_graph_node(topo, (const c_string)"R0_re");
    node_t *R1_re = create_graph_node(topo, (const c_string)"R1_re");
    node_t *R2_re = create_graph_node(topo, (const c_string)"R2_re");
    node_t *H1 = create_graph_node(topo, (const c_string)"H1");
    node_t *H2 = create_graph_node(topo, (const c_string)"H2");
    node_t *H3 = create_graph_node(topo, (const c_string)"H3");

    insert_link_between_two_nodes(R0_re, R2_re, "eth0", "eth1", 5);
    insert_link_between_two_nodes(R2_re, R1_re, "eth2", "eth3", 4);
    insert_link_between_two_nodes(R0_re, R1_re, "eth4", "eth5", 9);
    insert_link_between_two_nodes(H1, R1_re, "eth1", "eth1", 1);
    insert_link_between_two_nodes(H2, R2_re, "eth1", "eth3", 1);
    insert_link_between_two_nodes(H3, R0_re, "eth1", "eth1", 1);
    
    node_set_loopback_address(R0_re, "122.1.1.0");

    node_set_intf_ip_address(R0_re, "eth4", "40.1.1.1", 24);
    node_set_intf_ip_address(R0_re, "eth0", "20.1.1.1", 24);
    
    node_set_loopback_address(R2_re, "122.1.1.2");

    node_set_intf_ip_address(R2_re, "eth1", "20.1.1.2", 24);
    node_set_intf_ip_address(R2_re, "eth2", "30.1.1.1", 24);

    node_set_loopback_address(R1_re, "122.1.1.1");

    node_set_intf_ip_address(R1_re, "eth3", "30.1.1.2", 24);
    node_set_intf_ip_address(R1_re, "eth5", "40.1.1.2", 24);

    node_set_intf_ip_address(H1, "eth1", "192.168.0.10", 24);
    node_set_intf_ip_address(H2, "eth1", "192.168.0.20", 24);
    node_set_intf_ip_address(H3, "eth1", "192.168.0.30", 24);

    node_set_intf_switchport(R1_re, "eth1");
    node_set_intf_vlan_membership(R1_re, "eth1", 10, false);
    node_set_intf_switchport(R2_re, "eth3");
    node_set_intf_vlan_membership(R2_re, "eth3", 10, false);

    node_set_intf_switchport(R0_re, "eth1");
    node_set_intf_vlan_membership(R0_re, "eth1", 20, false);

    return topo;
}
