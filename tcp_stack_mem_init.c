/*
 * =====================================================================================
 *
 *       Filename:  tcp_stack_mem_init.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/30/2021 12:33:51 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

extern void snp_flow_mem_init();
extern void pkt_block_mem_init();
extern void pkt_notif_data_mem_init();
extern void pkt_tracer_mem_init ();
extern void acl_mem_init();
extern void object_network_mem_init () ;
extern void prefix_list_mem_init ();
extern void object_group_mem_init ();
extern void comm_mem_init();

#include "Tree/libtree.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "gluethread/glthread.h"
#include "mtrie/mtrie.h"
#include "stack/stack.h"

void
tcp_stack_miscellaneous_mem_init() ;

void
tcp_stack_miscellaneous_mem_init() {

    snp_flow_mem_init();
    pkt_block_mem_init();
    pkt_notif_data_mem_init();
    pkt_tracer_mem_init ();
    acl_mem_init();
    object_network_mem_init () ;
    prefix_list_mem_init ();
    object_group_mem_init ();
    comm_mem_init();

    /* Library structures */
    MM_REG_STRUCT (0, avltree_t);
    MM_REG_STRUCT (0, avltree_node_t);
    MM_REG_STRUCT(0, glthread_t);
    MM_REG_STRUCT(0, glthread_data_node_t);
    MM_REG_STRUCT(0, mtrie_t);
    MM_REG_STRUCT(0, mtrie_node_t);
    MM_REG_STRUCT(0, Stack_t);
}
