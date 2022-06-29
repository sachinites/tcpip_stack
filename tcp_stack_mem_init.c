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
void
tcp_stack_miscellaneous_mem_init() {

    snp_flow_mem_init();
    pkt_block_mem_init();
    pkt_notif_data_mem_init();
}
