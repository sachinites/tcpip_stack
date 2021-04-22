/*
 * =====================================================================================
 *
 *       Filename:  stp_init.c
 *
 *    Description: This file initialized the Spanning Tree Protocol (STP) 
 *
 *        Version:  1.0
 *        Created:  01/04/2021 07:47:05 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include "../../tcp_public.h"
#include "stp_struct.h"

static void
stp_process_config_bpdu(void *arg, size_t arg_size) {

}

static bool
stp_trap_config_bpdu( char *pkt, size_t pkt_size) {

	return true;
}

static void
stp_interface_update(void *arg, size_t arg_size) {

}

static void
stp_print_config_bpdu(void *arg, size_t arg_size) {


}

void
stp_init_stp_node_info(stp_node_info_t **stp_node_info) {


}

void
stp_init() {

	tcp_stack_register_l2_pkt_trap_rule(
		stp_trap_config_bpdu, stp_process_config_bpdu);

	nfc_register_for_pkt_tracing(STP_CONFIG_BPDU,
		stp_print_config_bpdu);

	nfc_intf_register_for_events(stp_interface_update);
}
