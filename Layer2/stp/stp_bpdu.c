/*
 * =====================================================================================
 *
 *       Filename:  stp_bpdu.c
 *
 *    Description: This file implements STP BPDUs 
 *
 *        Version:  1.0
 *        Created:  01/01/2021 10:43:29 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <stdbool.h>
#include "../../tcp_public.h"
#include "stp_struct.h"

/*
 * Fn to format the config BPDU which need to be sent
 * out of this interface
 * @return : Returns the no of bytes encoded in bpdu msg
 */
uint32_t
stp_format_configuration_bpdu(
	node_t *node,
	interface_t *intf,
	bpdu_fmt_t *bpdu_buffer) {

	return 0;
}

bool
stp_should_process_recvd_config_bpdu(
    node_t *node,
    interface_t *recv_intf,
    bpdu_fmt_t *bpdu) {

	stp_vlan_intf_info_t *stp_vlan_intf_info = recv_intf->intf_nw_props.stp_vlan_intf_info;

	if (!stp_vlan_intf_info) {
		return false;
	}	
	
	if (stp_vlan_intf_info->stp_config_changed) {
		stp_vlan_intf_info->stp_config_changed = false;
		return true;
	}

	if (!stp_vlan_intf_info->peer_config_bpdu) {
		return true;
	}

	if (memcmp(stp_vlan_intf_info->peer_config_bpdu,
			   bpdu, sizeof(bpdu_fmt_t))) {
		
		return true;
	}

	return false;
}

void
stp_start_root_bridge_bpdu_generation_timer(
		node_t *node) {

}

void
stp_cancel_root_bridge_bpdu_generation_timer(
		node_t *node) {

}

