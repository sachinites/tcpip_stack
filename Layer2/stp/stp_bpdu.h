/*
 * =====================================================================================
 *
 *       Filename:  stp_bpdu.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/28/2021 11:24:37 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __STP_BPDU__
#define __STP_BPDU__

uint32_t
stp_format_configuration_bpdu(
    node_t *node,
    interface_t *intf,
    bpdu_fmt_t *bpdu_buffer);

bool
stp_should_process_recvd_config_bpdu(
	node_t *node,
	interface_t *recv_intf,
	bpdu_fmt_t *bpdu);

void
stp_start_root_bridge_bpdu_generation_timer(
        node_t *node) {

}

void
stp_cancel_root_bridge_bpdu_generation_timer(
        node_t *node) {

}

#endif /* __STP_BPDU__  */
