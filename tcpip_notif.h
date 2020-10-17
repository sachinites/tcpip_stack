/*
 * =====================================================================================
 *
 *       Filename:  tcpip_notif.h
 *
 *    Description: This file defines notification chain structures for TCP/IP stack lib 
 *
 *        Version:  1.0
 *        Created:  10/17/2020 02:20:01 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __TCPIP_NOTIF_C
#define __TCPIP_NOTIF_C

#include "notif.h"

typedef struct interface_ interface_t;
typedef struct intf_nw_props_ intf_nw_props_t;
/* 
 * Structures for interface events notification
 * to subscribers 
 */

typedef struct intf_notif_data_{

	interface_t *interface;
	intf_nw_props_t *old_intf_nw_props;
	uint32_t change_flags;
} intf_notif_data_t;

/* Routines for interface Notif Chains */
void
nfc_intf_register_for_events(nfc_app_cb app_cb);

void
nfc_intf_invoke_notification_to_sbscribers(
	interface_t *intf,
    intf_nw_props_t *old_intf_nw_props,
    uint32_t change_flags);


/* 
 * Structure for wrapping up pkt info
 * to be notified to application for printing.
 * only appln has knowledge to recognize the
 * pkt content and print it 
 * */

typedef struct pkt_info_{

	uint32_t protocol_no;
	char *pkt;
	uint32_t pkt_size;
	char *pkt_print_buffer;
	uint32_t bytes_written;
} pkt_info_t;

void
nfc_register_for_pkt_tracing(
    uint32_t protocol_no,
    nfc_app_cb app_cb);

int
nfc_pkt_trace_invoke_notif_to_sbscribers(
                    uint32_t protocol_no,
                    char *pkt,
                    uint32_t pkt_size,
					char *pkt_print_buffer);

#endif /* __TCPIP_NOTIF_C */
