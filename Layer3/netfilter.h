/*
 * =====================================================================================
 *
 *       Filename:  netfilter.h
 *
 *    Description: This file defines the interfaces to work with Netfilter Hooks 
 *
 *        Version:  1.0
 *        Created:  02/13/2021 02:45:59 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __NF__
#define __NF__

#include <stdint.h>
#include "../tcpconst.h"
#include "../notif.h"

typedef enum {

	NF_IP_PRE_ROUTING,
	NF_IP_LOCAL_IN,
	NF_IP_FORWARD,
	NF_IP_LOCAL_OUT,
	NF_IP_POST_ROUTING,
	NF_IP_END
} nf_hook_t;

/* Net filter Actions */
#define NF_DROP		0 
#define NF_ACCEPT	1
#define NF_STOLEN	2
#define NF_QUEUE	3
#define NF_REPEAT	4
#define NF_STOP		5
#define NF_MAX_VERDICT  NF_STOP

typedef struct nf_hook_db_ {

	notif_chain_t nf_hook[NF_IP_END];
} nf_hook_db_t;

void
nf_init_netfilters(nf_hook_db_t *nf_hook_db);

typedef struct node_ node_t;
class Interface;
typedef struct pkt_block_ pkt_block_t;

int8_t
nf_invoke_netfilter_hook(
						nf_hook_t nf_hook_type,
						 pkt_block_t *pkt_block,
						 node_t *node,
						 Interface *intf,
						 hdr_type_t hdr_code);

void
nf_register_netfilter_hook(node_t *node,
						   nf_hook_t nf_hook_type,
                           nfc_pkt_trap pkt_trap_cb,
                           nfc_app_cb pkt_notif_app_cb);

void
nf_de_register_netfilter_hook(node_t *node,
	    				      nf_hook_t nf_hook_type,
                              nfc_pkt_trap pkt_trap_cb,
                              nfc_app_cb pkt_notif_app_cb);
#endif 
