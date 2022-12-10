/*
 * =====================================================================================
 *
 *       Filename:  netfilter.c
 *
 *    Description: This file implements the APIs to be used with Netfilter Hooks 
 *
 *        Version:  1.0
 *        Created:  02/13/2021 02:51:40 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <string.h>
#include "../graph.h"
#include "netfilter.h"
#include "../Layer5/layer5.h"
#include "../pkt_block.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../LinuxMemoryManager/uapi_mm.h"

static inline void
nf_init_nf_hook(notif_chain_t *nfc,
			  char *nf_hook_name, 
			  void (*preprocessing_fn_ptr)(void *),
			  void * (copy_arg_fn_ptr(void *))) {

	strcpy(nfc->nfc_name, nf_hook_name);
	nfc->preprocessing_fn_ptr = preprocessing_fn_ptr;
	nfc->copy_arg_fn_ptr = copy_arg_fn_ptr;
	init_glthread(&nfc->notif_chain_head);
}

void *
netfilter_pkt_notif_data_dup_fn (void *arg);

void *
netfilter_pkt_notif_data_dup_fn (void *arg) {

	pkt_notif_data_t *pkt_notif_data = (pkt_notif_data_t *)arg;
	pkt_notif_data_t *pkt_notif_data2 = (pkt_notif_data_t *)XCALLOC(0, 1, pkt_notif_data_t);
	pkt_notif_data2->recv_node = pkt_notif_data->recv_node;
	pkt_notif_data2->recv_interface = pkt_notif_data->recv_interface;
	pkt_notif_data2->pkt_block = pkt_block_dup(pkt_notif_data->pkt_block);
	pkt_block_reference(pkt_notif_data2->pkt_block);
	pkt_notif_data2->hdr_code = pkt_notif_data->hdr_code;
	pkt_notif_data2->return_code = pkt_notif_data->return_code;
	return (void *)pkt_notif_data2;
}

void
nf_init_netfilters(nf_hook_db_t *nf_hook_db) {

	nf_init_nf_hook(&nf_hook_db->nf_hook[NF_IP_PRE_ROUTING],
					"NF_IP_PRE_ROUTING", NULL, netfilter_pkt_notif_data_dup_fn);
	nf_init_nf_hook(&nf_hook_db->nf_hook[NF_IP_LOCAL_IN],
					"NF_IP_LOCAL_IN", NULL, netfilter_pkt_notif_data_dup_fn);
	nf_init_nf_hook(&nf_hook_db->nf_hook[NF_IP_FORWARD],
					"NF_IP_FORWARD", NULL, netfilter_pkt_notif_data_dup_fn);
	nf_init_nf_hook(&nf_hook_db->nf_hook[NF_IP_LOCAL_OUT],
					"NF_IP_LOCAL_OUT", NULL, netfilter_pkt_notif_data_dup_fn);
	nf_init_nf_hook(&nf_hook_db->nf_hook[NF_IP_POST_ROUTING],
					"NF_IP_POST_ROUTING", NULL, netfilter_pkt_notif_data_dup_fn);
}

int8_t
nf_invoke_netfilter_hook(
						nf_hook_t nf_hook_type,
						 pkt_block_t *pkt_block,
						 node_t *node,
						 Interface *intf,
						 hdr_type_t hdr_code) {

	char *pkt;
	pkt_size_t pkt_size;
	pkt_notif_data_t pkt_notif_data;

    pkt_notif_data.recv_node = node;
    pkt_notif_data.recv_interface = intf;
    pkt_notif_data.pkt_block = pkt_block;
	pkt_block_reference(pkt_block);
	pkt_notif_data.hdr_code = hdr_code;
    pkt_notif_data.return_code = NF_ACCEPT;

	pkt = (char *) pkt_block_get_pkt(pkt_block, &pkt_size);

    nfc_invoke_notif_chain(
			EV(node),
			&node->nf_hook_db.nf_hook[nf_hook_type],
			(void *)&pkt_notif_data,
            sizeof(pkt_notif_data_t),
            pkt, pkt_size, TASK_PRIORITY_PKT_PROCESSING);

	pkt_block_dereference(pkt_block);
    return NF_ACCEPT;
}

void
nf_register_netfilter_hook(node_t *node,
						   nf_hook_t nf_hook_type,
						   nfc_pkt_trap pkt_trap_cb,
						   nfc_app_cb pkt_notif_app_cb) {

	notif_chain_t *nfc;
	notif_chain_elem_t nfce;

	nfc = &node->nf_hook_db.nf_hook[nf_hook_type];
	
	memset(&nfce, 0, sizeof(notif_chain_elem_t));
	nfce.is_key_set = false;
	nfce.app_cb = pkt_notif_app_cb;
	nfce.pkt_trap_cb = pkt_trap_cb;
	
	nfc_register_notif_chain(nfc, &nfce);
}


void
nf_de_register_netfilter_hook(node_t *node,
						   nf_hook_t nf_hook_type,
						   nfc_pkt_trap pkt_trap_cb,
						   nfc_app_cb pkt_notif_app_cb) {

	notif_chain_t *nfc;
	notif_chain_elem_t nfce;

	nfc = &node->nf_hook_db.nf_hook[nf_hook_type];
	
	memset(&nfce, 0, sizeof(notif_chain_elem_t));
	nfce.is_key_set = false;
	nfce.app_cb = pkt_notif_app_cb;
	nfce.pkt_trap_cb = pkt_trap_cb;
	
	nfc_de_register_notif_chain(nfc, &nfce);
}
