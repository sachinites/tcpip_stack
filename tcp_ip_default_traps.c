/*
 * =====================================================================================
 *
 *       Filename:  tcp_ip_default_traps.c
 *
 *    Description: This file defines the structures and routines to allow applications to register for default pkt traps
 *    on all nodes.
 *
 *        Version:  1.0
 *        Created:  07/14/2021 08:19:55 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <unistd.h>
#include <stdbool.h>
#include "net.h"
#include "Layer5/layer5.h"
#include "Layer3/netfilter.h"

/*  Default pkt traps, enabled by default
 *  on all nodes */
typedef bool (*pkt_trap_qualifier)(char *, size_t);
typedef void (*pkt_processing_fn)(void *, size_t);

typedef struct pkt_trap_data_ {

    nf_hook_t nf_hook_type;
    pkt_trap_qualifier pkt_trap_qualifier_cb;
    pkt_processing_fn pkt_processing_fn_cb;
} pkt_trap_data_t;

/* Application pkt trappers imports */
extern bool
ddcp_trap_l2_pkt_rule(char *pkt, size_t pkt_size);
extern void
ddcp_process_ddcp_query_msg(void *arg, size_t arg_size);

static pkt_trap_data_t
tcp_ip_default_l2_pkt_trap_rule[] = {
    {NF_IP_END, ddcp_trap_l2_pkt_rule, ddcp_process_ddcp_query_msg},
    {NF_IP_END, 0, 0} /*  Dont remove this NULL element */
};

/*  Application pkt trappers imports */
extern bool
ddcp_trap_l3_pkt_rule(char *pkt, size_t pkt_size);
extern void
ddcp_process_ddcp_reply_msg(void *arg, size_t arg_size);

static pkt_trap_data_t
tcp_ip_default_l3_pkt_trap_rule[] = {
    {NF_IP_LOCAL_IN, ddcp_trap_l3_pkt_rule, ddcp_process_ddcp_reply_msg},
    {NF_IP_LOCAL_IN, 0, 0} /*   Dont remove this NULL element */
};

void
tcp_ip_register_default_l2_pkt_trap_rules(node_t *node){

    pkt_trap_data_t *pkt_trap_data =
        &tcp_ip_default_l2_pkt_trap_rule[0];

    while(pkt_trap_data->pkt_trap_qualifier_cb &&
            pkt_trap_data->pkt_processing_fn_cb) {

        tcp_stack_register_l2_pkt_trap_rule(node,
                pkt_trap_data->pkt_trap_qualifier_cb,
                pkt_trap_data->pkt_processing_fn_cb);
        pkt_trap_data++;
    }
}

void
tcp_ip_register_default_l3_pkt_trap_rules(node_t *node){

    pkt_trap_data_t *pkt_trap_data =
        &tcp_ip_default_l3_pkt_trap_rule[0];

    while(pkt_trap_data->pkt_trap_qualifier_cb &&
            pkt_trap_data->pkt_processing_fn_cb) {

        nf_register_netfilter_hook(node,
                pkt_trap_data->nf_hook_type,
                pkt_trap_data->pkt_trap_qualifier_cb,
                pkt_trap_data->pkt_processing_fn_cb);
        pkt_trap_data++;
    }
}
