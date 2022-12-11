/*
 * =====================================================================================
 *
 *       Filename:  conn.h
 *
 *    Description:  This file defines the structures required to work with Connections
 *
 *        Version:  1.0
 *        Created:  10/05/2022 11:49:24 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __CONN__
#define __CONN

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

typedef struct _wheel_timer_t wheel_timer_t;
typedef struct node_ node_t;
class Interface;
typedef  struct hashtable hashtable_t;
typedef struct pkt_block_ pkt_block_t;

typedef struct conn_tuple_ {

    uint16_t proto;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
} conn_tuple_t;

typedef struct conn_ {

    conn_tuple_t conn_tuple;
    time_t create_time;
    wheel_timer_t * expiry_time;
    Interface *ingress_intf;
    Interface *egress_intf;
    struct conn_ *reverse_conn;
} conn_t;

void
conn_create_type_from_pkt (pkt_block_t *pkt_block, conn_tuple_t *conn_tuple);

void
connection_table_print (node_t *node);

conn_t *
create_new_connection (node_t *node, conn_tuple_t *conn_tuple);

conn_t *
connection_lookup (node_t *node, conn_tuple_t *conn_tuple);

void
connection_print (conn_t *conn);

void
connection_delete (node_t *node, conn_t *conn);

bool
connection_exist(node_t *node, pkt_block_t *pkt_block);

#endif
