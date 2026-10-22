#ifndef __FLOW_MGR__
#define __FLOW_MGR__

#include <rte_hash.h>

#include "../../libs/Tree/libtree.h"
#include "../../libs/gluethread/glthread.h"
#include "dp_flow.h"

typedef struct dp_ctx_ dp_ctx_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;

/* Centralized DB of dp_flow_t */
typedef struct gflow_db_ {

    struct rte_hash *hash;

} gflow_db_t;

/* Per interface dp_flow_t  DB */
typedef struct lflow_db_ {

    struct rte_hash *hash;

} lflow_db_t;

typedef struct flow_mgr_ {

    gflow_db_t *gflow_db;

    /* AVL tree indexed by dp_flow_t->flow_key.ifindex, stores  dp_flow_t objects */
    avltree_t gflow_db_keyed_by_ifindex;

    /* AVL tree indexed by dp_flow_t->fdata.nexthop_mac, stores  pointer to dp_flow_t objects */
    avltree_t gflow_db_keyed_by_nexthop_mac;

    /* AVL tree indexed by dp_flow_t->fdata.nh.cnhidx, stores  pointer to dp_flow_t objects */
    avltree_t gflow_db_keyed_by_nh;

    /* Periodic GC Timer , runs every 1 minute, delete all flows enqueued in gc_thread */
    wheel_timer_elem_t *gc_wheel_job;
    glthread_data_node_t gc_thread;

} flow_mgr_t;

void 
dp_flow_mgr_init(dp_ctx_t *dp_ctx);

/* Create flow object in the global flow HT and all AVL Trees */
bool
dp_flow_mgr_create_flow (dp_ctx_t *dp_ctx, 
                                            flow_key_t flow_key, 
                                            flow_data_t *fdata);

/* Delete flows from all AVL Trees, and  global flow HT , Queue the flow */
bool
dp_flow_mgr_delete_flow (dp_ctx_t *dp_ctx, uint32_t ifindex, flow_key_t flow_key);

/* To be implemented Later */
bool
dp_flow_mgr_sync_intf (dp_ctx_t *dp_ctx, 
                                        flow_key_t flow_key,  
                                        flow_data_t *fdata,  /* Null if del*/
                                        dp_intf_t *dp_intf, 
                                        bool add);

#endif 