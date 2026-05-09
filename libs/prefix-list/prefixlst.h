#ifndef __PREFIX_LST__
#define __PREFIX_LST__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "../gluethread/glthread.h"

typedef glthread_t pfxlst_db;

#define PFX_LST_NAME_LEN 64
#define PFX_LST_SEQ_NO_LAPS 5

typedef enum pfx_lst_result_ {

    PFX_LST_DENY,
    PFX_LST_PERMIT,
    PFX_LST_SKIP,
    PFX_LST_UNKNOWN
} pfx_lst_result_t;

typedef struct pfx_lst_node_ {

    glthread_t glue;
    uint64_t hit_count;
    uint32_t pfx;
    pfx_lst_result_t res;
    uint8_t seq_no;
    uint8_t pfx_len;
    int8_t lb;
    int8_t ub;
    
} __attribute__((aligned(8))) pfx_lst_node_t;
GLTHREAD_TO_STRUCT(glue_to_pfx_lst_node, pfx_lst_node_t, glue);

typedef struct prefix_lst_ {

    glthread_t pfx_lst_head;
    glthread_t glue;
    unsigned char name[PFX_LST_NAME_LEN];
    uint32_t seq_no;
    uint8_t ref_count;

} __attribute__((aligned(8))) prefix_list_t;
GLTHREAD_TO_STRUCT(glue_to_pfx_lst, prefix_list_t, glue);

prefix_list_t *
prefix_lst_lookup_by_name (pfxlst_db *pfxlstdb, unsigned char *pfxlst_name);

bool
prefix_list_add_rule (prefix_list_t *prefix_lst, uint32_t seq_no, pfx_lst_result_t res, uint32_t prefix, uint8_t len, int8_t lb, int8_t ub);

bool
prefix_list_del_rule (prefix_list_t *prefix_lst, uint32_t seq_no);

/* Returns the rule with the given seq_no in `prefix_lst`, or NULL if no
   such rule exists. seq_no == 0 is reserved for auto-assignment and never
   matches any stored rule. */
pfx_lst_node_t *
prefix_list_lookup_by_seq_no (prefix_list_t *prefix_lst, uint32_t seq_no);

void
prefix_list_show (prefix_list_t *prefix_lst);

pfx_lst_result_t
prefix_list_evaluate_against_pfx_lst_node(uint32_t prefix,
                                          uint8_t len,
                                          pfx_lst_node_t *pfx_lst_node);

pfx_lst_result_t
prefix_list_evaluate (uint32_t prefix, uint8_t len, prefix_list_t *prefix_lst);

static inline void
prefix_list_reference (prefix_list_t *prefix_lst) {

    prefix_lst->ref_count++;
}

static inline uint32_t
prefix_list_dereference (prefix_list_t *prefix_lst) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

    prefix_lst->ref_count--;

    if (prefix_lst->ref_count) return prefix_lst->ref_count;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        remove_glthread (curr);
        free(pfx_lst_node);

    } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr) ;

    assert(IS_GLTHREAD_LIST_EMPTY(&prefix_lst->glue));

    free(prefix_lst);
    return 0;
}

static inline bool
prefix_list_is_in_use (prefix_list_t *prefix_lst) {

    return prefix_lst->ref_count > 1;
}

/* Per-node prefix-list change subscription registry.
   A client (e.g. a routing protocol instance) registers a callback that
   the prefix-list code invokes whenever any prefix-list owned by `node`
   is modified. The (vrf_id, instance_no) pair is opaque to the registry;
   it is stored alongside the callback so the callee can route the event
   to the right protocol instance without the registry needing to know
   anything about the protocols. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct node_ node_t;
typedef struct vrf_  vrf_t;

typedef void (*prefix_list_change_cbk)(node_t *node,
                                       vrf_t *vrf,
                                       uint32_t instance_no,
                                       prefix_list_t *prefix_lst);

void
prefix_list_register_client(node_t *node,
                            prefix_list_change_cbk cbk,
                            vrf_t *vrf,
                            uint32_t instance_no);

void
prefix_list_unregister_client(node_t *node,
                              prefix_list_change_cbk cbk,
                              vrf_t *vrf,
                              uint32_t instance_no);

void
prefix_list_update_notify_clients(node_t *node,
                                  prefix_list_t *prefix_lst);

#ifdef __cplusplus
}
#endif

#endif 
