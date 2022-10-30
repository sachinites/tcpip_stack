#ifndef __PREFIX_LST__
#define __PREFIX_LST__

#include <stdint.h>
#include <stdbool.h>
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

    uint8_t seq_no;
    uint32_t pfx;
    uint8_t pfx_len;
    int8_t lb;
    int8_t ub;
    uint64_t hit_count;
    pfx_lst_result_t res;
    glthread_t glue;
} pfx_lst_node_t;
GLTHREAD_TO_STRUCT(glue_to_pfx_lst_node, pfx_lst_node_t, glue);

typedef struct prefix_lst_ {

    unsigned char name[PFX_LST_NAME_LEN];
    uint8_t ref_count;
    uint32_t seq_no;
    glthread_t pfx_lst_head;
    glthread_t glue;
} prefix_list_t;
GLTHREAD_TO_STRUCT(glue_to_pfx_lst, prefix_list_t, glue);

prefix_list_t *
prefix_lst_lookup_by_name (pfxlst_db *pfxlstdb, unsigned char *pfxlst_name);

bool
prefix_list_add_rule (prefix_list_t *prefix_lst, uint32_t seq_no, pfx_lst_result_t res, uint32_t prefix, uint8_t len, int8_t lb, int8_t ub);

bool
prefix_list_del_rule (prefix_list_t *prefix_lst, uint32_t seq_no);

void
prefix_list_show (prefix_list_t *prefix_lst);

pfx_lst_result_t
prefix_list_evaluate_against_pfx_lst_node (uint32_t prefix,
                                                                      uint8_t len,
                                                                      pfx_lst_node_t *pfx_lst_node );

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
        XFREE(pfx_lst_node);

    } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr) ;

    assert(IS_GLTHREAD_LIST_EMPTY(&prefix_lst->glue));

    XFREE(prefix_lst);
    return 0;
}

static inline bool
prefix_list_is_in_use (prefix_list_t *prefix_lst) {

    return prefix_lst->ref_count > 1;
}

#endif 