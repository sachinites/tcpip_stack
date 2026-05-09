#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "LinuxMemoryManager/uapi_mm.h"
#include "../prefix-list/prefixlst.h"

extern int (*stdlib_printf)(const char *format, ...);

prefix_list_t *
prefix_lst_lookup_by_name (pfxlst_db *pfxlstdb, unsigned char *pfxlst_name) {

    glthread_t *curr;
    prefix_list_t *prefix_lst;

    ITERATE_GLTHREAD_BEGIN(pfxlstdb, curr) {

        prefix_lst = glue_to_pfx_lst(curr);
        
        if (strncmp (prefix_lst->name, pfxlst_name, PFX_LST_NAME_LEN) == 0) {
            return prefix_lst;
        }

    } ITERATE_GLTHREAD_END(pfxlstdb, curr);
    
    return NULL;
}

static pfx_lst_node_t *
prefix_lst_node_lookup (prefix_list_t *prefix_lst, pfx_lst_node_t *pfx_lst_node_template) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

   ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);

        if (pfx_lst_node->pfx == pfx_lst_node_template->pfx &&
             pfx_lst_node->pfx_len == pfx_lst_node_template->pfx_len &&
             pfx_lst_node->lb == pfx_lst_node_template->lb &&
             pfx_lst_node->ub == pfx_lst_node_template->ub) {

             return pfx_lst_node;
        }
   } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);

    return NULL;
}

static int
prefix_lst_node_comp_fn (void *arg1, void *arg2) {

    pfx_lst_node_t *new_node = (pfx_lst_node_t *)arg1;
    pfx_lst_node_t *existing_node = (pfx_lst_node_t *)arg2;

    if (new_node->seq_no == existing_node->seq_no) return 0;

    return  new_node->seq_no - existing_node->seq_no;
}

pfx_lst_node_t *
prefix_list_lookup_by_seq_no (prefix_list_t *prefix_lst, uint32_t seq_no) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

    if (!prefix_lst || seq_no == 0) return NULL;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        if (pfx_lst_node->seq_no == seq_no) return pfx_lst_node;

    } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);

    return NULL;
}

bool
prefix_list_add_rule (prefix_list_t *prefix_lst,
                                   uint32_t seq_no,
                                   pfx_lst_result_t res,
                                   uint32_t prefix,
                                   uint8_t len,
                                   int8_t lb,
                                   int8_t ub) {

    pfx_lst_node_t *pfx_lst_node;
    pfx_lst_node_t *pfx_lst_node_existing;

    /* seq_no must be unique within a prefix-list so that operations keyed
       on seq_no (delete, show) target exactly one rule. seq_no == 0 means
       "auto-assign" and is handled below. */
    if (seq_no && prefix_list_lookup_by_seq_no(prefix_lst, seq_no)) {
        return false;
    }

    pfx_lst_node = (pfx_lst_node_t *)calloc( 1, sizeof(pfx_lst_node_t));
    pfx_lst_node->pfx = prefix;
    pfx_lst_node->pfx_len = len;

    pfx_lst_node->lb = (lb == -1) ? len : lb;
    pfx_lst_node->ub = (ub == -1) ? len : ub;

    pfx_lst_node_existing = prefix_lst_node_lookup (prefix_lst, pfx_lst_node);

    if (pfx_lst_node_existing) {
        free(pfx_lst_node);
        pfx_lst_node = NULL;
        //stdlib_printf ("Error : This Prefix list rule already exists\n");
        return false;
    }

    pfx_lst_node->seq_no = !seq_no ? (prefix_lst->seq_no += PFX_LST_SEQ_NO_LAPS) : seq_no;
    pfx_lst_node->res = res;

    glthread_priority_insert (&prefix_lst->pfx_lst_head,
                                            &pfx_lst_node->glue,
                                            prefix_lst_node_comp_fn,
                                            (int)&((pfx_lst_node_t *)0)->glue);

    return true;
}

bool
prefix_list_del_rule (prefix_list_t *prefix_lst,
                                  uint32_t seq_no) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

     ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        if (pfx_lst_node->seq_no == seq_no) {
            remove_glthread(&pfx_lst_node->glue);
            free(pfx_lst_node);
            return true;
        }
     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);

    return false;
}

static void
print_pfx_lst_node ( prefix_list_t *prefix_lst, pfx_lst_node_t *pfx_lst_node) {

    unsigned char out_buff[16];

    uint32_t ip_addr_int = htonl(pfx_lst_node->pfx);

    stdlib_printf ("prefix-list %s %s %u %s/%d ge %d le %d (hit-count = %lu)\n",  
        prefix_lst->name,
        pfx_lst_node->res == PFX_LST_DENY ? "deny" : "permit",
        pfx_lst_node->seq_no,
        inet_ntop(AF_INET, &ip_addr_int, (char *)out_buff, 16),
        pfx_lst_node->pfx_len,
        pfx_lst_node->lb,
        pfx_lst_node->ub,
        pfx_lst_node->hit_count);
}


void
prefix_list_show (prefix_list_t *prefix_lst) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        print_pfx_lst_node (prefix_lst, pfx_lst_node);

     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);
}

pfx_lst_result_t
prefix_list_evaluate_against_pfx_lst_node (uint32_t prefix,
                                                                      uint8_t len,
                                                                      pfx_lst_node_t *pfx_lst_node) {

    bool rc = false;
    uint32_t subnet_mask = ~0;
    uint32_t input_binary_prefix = 0;
    uint32_t pfxlst_node_binary_prefix = 0;

    if (len < pfx_lst_node->lb) return PFX_LST_SKIP;

    if (pfx_lst_node->ub > -1 && 
        (len > pfx_lst_node->ub)) return PFX_LST_SKIP;
    
     /*Compute Mask in binary format as well*/
    if (pfx_lst_node->pfx_len) {
        subnet_mask = subnet_mask << (32 - pfx_lst_node->pfx_len);
    }
    else {
        subnet_mask = 0;
    }

    /*Perform logical AND to apply mask on IP address*/
    input_binary_prefix = prefix & subnet_mask;
    pfxlst_node_binary_prefix = pfx_lst_node->pfx & subnet_mask;

    rc = (input_binary_prefix == pfxlst_node_binary_prefix);

    if (!rc) {
        return PFX_LST_SKIP;
    }

    pfx_lst_node->hit_count++;
    return pfx_lst_node->res;
}

pfx_lst_result_t
prefix_list_evaluate (uint32_t prefix, uint8_t len, prefix_list_t *prefix_lst) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;
    pfx_lst_result_t res;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);

        res = prefix_list_evaluate_against_pfx_lst_node (prefix, len, pfx_lst_node);

        switch (res) {
            case PFX_LST_SKIP:
                continue;
            case PFX_LST_DENY:
            case PFX_LST_PERMIT:
                return res;
            case PFX_LST_UNKNOWN:
                assert(0);
        }

     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);    

    return PFX_LST_SKIP;
}


