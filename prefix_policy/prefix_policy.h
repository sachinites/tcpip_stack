#ifndef __PREFIX_IMPORT__
#define __PREFIX_IMPORT__

#define POLICY_NAME_LEN  64

#include <stdint.h>
#include <stdbool.h>
#include "../Tree/libtree.h"

typedef avltree_t policy_db_t;

typedef struct policy_prefix_action_template_ {
    bool metric_set;
    uint32_t metric;
}policy_prefix_action_template_t;

typedef struct policy_prefix_ {

     avltree_node_t glue;
     /* Filter Criteria */
     uint32_t prefix;
     uint8_t mask;
     uint8_t protocol;

    /* Action to be applied*/
    bool metric_set;
     uint32_t metric;
} policy_prefix_t;

typedef struct policy_ {

    unsigned char name[POLICY_NAME_LEN];
    avltree_node_t glue;
    avltree_t prefix_tree;
    uint16_t ref_count;
} policy_t;

void
policy_init (policy_db_t *policy_db);

policy_t *
policy_get(policy_db_t *policy_db, unsigned char *policy_name) ;

void
policy_dereference (policy_db_t *policy_db, policy_t *policy);

void
policy_reference (policy_t *policy);

policy_prefix_t *
policy_add_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto);

void
policy_prefix_set_action_matric(policy_prefix_t *pprefix, uint32_t metric);

void
policy_prefix_unset_action_matric(policy_prefix_t *pprefix, uint32_t metric);

void
policy_delete_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto);

policy_t *
policy_lookup(policy_db_t *policy_db, unsigned char *policy_name);

 policy_prefix_t *
 policy_lookup_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto);

bool
policy_evaluate (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto, 
                            policy_prefix_action_template_t *act_template);

#endif