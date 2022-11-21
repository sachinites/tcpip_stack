#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "Threads/refcount.h"
#include "../graph.h"
#include "../Layer3/rt_table/nexthop.h"
#include "../Layer3/layer3.h"
#include "snp_flow.h"

void
snp_flow_mem_init() {

    MM_REG_STRUCT(0,  snp_flow_key_t);
    MM_REG_STRUCT(0,  snp_l2_flow_info_t);
    MM_REG_STRUCT(0,  snp_l3_flow_info_t);
    MM_REG_STRUCT(0,  snp_l4_flow_info_t);
    MM_REG_STRUCT(0, snp_flow_t);
}

#define SNP_FLOW_KEY_ATTR_COMPARE(flow_ptr1, flow_ptr2, key_name)   \
{                                                                                               \
    snp_flow_key_t *_key1 = &flow_ptr1->flow_key;            \
    snp_flow_key_t *_key2 = &flow_ptr1->flow_key;            \
    if (_key1->is_##key_name##_set) {                                    \
        if (_key2->is_##key_name##_set) {                                \
            if (_key1->key_name < _key2->key_name)                \
                return 1;                                                                    \
            else if (_key1->key_name > _key2->key_name)         \
                return -1;                                                                   \
        } else return -1;                                                                 \
    } else if (_key2->is_##key_name##_set)                             \
        return 1;                                                                             \
}

static int
 snp_flow_compare_fn (const avltree_node_t *_c1_new, 
                                      const avltree_node_t *_c2_existing) {

    snp_flow_t *flow1 = avltree_container_of(_c1_new, snp_flow_t, avl_node);
    snp_flow_t *flow2 = avltree_container_of(_c2_existing, snp_flow_t, avl_node);

    SNP_FLOW_KEY_ATTR_COMPARE(flow1, flow2, src_ip);
    SNP_FLOW_KEY_ATTR_COMPARE(flow1, flow2, dst_ip);
    SNP_FLOW_KEY_ATTR_COMPARE(flow1, flow2, ip_proto);
    SNP_FLOW_KEY_ATTR_COMPARE(flow1, flow2, src_port_no);
    SNP_FLOW_KEY_ATTR_COMPARE(flow1, flow2, dst_port_no);
    return 0;
}

void
snp_flow_init_flow_tree_root (avltree_t *avl_root) {

    avltree_init(avl_root, snp_flow_compare_fn);
}

snp_flow_t *
snp_flow_calloc() {

    snp_flow_t *flow = (snp_flow_t *)XCALLOC(0, 1, snp_flow_t);
    return flow;
}

bool
snp_flow_insert_into_avl_tree (avltree_t *avl_root, snp_flow_t *flow){

    if (avltree_insert(&flow->avl_node, avl_root) ) return true;
    return false;
}

bool
snp_flow_remove_from_avl_tree (avltree_t *avl_root, snp_flow_t *flow) {

    avltree_remove(&flow->avl_node, avl_root);
    return true;
}

snp_flow_t *
snp_flow_lookup_from_avl_tree (avltree_t *avl_root, snp_flow_key_t flow_key) {

    snp_flow_t dummy_flow;
    avltree_node_t *flow_avl_node;
    memcpy(&dummy_flow.flow_key, &flow_key, sizeof(snp_flow_key_t));
    flow_avl_node = avltree_lookup(&dummy_flow.avl_node, avl_root);
    if (flow_avl_node) {
        return avltree_container_of(flow_avl_node, snp_flow_t, avl_node);
    }
    return NULL;
}

void
snp_flow_print_one_flow (node_t *node, snp_flow_t *flow) {
    
    
}