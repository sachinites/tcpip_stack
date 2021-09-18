#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf_group.h"

static int
isis_compare_intf_groups(const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_intf_group_t *intf_grp1 = avltree_container_of(n1, isis_intf_group_t, avl_glue);
    isis_intf_group_t *intf_grp2 = avltree_container_of(n2, isis_intf_group_t, avl_glue);

    return strncmp(intf_grp1->name, intf_grp2->name, ISIS_INTF_GRP_NAME_LEN);
}

void
isis_init_intf_group_avl_tree(avltree_t *avl_root) {

     avltree_init(avl_root, isis_compare_intf_groups);
}


isis_intf_group_t *
isis_look_up_intf_group(node_t *node, char *intf_grp_name) {

    isis_intf_group_t dummy_intf_grp;
    isis_node_info_t *isis_node_info; 

    isis_node_info = ISIS_NODE_INFO(node);

    strncpy(dummy_intf_grp.name, intf_grp_name, ISIS_INTF_GRP_NAME_LEN);
    
    avltree_node_t *avl_node =
        avltree_lookup(&dummy_intf_grp.avl_glue , &isis_node_info->intf_grp_avl_root);

    if (!avl_node) return NULL;
    return avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
}

bool
isis_intf_group_insert_in_intf_grp_db(node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *isis_node_info; 

    isis_node_info = ISIS_NODE_INFO(node);
    
    if (avltree_insert(&intf_grp->avl_glue, &isis_node_info->intf_grp_avl_root))
        return true;

    return false;
}

isis_intf_group_t *
isis_intf_group_create_new(char *grp_name) {

    isis_intf_group_t *intf_grp;

    intf_grp = XCALLOC(0, 1, isis_intf_group_t);
    assert(intf_grp);
    strncpy(intf_grp->name, grp_name, ISIS_INTF_GRP_NAME_LEN);
    intf_grp->last_lsp_xmit_seq_no = 0;
    init_glthread(&intf_grp->intf_list_head);
    return intf_grp;
}

bool
isis_intf_group_delete_by_name_from_intf_grp_db(
            node_t *node, char *intf_grp_name) {

    isis_intf_group_t *intf_grp;
    isis_node_info_t *isis_node_info; 

     isis_node_info = ISIS_NODE_INFO(node);
     intf_grp = isis_look_up_intf_group(node, intf_grp_name);
     if (!intf_grp) return false;
     avltree_remove(&intf_grp->avl_glue, &isis_node_info->intf_grp_avl_root);
    return true;
}

void
isis_intf_group_delete_from_intf_grp_db(
            node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *isis_node_info;

    isis_node_info = ISIS_NODE_INFO(node);
    avltree_remove(&intf_grp->avl_glue, &isis_node_info->intf_grp_avl_root);
}
