#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_intf_group.h"

static int
isis_compare_intf_groups (const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_intf_group_t *intf_grp1 = avltree_container_of(n1, isis_intf_group_t, avl_glue);
    isis_intf_group_t *intf_grp2 = avltree_container_of(n2, isis_intf_group_t, avl_glue);

    return strncmp(intf_grp1->name, intf_grp2->name, ISIS_INTF_GRP_NAME_LEN);
}

void
isis_init_intf_group_avl_tree (avltree_t *avl_root) {

     avltree_init(avl_root, isis_compare_intf_groups);
}


isis_intf_group_t *
isis_look_up_intf_group (node_t *node, char *intf_grp_name) {

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
isis_intf_group_insert_in_intf_grp_db (node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *isis_node_info; 

    isis_node_info = ISIS_NODE_INFO(node);
    
    if (!avltree_insert(&intf_grp->avl_glue, &isis_node_info->intf_grp_avl_root))
        return true;

    return false;
}

isis_intf_group_t *
isis_intf_group_create_new (char *grp_name) {

    isis_intf_group_t *intf_grp;
    intf_grp = XCALLOC(0, 1, isis_intf_group_t);
    assert(intf_grp);
    strncpy(intf_grp->name, grp_name, ISIS_INTF_GRP_NAME_LEN);
    intf_grp->last_lsp_xmit_seq_no = 0;
    init_glthread(&intf_grp->intf_list_head);
    return intf_grp;
}

bool
isis_intf_group_delete_by_name_from_intf_grp_db (
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
isis_intf_group_delete_from_intf_grp_db (
            node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *isis_node_info;

    isis_node_info = ISIS_NODE_INFO(node);
    avltree_remove(&intf_grp->avl_glue, &isis_node_info->intf_grp_avl_root);
}

int
isis_intf_group_add_intf_membership (isis_intf_group_t *intf_grp, 
                                                                interface_t *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF "\n");
        return -1;
    }

    if (intf_info->intf_grp == intf_grp) return -1;

    remove_glthread(&intf_info->intf_grp_member_glue);
    intf_info->intf_grp = intf_grp;
    glthread_add_next(&intf_grp->intf_list_head, &intf_info->intf_grp_member_glue);
    return 0;
}

int
isis_intf_group_remove_intf_membership (isis_intf_group_t *intf_grp,
                                                                      interface_t *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF "\n");
        return -1;
    }

     if (intf_info->intf_grp != intf_grp) return -1;
     intf_info->intf_grp = NULL;
     remove_glthread(&intf_info->intf_grp_member_glue);
     return 0;
}

uint32_t
isis_show_one_interface_group (node_t *node, isis_intf_group_t *intf_grp, uint32_t rc) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    isis_node_info_t *isis_node_info;

    byte *buff = node->print_buff;

    isis_node_info = ISIS_NODE_INFO(node);
    
    if (!isis_is_protocol_enable_on_node(node)) return 0;

    rc += sprintf (buff + rc, "Intf-grp name : %s\n", intf_grp->name);
    rc += sprintf (buff + rc, "  Member Interfaces : ");

    ITERATE_GLTHREAD_BEGIN(&intf_grp->intf_list_head, curr) {

        intf_info = intf_grp_member_glue_to_intf_info(curr);
        rc += sprintf (buff + rc, "  %s  ", intf_info->intf->if_name);
    } ITERATE_GLTHREAD_END(&intf_grp->intf_list_head, curr) 

     rc += sprintf (buff + rc, "\n");
   return rc;
}

uint32_t
isis_show_all_interface_group(node_t *node) {

    uint32_t rc = 0;
    avltree_node_t *avl_node;
    isis_intf_group_t *intf_grp;
    isis_node_info_t *isis_node_info;
    
    byte *buff = node->print_buff;
    isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return 0;
    
    rc = sprintf(buff, "Interface Groups : \n");

    ITERATE_AVL_TREE_BEGIN(&isis_node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
        rc += isis_show_one_interface_group(node, intf_grp, rc);

    } ITERATE_AVL_TREE_END;

    return rc;
}

int
isis_config_intf_grp (node_t *node, char *if_grp_name) {

    isis_intf_group_t *intf_grp;

    if (!isis_is_protocol_enable_on_node(node)) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    intf_grp = isis_intf_group_create_new(if_grp_name);

    if (!isis_intf_group_insert_in_intf_grp_db(node, intf_grp)) {

        printf("Error : Intf-grp Already Exist\n");
        XFREE(intf_grp);
        return -1;
    }
    return 0;
}

int
isis_un_config_intf_grp (node_t *node, char *if_grp_name) {

    isis_intf_group_t *intf_grp;

    if (!isis_is_protocol_enable_on_node(node)) return 0;

    if (!isis_intf_group_delete_by_name_from_intf_grp_db(
                    node, if_grp_name) ) {
        printf("Error : Intf grp do not exist\n");
        return -1;
    }
    return 0;
}