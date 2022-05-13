#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_intf_group.h"
#include "isis_adjacency.h"

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
isis_intf_grp_look_up (node_t *node, char *intf_grp_name) {

    isis_intf_group_t dummy_intf_grp;
    isis_node_info_t *node_info; 

    node_info = ISIS_NODE_INFO(node);

    strncpy(dummy_intf_grp.name, intf_grp_name, ISIS_INTF_GRP_NAME_LEN);
    
    avltree_node_t *avl_node =
        avltree_lookup(&dummy_intf_grp.avl_glue , &node_info->intf_grp_avl_root);

    if (!avl_node) return NULL;
    return avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
}

bool
isis_intf_group_insert_in_intf_grp_db (node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *node_info; 

    node_info = ISIS_NODE_INFO(node);
    
    if (!avltree_insert(&intf_grp->avl_glue, &node_info->intf_grp_avl_root))
        return true;

    return false;
}

isis_intf_group_t *
isis_intf_group_create_new (char *grp_name) {

    isis_intf_group_t *intf_grp;
    intf_grp = XCALLOC(0, 1, isis_intf_group_t);
    assert(intf_grp);
    strncpy(intf_grp->name, grp_name, ISIS_INTF_GRP_NAME_LEN);
    init_glthread(&intf_grp->intf_list_head);
    return intf_grp;
}

bool
isis_intf_group_delete_by_name_from_intf_grp_db (
            node_t *node, char *intf_grp_name) {

    isis_intf_group_t *intf_grp;
    isis_node_info_t *node_info; 

     node_info = ISIS_NODE_INFO(node);
     intf_grp = isis_intf_grp_look_up(node, intf_grp_name);
     if (!intf_grp) return false;
     avltree_remove(&intf_grp->avl_glue, &node_info->intf_grp_avl_root);
    return true;
}

void
isis_intf_group_remove_from_intf_grp_db (
            node_t *node, isis_intf_group_t *intf_grp) {

    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);
    avltree_remove(&intf_grp->avl_glue, &node_info->intf_grp_avl_root);
}

static bool
isis_intf_grp_is_member_intf_active(interface_t *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    isis_adjacency_t *adjacency =
        isis_find_adjacency_on_interface(intf_info->intf, 0);

    if (intf_info->intf_grp &&
         adjacency               &&
         adjacency->adj_state == ISIS_ADJ_STATE_UP) {
             
             return true;
    }
    return false;
}

static int
intf_grp_membership_add_comp_fn(void *n1, void *n2) {

    isis_intf_info_t *intf_info1 = (isis_intf_info_t *)n1;

    if (isis_intf_grp_is_member_intf_active(intf_info1->intf)) {
        return -1;
    }
    return 1;
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
    intf_info->intf_grp = intf_grp;
    isis_intf_grp_refresh_member_interface(intf);
    return 0;
}

void
isis_intf_grp_refresh_member_interface (interface_t *intf) {

    isis_intf_group_t *intf_grp;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    intf_grp = intf_info->intf_grp;

    assert(intf_grp);

    remove_glthread (&intf_info->intf_grp_member_glue);
    glthread_priority_insert(&intf_grp->intf_list_head,
                             &intf_info->intf_grp_member_glue,
                             intf_grp_membership_add_comp_fn,
                             offsetof(isis_intf_info_t, intf_grp_member_glue));

    sprintf(tlb, "%s : Refresh interface Grp %s with interface %s\n",
            ISIS_ADJ_MGMT, intf_grp->name, intf->if_name);
    tcp_trace(intf->att_node, intf, tlb);
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

void
isis_dynamic_intf_group_remove_intf_membership (
                    isis_adjacency_t *adjacency) { 
                        
    interface_t *intf = adjacency->intf;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(adjacency->intf);
    isis_intf_group_t *intf_grp = intf_info->intf_grp;
    isis_node_info_t *node_info = ISIS_NODE_INFO(adjacency->intf->att_node);

    if (!node_info                         ||
        !node_info->dyn_intf_grp ||
        !intf_info                            ||
        !intf_grp)
        return;

    isis_intf_group_remove_intf_membership (intf_grp, intf_info->intf);

    if (IS_GLTHREAD_LIST_EMPTY(&intf_grp->intf_list_head) &&
         node_info->dyn_intf_grp) {

        isis_intf_group_remove_from_intf_grp_db(intf->att_node, intf_grp);
        XFREE(intf_grp);
    }
}

uint32_t
isis_show_one_interface_group(node_t *node,
                              isis_intf_group_t *intf_grp,
                              uint32_t rc) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    isis_node_info_t *node_info;
    uint32_t bytes_written = rc;

    byte *buff = node->print_buff;

    node_info = ISIS_NODE_INFO(node);
    
    if ( !isis_is_protocol_enable_on_node(node) ) return 0;

    rc += sprintf (buff + rc, "Intf-grp name : %s\n", intf_grp->name);
    rc += sprintf (buff + rc, "  Member Interfaces : ");

    ITERATE_GLTHREAD_BEGIN (&intf_grp->intf_list_head, curr) {

        intf_info = intf_grp_member_glue_to_intf_info(curr);
        rc += sprintf (buff + rc,  "  %s%s  ",
                                intf_info->intf->if_name,
                                isis_intf_grp_is_member_intf_active(intf_info->intf) ? "*" : "");

    } ITERATE_GLTHREAD_END (&intf_grp->intf_list_head, curr) 

    rc += sprintf ( buff + rc, "\n");
    bytes_written  = rc - bytes_written;
   return bytes_written;
}

uint32_t
isis_show_all_interface_group(node_t *node) {

    uint32_t rc;
    avltree_node_t *avl_node;
    isis_intf_group_t *intf_grp;
    isis_node_info_t *node_info;
    
    byte *buff = node->print_buff;
    node_info = ISIS_NODE_INFO(node);

    if ( !isis_is_protocol_enable_on_node(node) ) return 0;
    
    rc = sprintf (buff,  "Interface Groups : \n");

    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
        rc += isis_show_one_interface_group (node, intf_grp, rc);
    } ITERATE_AVL_TREE_END;
    return rc;
}

int
isis_config_intf_grp (node_t *node, char *if_grp_name) {

    isis_intf_group_t *intf_grp;
    isis_node_info_t *node_info;

    if (!isis_is_protocol_enable_on_node(node)) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    node_info = ISIS_NODE_INFO(node);

    if (node_info->dyn_intf_grp) {
        node_info->dyn_intf_grp = false;
        isis_intf_grp_cleanup(node);
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

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    isis_intf_group_t *intf_grp;

    if (!isis_is_protocol_enable_on_node(node)) return 0;

    if (ISIS_NODE_INFO(node)->dyn_intf_grp) {
        printf("Error : Dynamic Intf-grp is enabled\n");
        return -1;
    }

    intf_grp = isis_intf_grp_look_up(node, if_grp_name);

    if (!intf_grp) return -1;

    ITERATE_GLTHREAD_BEGIN(&intf_grp->intf_list_head, curr) {

        intf_info = intf_grp_member_glue_to_intf_info(curr);
        isis_intf_group_remove_intf_membership(intf_grp, intf_info->intf);
    } ITERATE_GLTHREAD_END(&intf_grp->intf_list_head, curr)
    
    isis_intf_group_remove_from_intf_grp_db(node, intf_grp);

    if (avltree_is_empty(&(ISIS_NODE_INFO(node)->intf_grp_avl_root))) {
        ISIS_NODE_INFO(node)->dyn_intf_grp = true;
        isis_dynamic_intf_grp_build_intf_grp_db(node);
        printf("Info : Switched to Dynamic interface Group\n"); 
    }
    return 0;
}

static bool
isis_intf_grp_test_membership ( isis_intf_group_t *intf_grp, 
                                                     interface_t *intf) {

     isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
     if (!intf_info) return false;
     return intf_info->intf_grp == intf_grp;
}

void
 isis_intf_grp_cleanup(node_t *node) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    avltree_node_t *avl_node;
    isis_intf_group_t *intf_grp;
    
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
        
        ITERATE_GLTHREAD_BEGIN(&intf_grp->intf_list_head, curr) {

            intf_info =  intf_grp_member_glue_to_intf_info(curr);
            remove_glthread(&intf_info->intf_grp_member_glue);
            intf_info->intf_grp = NULL;

        } ITERATE_GLTHREAD_END(intf_grp->intf_list_head, curr);

        isis_intf_group_remove_from_intf_grp_db(node, intf_grp);
        XFREE(intf_grp);
        
    } ITERATE_AVL_TREE_END;
 }

 interface_t *
 isis_intf_grp_get_first_active_intf_grp_member (
            node_t *node,
            isis_intf_group_t *intf_grp) {

    glthread_t *first;
    isis_intf_info_t *intf_info;

    first = intf_grp->intf_list_head.right;
    
    if (!first) return NULL;
    intf_info = intf_grp_member_glue_to_intf_info(first);
    return intf_info->intf;
 }

 int
 isis_config_dynamic_intf_grp (node_t *node) {

     isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if ( !node_info ) {
        printf (ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    if (node_info->dyn_intf_grp) return 0;

    if ( !avltree_is_empty(&node_info->intf_grp_avl_root )) {
        printf("Error : Static interface Group(s) is/are configured\n");
        return -1;
    }

    node_info->dyn_intf_grp = true;
    isis_dynamic_intf_grp_build_intf_grp_db (node);
 }

 int
 isis_un_config_dynamic_intf_grp (node_t *node) {

     isis_node_info_t *node_info = ISIS_NODE_INFO(node);

     if ( !node_info ) {
         return 0;
     }

     if (node_info->dyn_intf_grp == false ) {
         return 0;
     }
     
     node_info->dyn_intf_grp = false;
     isis_intf_grp_cleanup(node);
     return 0;
 }

/* Dynamic interface Groups */
void
isis_dynamic_intf_grp_update_on_adjacency_create (
                    isis_adjacency_t *adjacency) {

    node_t *node;
    interface_t *intf;
    isis_intf_info_t *intf_info;
    isis_intf_group_t *intf_grp;
    
    intf = adjacency->intf;
    intf_info = ISIS_INTF_INFO(intf);
    node = intf->att_node;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info || !intf_info || !node_info->dyn_intf_grp) {
        return;
    }

    char *nbr_rtr_id_str = tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id, 0);
    intf_grp = isis_intf_grp_look_up (node, nbr_rtr_id_str);

    if (!intf_grp) {
        intf_grp = isis_intf_group_create_new (nbr_rtr_id_str);
        assert(isis_intf_group_insert_in_intf_grp_db(node,  intf_grp));
    }

    isis_intf_group_add_intf_membership(intf_grp, intf);
}

void
isis_dynamic_intf_grp_update_on_adjacency_delete (
                    isis_adjacency_t *adjacency) {

    node_t *node;
    interface_t *intf;
    isis_intf_group_t *intf_grp;
    isis_intf_info_t *intf_info;
    
    intf = adjacency->intf;
    intf_info = ISIS_INTF_INFO(intf);
    node = intf->att_node;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info || !intf_info || !node_info->dyn_intf_grp) {
        return;
    }

    char *nbr_rtr_id_str = tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id, 0);
    intf_grp = isis_intf_grp_look_up (node, nbr_rtr_id_str);
    assert(intf_grp);

   isis_intf_group_remove_intf_membership (intf_grp, intf);

    if (IS_GLTHREAD_LIST_EMPTY(&intf_grp->intf_list_head)) {

        isis_intf_group_remove_from_intf_grp_db(node, intf_grp);
        XFREE(intf_grp);
    }
}

void
isis_dynamic_intf_grp_build_intf_grp_db (node_t *node) {

    glthread_t *curr;
    interface_t *intf;
    isis_intf_info_t *intf_info;
    isis_adjacency_t *adjacency;
    isis_node_info_t *node_info;
    
    node_info = ISIS_NODE_INFO(node);

    ITERATE_NODE_INTERFACES_BEGIN (node, intf) {

        intf_info = ISIS_INTF_INFO(intf);
        if (!intf_info) continue;
        assert (!intf_info->intf_grp);
        ITERATE_GLTHREAD_BEGIN(&intf_info->adj_list_head, curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            isis_dynamic_intf_grp_update_on_adjacency_create (adjacency);
        } ITERATE_GLTHREAD_END(&intf_info->adj_list_head, curr);

    } ITERATE_NODE_INTERFACES_END (node, intf)
}
