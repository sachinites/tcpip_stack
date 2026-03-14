#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_intf_group.h"
#include "isis_adjacency.h"
#include "isis_utils.h"

static int
isis_compare_intf_groups (const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_intf_group_t *intf_grp1 = avltree_container_of(n1, isis_intf_group_t, avl_glue);
    isis_intf_group_t *intf_grp2 = avltree_container_of(n2, isis_intf_group_t, avl_glue);

    return string_compare(intf_grp1->name, intf_grp2->name, ISIS_INTF_GRP_NAME_LEN);
}

void
isis_init_intf_group_avl_tree (avltree_t *avl_root) {

     avltree_init(avl_root, isis_compare_intf_groups);
}


isis_intf_group_t *
isis_intf_grp_look_up (isis_node_info_t *node_info, char *intf_grp_name) {

    isis_intf_group_t dummy_intf_grp = {0};

    string_copy((char *)dummy_intf_grp.name, intf_grp_name, ISIS_INTF_GRP_NAME_LEN);
    
    avltree_node_t *avl_node =
        avltree_lookup(&dummy_intf_grp.avl_glue , &node_info->intf_grp_avl_root);

    if (!avl_node) return NULL;
    return avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
}

bool
isis_intf_group_insert_in_intf_grp_db (isis_node_info_t *node_info, isis_intf_group_t *intf_grp) {

    if (!avltree_insert(&intf_grp->avl_glue, &node_info->intf_grp_avl_root))
        return true;

    return false;
}

isis_intf_group_t *
isis_intf_group_create_new (char *grp_name) {

    isis_intf_group_t *intf_grp;
    intf_grp = XCALLOC2(0, 1, isis_intf_group_t);
    assert(intf_grp);
    string_copy((char *)intf_grp->name, grp_name, ISIS_INTF_GRP_NAME_LEN);
    init_glthread(&intf_grp->intf_list_head);
    return intf_grp;
}

bool
isis_intf_group_delete_by_name_from_intf_grp_db (
            isis_node_info_t *node_info, char *intf_grp_name) {

    isis_intf_group_t *intf_grp;

     intf_grp = isis_intf_grp_look_up(node_info, intf_grp_name);
     if (!intf_grp) return false;
     avltree_remove(&intf_grp->avl_glue, &node_info->intf_grp_avl_root);
    return true;
}

void
isis_intf_group_remove_from_intf_grp_db (
            isis_node_info_t *node_info, isis_intf_group_t *intf_grp) {

    avltree_remove(&intf_grp->avl_glue, &node_info->intf_grp_avl_root);
}

static bool
isis_intf_grp_is_member_intf_active(Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    isis_adjacency_t *adjacency =
        isis_find_adjacency_on_interface(intf_info->intf, NULL);

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
                                     Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) {
        cprintf(ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF "\n");
        return -1;
    }

    if (intf_info->intf_type != isis_intf_type_p2p) return -1;

    if (intf_info->intf_grp == intf_grp) return -1;
    intf_info->intf_grp = intf_grp;
    isis_intf_grp_refresh_member_interface(intf);
    return 0;
}

void
isis_intf_grp_refresh_member_interface (Interface *intf) {

    isis_intf_group_t *intf_grp;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    intf_grp = intf_info->intf_grp;

    assert(intf_grp);

    remove_glthread (&intf_info->intf_grp_member_glue);
    glthread_priority_insert(&intf_grp->intf_list_head,
                             &intf_info->intf_grp_member_glue,
                             intf_grp_membership_add_comp_fn,
                             offsetof(isis_intf_info_t, intf_grp_member_glue));
}

int
isis_intf_group_remove_intf_membership (isis_intf_group_t *intf_grp,
                                                                      Interface *intf) {

    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    if (!intf_info) {
        cprintf(ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF "\n");
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
                        
    Interface *intf = adjacency->intf;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(adjacency->intf);
    isis_intf_group_t *intf_grp = intf_info->intf_grp;
    isis_node_info_t *node_info = ISIS_CTX_INTF(adjacency->intf);

    if (!node_info               ||
        !node_info->dyn_intf_grp ||
        !intf_info               ||
        !intf_grp)
        return;

    isis_intf_group_remove_intf_membership (intf_grp, intf_info->intf);

    if (IS_GLTHREAD_LIST_EMPTY(&intf_grp->intf_list_head) &&
         node_info->dyn_intf_grp) {

        isis_intf_group_remove_from_intf_grp_db(node_info, intf_grp);
        XFREE(intf_grp);
    }
}

uint32_t
isis_show_one_interface_group(isis_node_info_t *node_info,
                              isis_intf_group_t *intf_grp,
                              uint32_t rc) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    uint32_t bytes_written = rc;

    byte *buff = node_info->vrf->node->print_buff;

    if ( !isis_is_protocol_enable_on_node(node_info->vrf) ) return 0;

    rc += cprintf ("Intf-grp name : %s\n", intf_grp->name);
    rc += cprintf ("  Member Interfaces : ");

    ITERATE_GLTHREAD_BEGIN (&intf_grp->intf_list_head, curr) {

        intf_info = intf_grp_member_glue_to_intf_info(curr);
        rc += cprintf ("  %s%s  ",
                                intf_info->intf->if_name.c_str(),
                                isis_intf_grp_is_member_intf_active(intf_info->intf) ? "*" : "");

    } ITERATE_GLTHREAD_END (&intf_grp->intf_list_head, curr) 

    rc += cprintf ( "\n");
    bytes_written  = rc - bytes_written;
   return bytes_written;
}

uint32_t
isis_show_all_interface_group(isis_node_info_t *node_info) {

    uint32_t rc;
    avltree_node_t *avl_node;
    isis_intf_group_t *intf_grp;

    byte *buff = node_info->vrf->node->print_buff;

    if ( !isis_is_protocol_enable_on_node(node_info->vrf) ) return 0;
    
    rc = cprintf ("Interface Groups : \n");

    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
        rc += isis_show_one_interface_group (node_info, intf_grp, rc);
    } ITERATE_AVL_TREE_END;
    return rc;
}

int
isis_config_intf_grp (isis_node_info_t *node_info, char *if_grp_name) {

    isis_intf_group_t *intf_grp;

    if (!isis_is_protocol_enable_on_node(node_info->vrf)) {
        cprintf(ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    if (node_info->dyn_intf_grp) {
        node_info->dyn_intf_grp = false;
        isis_intf_grp_cleanup(node_info);
    }

    intf_grp = isis_intf_group_create_new(if_grp_name);

    if (!isis_intf_group_insert_in_intf_grp_db(node_info, intf_grp)) {

        cprintf("Error : Intf-grp Already Exist\n");
        XFREE(intf_grp);
        return -1;
    }
    return 0;
}

int
isis_un_config_intf_grp (isis_node_info_t *node_info, char *if_grp_name) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    isis_intf_group_t *intf_grp;

    if (!isis_is_protocol_enable_on_node(node_info->vrf)) return 0;

    if (node_info->dyn_intf_grp) {
        cprintf("Error : Dynamic Intf-grp is enabled\n");
        return -1;
    }

    intf_grp = isis_intf_grp_look_up(node_info, if_grp_name);

    if (!intf_grp) return -1;

    ITERATE_GLTHREAD_BEGIN(&intf_grp->intf_list_head, curr) {

        intf_info = intf_grp_member_glue_to_intf_info(curr);
        isis_intf_group_remove_intf_membership(intf_grp, intf_info->intf);
    } ITERATE_GLTHREAD_END(&intf_grp->intf_list_head, curr)
    
    isis_intf_group_remove_from_intf_grp_db(node_info, intf_grp);

    if (avltree_is_empty(&node_info->intf_grp_avl_root)) {
        node_info->dyn_intf_grp = true;
        isis_dynamic_intf_grp_build_intf_grp_db(node_info);
        cprintf("Info : Switched to Dynamic interface Group\n"); 
    }
    return 0;
}

static bool
isis_intf_grp_test_membership ( isis_intf_group_t *intf_grp, 
                                                     Interface *intf) {

     isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
     if (!intf_info) return false;
     return intf_info->intf_grp == intf_grp;
}

void
 isis_intf_grp_cleanup(isis_node_info_t *node_info) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    avltree_node_t *avl_node;
    isis_intf_group_t *intf_grp;

    if (!node_info) return;

    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);
        
        ITERATE_GLTHREAD_BEGIN(&intf_grp->intf_list_head, curr) {

            intf_info =  intf_grp_member_glue_to_intf_info(curr);
            remove_glthread(&intf_info->intf_grp_member_glue);
            intf_info->intf_grp = NULL;

        } ITERATE_GLTHREAD_END(intf_grp->intf_list_head, curr);

        isis_intf_group_remove_from_intf_grp_db(node_info, intf_grp);
        XFREE(intf_grp);
        
    } ITERATE_AVL_TREE_END;
 }

 Interface *
 isis_intf_grp_get_first_active_intf_grp_member (
            isis_node_info_t *node_info,
            isis_intf_group_t *intf_grp) {

    glthread_t *first;
    isis_intf_info_t *intf_info;

    first = intf_grp->intf_list_head.right;
    
    if (!first) return NULL;
    intf_info = intf_grp_member_glue_to_intf_info(first);
    return intf_info->intf;
 }

 int
 isis_config_dynamic_intf_grp (isis_node_info_t *node_info) {

    if ( !node_info ) {
        cprintf (ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    if (node_info->dyn_intf_grp) return 0;

    if ( !avltree_is_empty(&node_info->intf_grp_avl_root )) {
        cprintf("Error : Static interface Group(s) is/are configured\n");
        return -1;
    }

    node_info->dyn_intf_grp = true;
    isis_dynamic_intf_grp_build_intf_grp_db (node_info);
    return 0;
 }

 int
 isis_un_config_dynamic_intf_grp (isis_node_info_t *node_info) {

     if ( !node_info ) {
         return 0;
     }

     if (node_info->dyn_intf_grp == false ) {
         return 0;
     }
     
     node_info->dyn_intf_grp = false;
     isis_intf_grp_cleanup(node_info);
     return 0;
 }

/* Dynamic interface Groups */
void
isis_dynamic_intf_grp_update_on_adjacency_create (
                    isis_adjacency_t *adjacency) {

    isis_node_info_t *node_info;
    Interface *intf;
    char nbr_rtr_id_str[IPV4_ADDR_LEN_STR];
    isis_intf_info_t *intf_info;
    isis_intf_group_t *intf_grp;
    
    intf = adjacency->intf;
    intf_info = ISIS_INTF_INFO(intf);
    node_info = ISIS_CTX_INTF(intf);

    if (!node_info || !intf_info || !node_info->dyn_intf_grp || 
        (intf_info->intf_type != isis_intf_type_p2p)) {
        return;
    }

    tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id, nbr_rtr_id_str);
    intf_grp = isis_intf_grp_look_up (node_info, nbr_rtr_id_str);

    if (!intf_grp) {
        intf_grp = isis_intf_group_create_new (nbr_rtr_id_str);
        assert(isis_intf_group_insert_in_intf_grp_db(node_info,  intf_grp));
    }

    isis_intf_group_add_intf_membership(intf_grp, intf);
}

void
isis_dynamic_intf_grp_update_on_adjacency_delete (
                    isis_adjacency_t *adjacency) {

    isis_node_info_t *node_info;
    Interface *intf;
    char nbr_rtr_id_str[IPV4_ADDR_LEN_STR];
    isis_intf_group_t *intf_grp;
    isis_intf_info_t *intf_info;
    
    intf = adjacency->intf;
    intf_info = ISIS_INTF_INFO(intf);
    node_info = ISIS_CTX_INTF(intf);

    if (!node_info || !intf_info || !node_info->dyn_intf_grp) {
        return;
    }

    tcp_ip_covert_ip_n_to_p (adjacency->nbr_rtr_id,  nbr_rtr_id_str);
    intf_grp = isis_intf_grp_look_up (node_info, nbr_rtr_id_str);
    if (!intf_grp) return;

   isis_intf_group_remove_intf_membership (intf_grp, intf);

    if (IS_GLTHREAD_LIST_EMPTY(&intf_grp->intf_list_head)) {

        isis_intf_group_remove_from_intf_grp_db(node_info, intf_grp);
        XFREE(intf_grp);
    }
}

void
isis_dynamic_intf_grp_build_intf_grp_db (isis_node_info_t *node_info) {

    glthread_t *curr;
    Interface *intf;
    isis_intf_info_t *intf_info;
    isis_adjacency_t *adjacency;

    ITERATE_NODE_ISIS_INTERFACES_BEGIN (node_info, intf) {

        intf_info = ISIS_INTF_INFO(intf);
        if (!intf_info) continue;
        assert (!intf_info->intf_grp);
        if (intf_info->intf_type != isis_intf_type_p2p) continue;
        
        ITERATE_GLTHREAD_BEGIN(&intf_info->adj_list_head, curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            isis_dynamic_intf_grp_update_on_adjacency_create (adjacency);
        } ITERATE_GLTHREAD_END(&intf_info->adj_list_head, curr);

    } ITERATE_NODE_ISIS_INTERFACES_END;
}
