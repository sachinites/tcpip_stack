#ifndef __ISIS_INTF_GRP__
#define __ISIS_INTF_GRP__

#define ISIS_INTF_GRP_NAME_LEN  32

typedef struct isis_adjacency_ isis_adjacency_t;

typedef struct isis_intf_group_ {

    char name[ISIS_INTF_GRP_NAME_LEN];  /* key */
    glthread_t intf_list_head;
    avltree_node_t avl_glue;
} isis_intf_group_t;

void
isis_init_intf_group_avl_tree(avltree_t *avl_root);

isis_intf_group_t *
isis_intf_grp_look_up(node_t *node, char *intf_grp_name);

bool
isis_intf_group_insert_in_intf_grp_db(node_t *node, 
            isis_intf_group_t *intf_grp);

isis_intf_group_t *
isis_intf_group_create_new(char *grp_name);

bool
isis_intf_group_delete_by_name_from_intf_grp_db( 
            node_t *node, char *intf_grp_name);

void
isis_intf_group_remove_from_intf_grp_db(
            node_t *node, isis_intf_group_t *intf_grp);


int
isis_intf_group_add_intf_membership(isis_intf_group_t *intf_grp, 
                                                                interface_t *intf);

int
isis_intf_group_remove_intf_membership(isis_intf_group_t *intf_grp,
                                                                      interface_t *intf);

uint32_t
isis_show_one_interface_group(node_t *node, 
            isis_intf_group_t *intf_grp, uint32_t rc);

uint32_t
isis_show_all_interface_group(node_t *node);

int
isis_config_intf_grp(node_t *node, char *if_grp_name);

int
isis_un_config_intf_grp(node_t *node, char *if_grp_name);

void
isis_intf_grp_refresh_member_interface(interface_t *intf);

void
 isis_intf_grp_cleanup(node_t *node) ;

interface_t *
isis_intf_grp_get_first_active_intf_grp_member (
            node_t *node,
            isis_intf_group_t *intf_grp);
            
 int
 isis_config_dynamic_intf_grp(node_t *node) ;

 int
 isis_un_config_dynamic_intf_grp(node_t *node) ;

void
isis_dynamic_intf_grp_update_on_adjacency_create (
                    isis_adjacency_t *adjacency);

void
isis_dynamic_intf_grp_update_on_adjacency_delete (
                    isis_adjacency_t *adjacency);

void
isis_dynamic_intf_grp_build_intf_grp_db(node_t *node);

#endif /* __ISIS_INTF_GRP__*/