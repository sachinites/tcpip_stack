#include "../tcp_public.h"
#include "ted.h"

int
avltree_prefix_tree_comp_fn(const avltree_node_t *n1, const avltree_node_t *n2) ;

int
avltree_prefix_tree_comp_fn(const avltree_node_t *n1, const avltree_node_t *n2) {

    ted_prefix_t *prefix1 = avltree_container_of (n1, ted_prefix_t, avl_glue);
    ted_prefix_t *prefix2 = avltree_container_of (n2, ted_prefix_t, avl_glue);

    if (prefix1->prefix != prefix2->prefix) {

        if (prefix1->prefix < prefix2->prefix) 
            return -1;
        return 1;
    }

    if (prefix1->mask != prefix2->mask) {

        if (prefix1->mask < prefix2->mask)
            return -1;
        return 1;
    }

    if (prefix1->metric != prefix2->metric) {

        if (prefix1->metric < prefix2->metric)
            return -1;
        return 1;
    }    

    if (prefix1->flags != prefix2->flags) {

        if (prefix1->flags < prefix2->flags)
            return -1;
        return 1;
    }       

    return 0;
}

int8_t 
ted_node_get_empty_slot(ted_node_t *node) {

    int8_t i = 0;

    for (i = 0; i < TEDN_MAX_INTF_PER_NODE; i++) {
        if (!node->intf[i]) return i;
    }
    return -1;
}

bool
ted_insert_link ( ted_node_t *node1, 
                           ted_node_t *node2, 
                           ted_link_t *ted_link ) {

    int rc = 0;
    rc = ted_plug_in_interface(node1, &ted_link->intf1);
    if (rc < 0) return false;
    rc = ted_plug_in_interface(node2, &ted_link->intf2);
    if (rc < 0) return false;
    return true;
}

int8_t
ted_plug_in_interface(ted_node_t *node, ted_intf_t *intf) {

    int8_t available_slot = ted_node_get_empty_slot(node);

    if (available_slot < 0) {
        assert(0);
    }

    if (ted_is_interface_plugged_in(intf)) {
        assert(0);
    }

    intf->att_node = node;
    node->intf[available_slot] = intf;
    intf->slot_no = available_slot;
    intf->link->dirn_flag ^= intf->att_node->rtr_id;
    return available_slot;
}

int8_t
ted_plug_out_interface(ted_intf_t *intf) {
    
    uint16_t slot_no;
    if (!ted_is_interface_plugged_in(intf)) {
        return -1;
    }
    slot_no = intf->slot_no;
    intf->link->dirn_flag ^= intf->att_node->rtr_id;
    intf->att_node->intf[intf->slot_no] = NULL;
    intf->att_node = NULL;
    intf->slot_no = 0;
    return slot_no;
}

bool
ted_is_interface_plugged_in(ted_intf_t *intf) {

    return (intf->att_node &&
                intf->att_node->intf[intf->slot_no] == intf &&
                intf->link->dirn_flag);
}

bool
ted_is_link_dettached(ted_link_t *ted_link) {

    if ( ted_is_interface_plugged_in(&ted_link->intf1) ||
            ted_is_interface_plugged_in(&ted_link->intf2) ) {
                return false;
    }
    return true;
}

void
ted_unplug_all_interfaces(ted_node_t *node) {

    ted_intf_t *intf;

    TED_ITERATE_NODE_INTF_BEGIN(node, intf) {

        ted_plug_out_interface(intf);

        if (ted_is_link_dettached(intf->link)) {
            XFREE(intf->link);
        }

    } TED_ITERATE_NODE_INTF_END(node, intf);
}

bool
ted_link_is_bidirectional (ted_link_t *ted_link) {

    uint32_t xor_rtr_id;

    ted_node_t *node1 = ted_link->intf1.att_node;
    ted_node_t *node2 = ted_link->intf2.att_node;

    if (!node1 || !node2) return false;
    xor_rtr_id = node1->rtr_id ^ node2->rtr_id;
    return xor_rtr_id == ted_link->dirn_flag;
}

ted_link_t *
ted_create_link ( ted_link_t *ted_link , 
                            uint32_t from_if_index,
                            uint32_t to_if_index,
                            uint32_t from_ip_addr,
                            uint8_t from_mask,
                            uint32_t to_ip_addr,
                            uint8_t to_mask ) {

    if ( !ted_link) {
        ted_link = XCALLOC(0, 1, ted_link_t);
    }
    else {
        memset(ted_link, 0, sizeof(ted_link_t));
    }

    ted_link->intf1.ifindex  = from_if_index;
    ted_link->intf1.ip_addr = from_ip_addr;
    ted_link->intf1.mask     = from_mask;
    ted_link->intf2.ifindex  = to_if_index;
    ted_link->intf2.ip_addr = to_ip_addr;
    ted_link->intf2.mask     = to_mask;
    ted_link->dirn_flag = 0;
    ted_link->intf1.link = ted_link;
    ted_link->intf2.link = ted_link;
    return ted_link;
}

static int
ted_db_default_cmp_fn (const avltree_node_t *n1, const avltree_node_t *n2) {

    ted_node_t *node1 = avltree_container_of (n1, ted_node_t, avl_glue);
    ted_node_t *node2 = avltree_container_of (n2, ted_node_t, avl_glue);

    return node1->rtr_id - node2->rtr_id;
}

void
ted_init_teddb(ted_db_t *ted_db,  avltree_cmp_fn_t cmp_fn)  {

    avltree_cmp_fn_t cmp_fn2;
    cmp_fn2 = cmp_fn ? cmp_fn : ted_db_default_cmp_fn;
    avltree_init(&ted_db->teddb, cmp_fn2);
}

ted_node_t *
ted_lookup_node(ted_db_t *ted_db, uint32_t rtr_id) {

    ted_node_t dummy_node, *res_node;
    
    dummy_node.rtr_id = rtr_id;

     avltree_node_t *avl_node =
        avltree_lookup(&dummy_node.avl_glue,  &ted_db->teddb);

    if (!avl_node) return NULL;
    res_node = avltree_container_of (avl_node, ted_node_t , avl_glue);
    assert(res_node->is_installed_in_teddb);
    return res_node;
}

void
ted_delete_node_by_id (ted_db_t *ted_db, uint32_t rtr_id) {

    ted_node_t *node = ted_lookup_node(ted_db, rtr_id);
    if (!node) return;
    ted_unplug_all_interfaces(node);
    avltree_remove(&node->avl_glue, &ted_db->teddb);
    assert(node->is_installed_in_teddb);
    node->is_installed_in_teddb = false;
    ted_prefix_tree_cleanup_tree(node);
    XFREE(node);
}

void
ted_delete_node (ted_db_t *ted_db, ted_node_t *ted_node) {

    ted_unplug_all_interfaces(ted_node);
    avltree_remove(&ted_node->avl_glue, &ted_db->teddb);
    assert(ted_node->is_installed_in_teddb);
    ted_node->is_installed_in_teddb = false;
    ted_prefix_tree_cleanup_tree(ted_node);
    XFREE(ted_node);
}

bool
ted_insert_node_in_teddb(ted_db_t *ted_db, ted_node_t *node) {

     assert(!node->is_installed_in_teddb);
     avltree_insert( &node->avl_glue, &ted_db->teddb);
     node->is_installed_in_teddb = true;
     return true;
}

ted_node_t *
ted_create_node (uint32_t rtr_id, bool is_fake) {

    ted_node_t *node = XCALLOC (0,  1, ted_node_t);
    node->is_fake = is_fake;
    node->rtr_id = rtr_id;
    node->prefix_tree_root = NULL;
    return node;
}

ted_intf_t *
ted_node_lookup_intf (ted_node_t *node, uint32_t ifindex) {

    ted_intf_t *intf;

    TED_ITERATE_NODE_INTF_BEGIN(node, intf) {

        if (intf->ifindex == ifindex) return intf;
    } TED_ITERATE_NODE_INTF_END (node, intf)
    return NULL;
}

ted_link_t *
ted_resurrect_link (ted_db_t *ted_db,
                                uint32_t from_node_rtr_id,
                                uint32_t from_if_index,
                                uint32_t local_ip,
                                uint32_t to_node_rtr_id,
                                uint32_t to_ifindex,
                                uint32_t remote_ip) {
    
    ted_link_t *link;
    bool to_node_new = false;
    bool from_node_new = false;

    ted_node_t *from_node = ted_lookup_node (ted_db, from_node_rtr_id);
    
    if (!from_node) {
        from_node = ted_create_node(from_node_rtr_id, false);
        ted_insert_node_in_teddb(ted_db, from_node);
        from_node_new = true;
    }

    from_node->is_fake = false;

    ted_node_t *to_node = ted_lookup_node (ted_db, to_node_rtr_id);
    if (!to_node) {
        to_node = ted_create_node (to_node_rtr_id, true);
        ted_insert_node_in_teddb(ted_db, to_node);
        to_node_new = true;
    }

    ted_intf_t *from_intf = from_node_new ?
            NULL : ted_node_lookup_intf (from_node, from_if_index);

    ted_intf_t *to_intf =to_node_new ?
            NULL :  ted_node_lookup_intf (to_node, to_ifindex);

    if ( !from_intf && to_intf ) {

        from_intf = ted_link_get_other_interface(to_intf);
        if (ted_is_interface_plugged_in(from_intf)) {
            ted_plug_out_interface(from_intf);
        }
        from_intf->ifindex = from_if_index;
        from_intf->ip_addr = local_ip;
        ted_plug_in_interface(
                            from_node, from_intf );
        link = from_intf->link;
        goto done;
    }

    else if ( from_intf && !to_intf ) {

        to_intf = ted_link_get_other_interface(from_intf);
        if (ted_is_interface_plugged_in(to_intf)) {
            ted_plug_out_interface(to_intf);
        }
        to_intf->ifindex = to_ifindex;
        to_intf->ip_addr = remote_ip;
        ted_plug_in_interface(
                            to_node, to_intf );
        link = to_intf->link;
        goto done;
    }

    else if (from_intf && to_intf ) { 
        
        if (from_intf->link == to_intf->link) {
            link = to_intf->link;
            goto done;
        }

         ted_plug_out_interface(from_intf);
         ted_plug_out_interface(to_intf);

        if (ted_is_link_dettached(from_intf->link)) {
            XFREE(from_intf->link);
        }
        if (ted_is_link_dettached(to_intf->link)) {
            XFREE(to_intf->link);
        }

        link = ted_create_link (0, from_if_index, to_ifindex, local_ip, 0, remote_ip, 0);
        ted_plug_in_interface(from_node, &link->intf1);
        ted_plug_in_interface(to_node, &link->intf2);
        goto done;
    }

    else {
        
        link = ted_create_link (0, from_if_index, to_ifindex, local_ip, 0, remote_ip, 0);
        ted_plug_in_interface(from_node, &link->intf1);
        ted_plug_in_interface(to_node, &link->intf2);
        goto done;
    }

done:
    return link;
}

void
ted_create_or_update_node (ted_db_t *ted_db,
            ted_template_node_data_t *template_node_data,
            avltree_t *prefix_tree_root) {

    uint8_t i = 0;
    ted_link_t * link;
    ted_node_t *node;
    ted_intf_t *from_intf, *to_intf;
    ted_template_nbr_data_t *nbr_data;

    /* Delete the node, we would create it again from scratch. This is 
        Simplification and a bit brute-force*/
    ted_delete_node_by_id(ted_db, template_node_data->rtr_id);

    node = ted_create_node(template_node_data->rtr_id, false);
    string_copy((char *)node->node_name, template_node_data->node_name, NODE_NAME_SIZE);
    node->flags = template_node_data->flags;
    node->seq_no = template_node_data->seq_no;
    ted_insert_node_in_teddb(ted_db, node);

    for ( ; i < template_node_data->n_nbrs; i++) {

       nbr_data = &template_node_data->nbr_data[i]; 
       link = ted_resurrect_link (ted_db, 
                                                template_node_data->rtr_id,  
                                                nbr_data->local_if_index, 
                                                nbr_data->local_ip,
                                                nbr_data->nbr_rtr_id, 
                                                nbr_data->remote_if_index,
                                                nbr_data->remote_ip);
       /* Fix up cost attributes */
       from_intf = &link->intf1;
       from_intf->cost = nbr_data->metric;
       to_intf = &link->intf2;
       to_intf->cost =  nbr_data->metric;
    }

    node->prefix_tree_root = prefix_tree_root;
    return node;
}



static uint32_t 
ted_show_one_node (ted_node_t *node, byte *buff, bool detail) {

    uint32_t rc = 0;
    ted_intf_t *intf, *other_intf;
    ted_node_t *nbr;
    char ip_addr[16];
    avltree_node_t *curr;
    ted_prefix_t *ted_prefix;

    rc += sprintf(buff + rc, "Node : %s[%u]  %s-%u   flags : 0x%x\n", 
                node->node_name,
                node->seq_no,
                tcp_ip_covert_ip_n_to_p(node->rtr_id, ip_addr), 
                node->seq_no,
                node->flags);
    
    if (node->is_fake) {
        rc += sprintf(buff + rc, "  is_fake : %s\n", node->is_fake ? "Yes" : "No");
    }

    if (!detail) return rc;
    
    TED_ITERATE_NODE_INTF_BEGIN(node, intf) {

        nbr = ted_get_nbr_node(intf);
        rc += sprintf (buff + rc , "    Local Intf : %u,  Ip-Address/Mask : %s/%d,  cost = %u\n",
                                intf->ifindex, tcp_ip_covert_ip_n_to_p(intf->ip_addr, ip_addr),
                                intf->mask, intf->cost);

        rc += sprintf (buff + rc, "    Nbr : %s[%u]", nbr ? nbr->node_name : "None",
                                nbr ? nbr->seq_no : 0);

        if (nbr) {

            other_intf = ted_link_get_other_interface(intf);
            rc += sprintf (buff + rc, "   Remote if index : %u, Remote-Ip-Address/Mask : %s/%d,  cost = %u\n",
                other_intf->ifindex,
                tcp_ip_covert_ip_n_to_p(other_intf->ip_addr, ip_addr),
                other_intf->mask, other_intf->cost);
        }

        rc += sprintf (buff + rc, "\n");
    } TED_ITERATE_NODE_INTF_END(node, intf);

    ITERATE_AVL_TREE_BEGIN(node->prefix_tree_root, curr){

        ted_prefix = avltree_container_of(curr, ted_prefix_t, avl_glue);
        rc += sprintf (buff + rc, "  Prefix : %s/%d  metric %u  flags 0x%x\n",
                        tcp_ip_covert_ip_n_to_p(ted_prefix->prefix, ip_addr),
                        ted_prefix->mask,
                        ted_prefix->metric,
                        ted_prefix->flags);

    } ITERATE_AVL_TREE_END;

    return rc;
}

uint32_t 
ted_show_ted_db (ted_db_t *ted_db, uint32_t rtr_id, byte *buff, bool detail) {

    uint32_t rc;
    avltree_node_t *avl_node;
    ted_node_t *node = NULL;

    if (rtr_id) {
        node = ted_lookup_node(ted_db, rtr_id);
        if (!node) return 0;
        return ted_show_one_node(node, buff, detail);
    }

    rc = 0;
    ITERATE_AVL_TREE_BEGIN(&ted_db->teddb, avl_node) {

        node = avltree_container_of(avl_node, ted_node_t , avl_glue);
        rc +=  ted_show_one_node (node, buff + rc, detail);
    } ITERATE_AVL_TREE_END(&ted_db->teddb, avl_node);
    return rc;
}

void
ted_refresh_node_seq_no (ted_db_t *ted_db, 
                                           uint32_t rtr_id, uint32_t new_seq_no) {

    ted_node_t *node = ted_lookup_node(ted_db, rtr_id);
    if (!node) return;
    node->seq_no = new_seq_no;
}

/* TED prefix tree function */
void
ted_prefix_tree_cleanup_tree (ted_node_t *node) {

    avltree_node_t *curr;
    ted_prefix_t *ted_prefix;

    if (!node->prefix_tree_root) return;

     ITERATE_AVL_TREE_BEGIN(node->prefix_tree_root, curr){

         ted_prefix = avltree_container_of(curr, ted_prefix_t, avl_glue);
         avltree_remove(curr, node->prefix_tree_root);
         XFREE(ted_prefix);

     }  ITERATE_AVL_TREE_END;

     XFREE(node->prefix_tree_root);
     node->prefix_tree_root = NULL;
}

void
ted_mem_init() {

    MM_REG_STRUCT(0, ted_intf_t);
    MM_REG_STRUCT(0, ted_node_t);
    MM_REG_STRUCT(0, ted_db_t);
    MM_REG_STRUCT(0, ted_link_t);
    MM_REG_STRUCT(0, ted_template_nbr_data_t);
    MM_REG_STRUCT(0, ted_template_node_data_t);
    MM_REG_STRUCT(0, ted_prefix_t);
}
