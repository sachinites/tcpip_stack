#include "ted.h"

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

#if 0
void
ted_mark_all_links_stale(ted_node_t *node) {

    ted_intf_t *intf;

    TED_ITERATE_NODE_INTF_BEGIN(node, intf) {

        ted_mark_link_stale(intf->link, intf);

    } TED_ITERATE_NODE_INTF_END(node, intf);
}

bool
ted_is_link_stale(ted_link_t *ted_link, ted_intf_t *intf) {

    assert(intf->link == ted_link);

    if (&ted_link->intf1 == intf) {

        return IS_BIT_SET(ted_link->dirn_flags, TED_DN_INTF1_TO_INTF2);
    }

    if (&ted_link->intf2 == intf) {

        return IS_BIT_SET(ted_link->dirn_flags, TED_DN_INTF2_TO_INTF1);
    }
}

void
ted_mark_link_stale(ted_link_t *ted_link, ted_intf_t *intf) {

    assert(intf->link == ted_link);

    if (&ted_link->intf1 == intf) {

        UNSET_BIT8(ted_link->dirn_flags, TED_DN_INTF1_TO_INTF2);
    }

    if (&ted_link->intf2 == intf) {

        UNSET_BIT8(ted_link->dirn_flags, TED_DN_INTF2_TO_INTF1);
    }
}

void
ted_mark_link_unstale(ted_link_t *ted_link, ted_intf_t *intf) {

    assert(intf->link == ted_link);

    if (&ted_link->intf1 == intf) {

        SET_BIT(ted_link->dirn_flags, TED_DN_INTF1_TO_INTF2);
    }

    if (&ted_link->intf2 == intf) {

        SET_BIT8(ted_link->dirn_flags, TED_DN_INTF2_TO_INTF1);
    }
}

#endif

int8_t
ted_plug_in_interface(node_t *node, ted_intf_t *intf) {

    int8_t available_slot = ted_node_get_empty_slot(node);

    if (available_slot < 0) {
        return -1;
    }

    if (ted_is_interface_plugged_in(intf)) {
        assert(0);
    }

    intf->att_node = node;
    node->intf[available_slot] = intf;
    intf->slot = &node->intf[available_slot];
    return available_slot;
}

void
ted_plug_out_interface(ted_intf_t *intf) {
    
    if (!ted_is_interface_plugged_in(intf)) {
        return;
    }

    ted_mark_link_stale(intf->link, intf);
    intf->att_node = NULL;
    *(intf->slot) = NULL;
    intf->slot = NULL;
}

bool
ted_is_interface_plugged_in(ted_intf_t *intf) {

    return (intf->att_node && intf->slot && *(intf->slot));
}

bool
ted_is_link_dettached(ted_link_t *ted_link) {

    if ( ted_is_interface_plugged_in(&ted_link->intf1) ||
            ted_is_interface_plugged_in(&ted_link->intf2) ) {

                return false;
    }
    return true;
}

bool
ted_unplug_all_interfaces(node_t *node) {

    ted_intf_t *intf;

    TED_ITERATE_NODE_INTF_BEGIN(node, intf) {

        ted_plug_out_interface(intf);

        if (ted_is_link_dettached(intf->link)) {
            free(intf->link);
        }

    } TED_ITERATE_NODE_INTF_END(node, intf);
}

ted_link_t *
ted_create_link( ted_link_t *ted_link , 
                            uint32_t from_if_index,
                            uint32_t to_if_index,
                            uint32_t from_ip_addr, 
                            uint32_t to_ip_addr,
                            ted_link_dirn_t dirn) {


    if (!ted_link) {
        ted_link = calloc(1, sizeof(ted_link_t));
    }
    else {
        memset(ted_link, 0, sizeof(ted_link_t));
    }

    ted_link->intf1.ifindex = from_if_index;
    ted_link->intf1.ip_addr = from_ip_addr;
    ted_link->intf2.ifindex = to_if_index;
    ted_link->intf2.ip_addr = to_ip_addr;
    return ted_link;
}

void
ted_mark_link_stale(ted_intf_t *intf1, ted_intf_t *intf2) {

    ted_link_t *ted_link = intf1->link;

    assert(ted_link == intf2->link);

    if (ted_link->intf1 == intf1 &&
            ted_link->intf2 == intf2) {

        UNSET_BIT8(ted_link->dirn_flags, TED_LINK_DN_F_IF1_TO_IF2);
    }
    else {
        UNSET_BIT8(ted_link->dirn_flags, TED_LINK_DN_F_IF2_TO_IF1);
    }
    
}




























