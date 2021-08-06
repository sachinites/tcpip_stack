#ifndef __TED__
#define __TED__

#define TEDN_MAX_INTF_PER_NODE    8

#include <stdint.h>
#include <stdbool.h>
#include "../Bitop/bitsop.h"
#include "../gluethread/glthread.h"

typedef struct ted_intf_{

    uint32_t ifindex;
    uint32_t ip_addr;
    uint32_t cost;
    struct ted_node_ *att_node;
    struct ted_link_ *link;
    struct ted_intf_ **slot;
} ted_intf_t;

#define TED_LINK_DN_F_IF1_TO_IF2    1
#define TED_LINK_DN_F_IF2_TO_IF1    2

typedef struct ted_link_ {

    ted_intf_t intf1;
    ted_intf_t intf2;
    ted_link_dirn_flags_t dirn_flag;
} ted_link_t;

typedef struct ted_node_ {

    uint32_t rtr_id;
    uint32_t flags;
    ted_intf_t *intf[TEDN_MAX_INTF_PER_NODE];
    glthread_t glue;
} ted_node_t;
GLTHREAD_TO_STRUCT(glue_to_ted_node, ted_node_t , glue);

typedef struct ted_db_ {

    glthread_t node_list_head;
} ted_db_t;

bool
ted_insert_link (ted_node_t *node1 ,
                          ted_node_t *node2, 
                          ted_link_t *ted_link);

ted_link_t *
ted_create_link( ted_link_t *ted_link , 
                            uint32_t from_if_index,
                            uint32_t to_if_index,
                            uint32_t from_ip_addr, 
                            uint32_t to_ip_addr,
                            ted_link_dirn_t dirn);

#define TED_ITERATE_NODE_INTF_BEGIN(node_ptr, intf_ptr)   \
    {                                                                                                         \
        int _i;                                                                                              \
        for (_ i = 0 ; _i < TEDN_MAX_INTF_PER_NODE; _i++) {      \
            if (!node_ptr->intf[_i] ) continue;                                              \
            intf_ptr = node_ptr->intf[_i];

#define TED_ITERATE_NODE_INTF_END(node_ptr, intf_ptr)   }}

int8_t 
ted_node_get_empty_slot(ted_node_t *node);

int8_t
ted_plug_in_interface(node_t *node, ted_intf_t *intf) ;

void
ted_plug_out_interface(ted_intf_t *intf);

bool
ted_is_interface_plugged_in(ted_intf_t *intf) ;

bool
ted_is_link_dettached(ted_link_t *ted_link);

void
ted_mark_link_stale(ted_intf_t *intf1, ted_intf_t *intf2);

#endif /* __LSDB */