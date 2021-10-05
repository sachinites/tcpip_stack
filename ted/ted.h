#ifndef __TED__
#define __TED__

#define TEDN_MAX_INTF_PER_NODE   (MAX_INTF_PER_NODE + 1)


typedef struct ted_intf_{

    uint32_t ifindex;
    uint32_t ip_addr;
    uint8_t mask;
    uint32_t cost;
    struct ted_node_ *att_node;
    struct ted_link_ *link;
    uint16_t  slot_no;
} ted_intf_t;

typedef struct ted_link_ {

    ted_intf_t intf1;
    ted_intf_t intf2;
    uint32_t dirn_flag;
} ted_link_t;

typedef struct ted_node_ {

    uint32_t rtr_id;
    char node_name[NODE_NAME_SIZE];
    uint32_t flags;
    bool is_installed_in_teddb;
    bool is_fake;
    uint32_t seq_no;
    ted_intf_t *intf[TEDN_MAX_INTF_PER_NODE];
    avltree_node_t avl_glue;
} ted_node_t;

typedef struct ted_db_ {

    avltree_t teddb;
} ted_db_t;

void
ted_init_teddb(ted_db_t *ted_db, avltree_cmp_fn_t cmp_fn) ;

static inline ted_intf_t *
ted_link_get_other_interface (ted_intf_t *intf) {

    ted_link_t *link = intf->link;
    if (&link->intf1 == intf) return &link->intf2;
    return &link->intf1;
}

static ted_node_t *
ted_get_nbr_node(ted_intf_t *intf) {

    ted_intf_t *other_intf = ted_link_get_other_interface(intf);
    return other_intf->att_node;
}

bool
ted_insert_link (ted_node_t *node1 ,
                          ted_node_t *node2, 
                          ted_link_t *ted_link);

ted_link_t *
ted_create_link ( ted_link_t *ted_link , 
                            uint32_t from_if_index,
                            uint32_t to_if_index,
                            uint32_t from_ip_addr,
                            uint8_t from_mask,
                            uint32_t to_ip_addr,
                            uint8_t to_mask);

#define TED_ITERATE_NODE_INTF_BEGIN(node_ptr, intf_ptr)   \
    {                                                                                                         \
        int _i;                                                                                              \
        for (_i = 0 ; _i < TEDN_MAX_INTF_PER_NODE; _i++) {      \
            if (!node_ptr->intf[_i] ) continue;                                              \
            intf_ptr = node_ptr->intf[_i];

#define TED_ITERATE_NODE_INTF_END(node_ptr, intf_ptr)   }}

int8_t 
ted_node_get_empty_slot(ted_node_t *node);

int8_t
ted_plug_in_interface(ted_node_t *node, ted_intf_t *intf) ;

int8_t
ted_plug_out_interface(ted_intf_t *intf);

void
ted_unplug_all_interfaces(ted_node_t *node) ;

bool
ted_is_interface_plugged_in(ted_intf_t *intf) ;

bool
ted_link_is_bidirectional (ted_link_t *ted_link);

bool
ted_is_link_dettached(ted_link_t *ted_link);

ted_node_t *
ted_lookup_node(ted_db_t *ted_db, uint32_t rtr_id);

ted_intf_t *
ted_node_lookup_intf (ted_node_t *node, uint32_t ifindex);

bool
ted_insert_node_in_teddb(ted_db_t *ted_db, ted_node_t *node);

ted_node_t *
ted_create_node(uint32_t rtr_id, bool is_fake);

ted_link_t *
ted_resurrect_link (ted_db_t *ted_db,
                                uint32_t from_node_rtr_id,
                                uint32_t from_if_index,
                                uint32_t to_node_rtr_id,
                                uint32_t to_ifindex);

/* Public APIs */

typedef struct ted_template_nbr_data_ {

    uint32_t local_if_index;
    uint32_t remote_if_index;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint32_t nbr_rtr_id;
    uint32_t metric;
} ted_template_nbr_data_t;

typedef struct  ted_template_node_data_ {

    uint32_t rtr_id;
    char node_name[NODE_NAME_SIZE];
    uint32_t seq_no;
    uint8_t n_nbrs;
    uint32_t flags; 
    ted_template_nbr_data_t nbr_data[0];
} ted_template_node_data_t;

void
ted_delete_node (ted_db_t *ted_db, uint32_t rtr_id);

void
ted_create_or_update_node (ted_db_t *ted_db,
            ted_template_node_data_t *template_node_data);

uint32_t 
ted_show_ted_db (ted_db_t *ted_db, uint32_t rtr_id, byte *buff, bool detail) ;

void
ted_refresh_node_seq_no (ted_db_t *ted_db, 
                                           uint32_t rtr_id, uint32_t new_seq_no);

#endif /* __TED__ */
