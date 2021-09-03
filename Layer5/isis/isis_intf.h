#ifndef __ISIS_INTF__
#define __ISIS_INTF__

typedef struct isis_intf_info_ {

// 

} isis_intf_info_t;

bool
isis_is_protocol_enable_on_node(node_t *node);

#define ISIS_INTF_INFO(intf_ptr)    \
    ((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))

#endif  