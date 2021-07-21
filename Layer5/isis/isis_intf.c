#include "../../tcp_public.h"
#include "isis_intf.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}
