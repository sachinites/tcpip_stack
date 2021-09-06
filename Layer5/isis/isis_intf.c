#include "../../tcp_public.h"
#include "isis_intf.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}

void
isis_enable_protocol_on_interface(interface_t *intf ) {

}

void
isis_disable_protocol_on_interface(interface_t *intf ) {

}