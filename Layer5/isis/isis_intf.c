#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_rtr.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}

void
isis_enable_protocol_on_interface(interface_t *intf ) {

    isis_intf_info_t *intf_info = NULL;

    /* 1. Enable protocol on interface only when protocol is already enabled
            at node level, else throw an error
        2. If protocol already enabled on interface, then do nothing
        3. Enable the protocol on interface finally
    */
   if (ISIS_NODE_INFO(intf->att_node) == NULL) {
       printf("Error : Enable Protocol on node first\n");
       return;
   }

    intf_info = ISIS_INTF_INFO(intf);

    if (intf_info) {
        return;
    }

    intf_info = calloc ( 1, sizeof (isis_intf_info_t));
    intf->intf_nw_props.isis_intf_info = intf_info;
}

void
isis_disable_protocol_on_interface(interface_t *intf ) {

      isis_intf_info_t *intf_info = NULL;

       intf_info = ISIS_INTF_INFO(intf);

       if (!intf_info) return;

       free(intf_info);

       intf->intf_nw_props.isis_intf_info = NULL;
}