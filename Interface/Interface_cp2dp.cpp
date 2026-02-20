#include "../common/cp2dp.h"
#include "Interface_cp2dp.h"

#include "../datapath/Interface/dp_intf_update.h"
#include "InterfaceUApi.h"
#include "../common/cmn_struct.h"

void 
cp2dp_interface_create (node_t *node, Interface *intf) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;

    assert (intf->ifindex);

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->iftype = (uint32_t)intf->iftype;
    memcpy (intf_msg->mac_addr, intf->GetMacAddr()->mac, 6);
    strncpy (intf_msg->intf_name, intf->if_name.c_str(), IF_NAME_SIZE);
    intf_msg->update_code = 0;
    
    /* Use synchronous submission to ensure interface is created before caller proceeds */
    cp2dp_submit(node, dp_msg, false);
}

void 
cp2dp_interface_delete (node_t *node, Interface *intf) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;

    assert (intf->iftype != INTF_TYPE_PHY);

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->iftype = (uint32_t)intf->iftype;
    intf_msg->update_code = 0;
    
    cp2dp_submit(node, dp_msg, true);
}
