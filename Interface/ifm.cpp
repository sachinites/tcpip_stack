#include <stdlib.h>

#include "ifm.h"
#include "Interface.h"
#include "../router_init.h"
#include "../FireWall/acl/acldb.h"
#include "../libs/prefix-list/prefixlst.h"
#include "../dpal/cp2dp.h"

extern int cprintf(const char *format, ...);

static void
ifm_internal_process_acl_change_notification (
                        event_dispatcher_t *ev_dis, 
                        void *data, 
                        uint32_t len) {

    access_list_t *access_list = (access_list_t *)data;
    node_t        *node        = (node_t *)ev_dis->app_data;

    /* Re-program the data-plane for every interface that has this
       access-list bound.  The lambda factors out the four-direction
       check so each interface only needs a single call site. */
    auto notify_intf = [&](Interface *intf) {
        if (!intf) return;
        if (intf->l2_ingress_acc_lst == access_list)
            cp2dp_interface_add_acl(node, (uintptr_t)access_list->mtrie, 2, intf->ifindex, true);
        if (intf->l2_egress_acc_lst  == access_list)
            cp2dp_interface_add_acl(node, (uintptr_t)access_list->mtrie, 2, intf->ifindex, false);
        if (intf->l3_ingress_acc_lst == access_list)
            cp2dp_interface_add_acl(node, (uintptr_t)access_list->mtrie, 3, intf->ifindex, true);
        if (intf->l3_egress_acc_lst  == access_list)
            cp2dp_interface_add_acl(node, (uintptr_t)access_list->mtrie, 3, intf->ifindex, false);
    };

    /* Regular interfaces (physical / GRE / loopback / vport …) */
    if (node->intf_by_ifindex) {
        for (auto &[ifindex, intf_ptr] : *node->intf_by_ifindex)
            notify_intf(intf_ptr.get());
    }

    /* VLAN (SVI) interfaces */
    if (node->vlan_intf_db) {
        for (auto &[vlan_id, vlan_intf_ptr] : *node->vlan_intf_db)
            notify_intf(vlan_intf_ptr.get());
    }

    /* Special interfaces — accessed directly through node_nw_prop */
    notify_intf(NODE_NVE_INTF(node).get());

    //access_list_dereference(node, access_list);
}

static void 
ifm_acl_change_cbk(node_t *node,
                    vrf_t *vrf,
                    uint32_t instance_no,
                    access_list_t *access_list)
{
    task_create_new_job (EV(node), 
                        (void *)access_list, 
                        ifm_internal_process_acl_change_notification, 
                        TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE);

    //access_list_reference(node, access_list);
}

static void 
ifm_prefix_lst_change_cbk(node_t *node,
                    vrf_t *vrf,
                    uint32_t instance_no,
                    prefix_list_t *prefix_lst)
{
    /* For now, we are not doing anything with ACL change notifications in IFM.
       This callback is registered to ensure that IFM gets notified of ACL changes
       so it can trigger interface updates if needed. */
}


void 
ifm_init(node_t *node) {

    node->ifm = (ifm_t *)calloc(1, sizeof(ifm_t));
    node->ifm->node = node;

    access_list_register_client(node, ifm_acl_change_cbk, NULL, 0);
    prefix_list_register_client(node, ifm_prefix_lst_change_cbk, NULL, 0);
}