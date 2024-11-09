#include <stdbool.h>
#include <assert.h>
#include "dp_rtm.h"
#include "../../Layer3/layer3.h"
#include "../../graph.h"
#include "../../common/cp2dp.h"
#include "../../net.h"
#include "../../utils.h"
#include "../../Interface/Interface.h"

void 
np_rt_table_process_msg(node_t *node, dp_msg_t *dp_msg) {

    bool rc;
    unsigned char gw_str[16];
    unsigned char dest_str[16];
    rt_update_msg_t *rt_update_msg;

    rt_table_t *rt_table = NODE_RT_TABLE(node);

    assert (dp_msg->component_type == RT_TABLE_IPV4);

    switch (dp_msg->opr_type) {

        case DP_CREATE:

            rt_update_msg = (rt_update_msg_t *)dp_msg->data;

            if (rt_update_msg->oif) {

                if (rt_update_msg->oif->InterfaceUnLockDynamic()) {
                    cp2dp_msg_free (node, dp_msg);
                    return;
                }
            }

            rt_table_add_route (rt_table, 
                    (const char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->prefix, dest_str),
                    rt_update_msg->mask,
                    rt_update_msg->gateway ? 
                    (const char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->gateway, gw_str) : NULL,
                    rt_update_msg->oif,
                    rt_update_msg->metric,
                    rt_update_msg->proto_id);
            break;

        case DP_DEL:

             rt_update_msg = (rt_update_msg_t *)dp_msg->data;
             rt_table_delete_route (rt_table, 
                        (unsigned char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->prefix, dest_str),
                        rt_update_msg->mask,
                        rt_update_msg->proto_id);
            break;

        case DP_UPDATE:
            //rt_table_update_route(rt_table, (rt_table_entry_t *)dp_msg->data);
            break;
            
        case DP_READ:
            break;
        default:
            break;
    }
    cp2dp_msg_free (node, dp_msg);
}