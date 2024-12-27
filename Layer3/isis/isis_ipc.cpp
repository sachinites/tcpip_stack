#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_advt.h"
#include "isis_tlv_struct.h"
#include "isis_srv6.h"

extern  void 
 isis_interface_ipc_updates(node_t *node, uint32_t minor_code, ipc_interface_t *msg);
 
extern  void 
 isis_gre_tunnel_ipc_updates (node_t *node, uint32_t minor_code, ipc_gre_t *msg);

extern  void 
isis_access_lst_ipc_updates (node_t *node, uint32_t minor_code, ipc_access_lst_t *msg) ;

static void
isis_srv6_recv_ips_updates (node_t *node, uint32_t minor_code, ips_srv6_data_t *msg) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];
    isis_advt_info_t advt_info;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    tracer (ISIS_TR(node), TR_ISIS_IPC,
        "Recvd SRv6 ips update, code = %u\n", minor_code);

    switch (minor_code ) {

        case  IPC_SRV6_LOCATOR_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator ADD : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, ipv6_addr_str),
                     msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

            assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv236) ;

            node_info->tlv_global_advt.v6loc_adv_data_tlv236 = 
                (isis_adv_data_t *) XCALLOC(0, 1, isis_adv_data_t);

            isis_adv_data_t *advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv236;

            advt_data->tlv_no = ISIS_TLV_IPV6_REACH;
            memcpy (advt_data->u.v6pfx.prefix, msg->u.locator.prefix.addr, 16);
            advt_data->u.v6pfx.metric = msg->u.locator.metric;
            advt_data->u.v6pfx.mask = msg->u.locator.prefix_len;
            advt_data->u.v6pfx.flags = 0;
            advt_data->src.holder = &node_info->tlv_global_advt.v6loc_adv_data_tlv236;
            init_glthread (&advt_data->glue);
            advt_data->tlv_size = isis_get_adv_data_size (advt_data);
            advt_data->fragment = NULL;
            isis_advertise_tlv (node, 0, advt_data, &advt_info);
        }
        break;

        case  IPC_SRV6_LOCATOR_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator DEL : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, ipv6_addr_str), 
                    msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

            isis_adv_data_t *advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv236;
            assert (advt_data);
            isis_advt_data_clear_backlinkage( node_info, advt_data);
            if (!advt_data->fragment) {
                isis_wait_list_advt_data_remove(node, advt_data);
                isis_free_advt_data(advt_data);
                break;
            }
            isis_withdraw_tlv_advertisement (node, advt_data);
            isis_free_advt_data(advt_data);
        }
        break;

        case IPC_SRV6_PREFIX_SID_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID ADD : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                    msg->u.prefix_sid.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        }
        break;

        case IPC_SRV6_PREFIX_SID_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID DEL : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                    msg->u.prefix_sid.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        }
        break;

        case IPC_SRV6_ADJ_SID_ADD:
        {

        }
        break;
        
        case IPC_SRV6_ADJ_SID_DEL:
        {

        }
        break;
    }
}

void isis_recv_ipc_updates (node_t *node, 
                                             ips_major_code_t major_code,
                                             uint32_t minor_code,
                                             void *msg,
                                             uint32_t msg_size) {

    switch (major_code) {

        case IPC_SRV6_INFO:
            {   
                isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);
                if (!srv6_config) break;
                isis_srv6_recv_ips_updates (node, minor_code, (ips_srv6_data_t *)msg);
            }
        break;
        case IPC_INTERFACE:
            isis_interface_ipc_updates(node, minor_code, (ipc_interface_t *)msg);
        break;
        case IPC_GRE_TUNNEL:
            isis_gre_tunnel_ipc_updates (node, minor_code, (ipc_gre_t *)msg);
        break;
        case IPC_ACCESS_LIST:
            isis_access_lst_ipc_updates (node, minor_code, (ipc_access_lst_t *)msg);
        default: 
        ;
    }
}