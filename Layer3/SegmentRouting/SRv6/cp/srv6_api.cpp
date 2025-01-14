#include <assert.h>
#include "../../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../../mtrie/mtrie.h"
#include "../../../../graph.h"
#include "../../../../net.h"
#include "../../../../utils.h"
#include "../../../../cp_ipc_struct.h"
#include "srv6_rtr.h"
#include "srv6_api.h"
#include "../../../../common/cp2dp.h"
#include "../../../ipv6/v6nexthop.h"
#include "../../../../Tracer/tracer.h"

extern void 
srv6_recv_ips_updates(node_t *node, 
                                      ips_major_code_t major_code, 
                                      uint32_t minor_code, 
                                      void *msg, uint32_t msg_size) ;

bool 
srv6_is_enable (node_t *node) {

    return (!(SRV6_NODE_INFO(node) == NULL));
}

void 
srv6_init (node_t *node) {

    char log_file_name[NODE_NAME_SIZE + 32] = {0};

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    node_info->configured_pfx_sids = (mtrie_t *)XCALLOC (0, 1, mtrie_t);
    init_mtrie(node_info->configured_pfx_sids, 128, 0);

    node_info->configured_adj_sids = (mtrie_t *)XCALLOC (0, 1, mtrie_t);
    init_mtrie(node_info->configured_adj_sids, 128, 0);    

    /* Enable Tracer*/
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-srv6-log.txt", node->node_name);
    node_info->tr = tracer_init ("srv6", log_file_name, node->node_name, STDOUT_FILENO, 0);

    /* Enable ips Joins */

    /* Srv6 can entertain bulk sid publish request from IGPs*/
    cp_ips_join (node, IPC_IGP_REQUEST_SRV6_PUBLISH_SIDs,
        IPC_REQ_SRV6_PUBLISH_PFX_SIDS | IPC_REQ_SRV6_PUBLISH_ADJ_SIDS, 
        srv6_recv_ips_updates);
}

static void 
check_and_delete_srv6_node_info (node_t *node) {

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
    assert (!node_info->configured_pfx_sids);
    assert (!node_info->configured_adj_sids);
    assert (!node_info->tr);
    XFREE(node_info);
    SRV6_NODE_INFO(node) = NULL;
}

void 
srv6_de_init (node_t *node) {

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
    /* Delete Configure Sids and its routes from RIB */
    srv6_delete_all_pfx_sids (node) ;
    /* Delete Configured Adj Sids and its routes from RIB */
    srv6_delete_all_adj_sids (node) ;
    /* Delete Locator Config and its route from RIB*/
    srv6_locator_t *loc = &node_info->loc;

    if (!is_ipv6_addr_unspecified (&loc->sid.addr)) {

        srv6_local_sid_unconfig_pre_processing(node,
                                               &loc->sid,
                                               loc->prefix_len,
                                               END,
                                               0,
                                               0, 0, IPC_SRV6_LOCATOR_DEL);    
        memset (loc, 0, sizeof (*loc));
    }

    /* Delete Tracer */
    tracer_deinit (node_info->tr);
    node_info->tr = NULL;

    /* Delete ips joins */
    cp_ips_unjoin  (node, IPC_IGP_REQUEST_SRV6_PUBLISH_SIDs,  srv6_recv_ips_updates);

    /* check and delete srv6 node info*/
    check_and_delete_srv6_node_info (node);
    cprintf ("SRv6 shutdown Successfully\n");
}

void
srv6_local_sid_config_post_processing (
            node_t *node,
            ipv6_addr_t *pfxsid,
            uint8_t pfxsid_len,
            Srv6_endpcode_t pfxsid_endfn,
            uint8_t flags,
            uint8_t algo,
            ipv6_addr_t *gw,
            Interface *oif,
            uint32_t metric,
            uint32_t ipc_minor_code_event) {

        bool install_rt = false;
        ipv6_addr_t rt_addr;
        uint8_t rt_prefix_len;

        srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

         /* Send the IPS to Subscribers (IGPs)*/
        ips_srv6_data_t *ips_srv6_data = new ips_srv6_data_t;
        ips_srv6_data->rtr_id = tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(node));

        srv6_locator_t *loc = &node_info->loc;

        switch (ipc_minor_code_event) {

            case IPC_SRV6_LOCATOR_ADD:
            {
                memcpy(ips_srv6_data->u.locator.prefix.addr, loc->sid.addr, 16);
                ips_srv6_data->u.locator.prefix_len = loc->prefix_len;
                ips_srv6_data->u.locator.mt_id = 0; /* Default */
                ips_srv6_data->u.locator.metric = metric;
                ips_srv6_data->u.locator.algorithm = algo;
                ips_srv6_data->u.locator.flags = flags;
                /* Route to be installed */
                install_rt = true;
                memcpy(rt_addr.addr, loc->sid.addr, 16);
                rt_prefix_len = loc->prefix_len;
            }
            break;
            case IPC_SRV6_LOCATOR_UPDATE:
            {
                memcpy(ips_srv6_data->u.locator.prefix.addr, loc->sid.addr, 16);
                ips_srv6_data->u.locator.prefix_len = loc->prefix_len;
                ips_srv6_data->u.locator.mt_id = 0; /* Default */
                ips_srv6_data->u.locator.metric = metric;
                ips_srv6_data->u.locator.algorithm = algo; 
                ips_srv6_data->u.locator.flags = flags;
            }
            break;  
            case IPC_SRV6_PREFIX_SID_ADD:
            {
                memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
                ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;

                memcpy (ips_srv6_data->u.prefix_sid.prefix.addr, pfxsid->addr, 16);
                ips_srv6_data->u.prefix_sid.endfn = pfxsid_endfn;
                ips_srv6_data->u.prefix_sid.flags = flags;
                /* Route to be installed */
                install_rt = true;
                memcpy(rt_addr.addr, pfxsid->addr, 16);
                rt_prefix_len = pfxsid_len;
            }
            break;
            case IPC_SRV6_ADJ_SID_ADD:
            {
                /* Locator */
                memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
                ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;
                /* Adj sid*/
                memcpy(ips_srv6_data->u.adj_sid.prefix.addr, pfxsid->addr, 16);
                ips_srv6_data->u.adj_sid.flags = flags;
                ips_srv6_data->u.adj_sid.endfn = pfxsid_endfn;
                /* Route to be installed */
                install_rt = true;
                memcpy(rt_addr.addr, pfxsid->addr, 16);
                rt_prefix_len = pfxsid_len;
            }
            break;
            default :
                assert(0);
        }

        /* Send it to IGP */
      cp_ips_send (node, IPC_SRV6_INFO, 
                            ipc_minor_code_event,
                            (void *)ips_srv6_data, sizeof (ips_srv6_data_t), true);

    /* Install the locator route in RIB */
    if (install_rt) {
        ipv6_route_install (node, 
                                        &rt_addr,
                                        rt_prefix_len, 
                                        IPV6_LOCAL_RT,
                                        gw, oif,
                                        NULL, 0, 
                                        pfxsid_endfn,
                                        PROTO_SRv6);
    }
}

void srv6_local_sid_unconfig_pre_processing(
            node_t *node,
            ipv6_addr_t *pfxsid,
            uint8_t pfxsid_len,
            Srv6_endpcode_t pfxsid_endfn,
            uint8_t flags,
            ipv6_addr_t *gw,
            Interface *oif,
            uint32_t  ipc_minor_code_event)
{

    ipv6_addr_t rt_addr;
    uint8_t rt_prefix_len;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    /* Send the IPS to Subscribers (IGPs)*/
    ips_srv6_data_t *ips_srv6_data = new ips_srv6_data_t;
    ips_srv6_data->rtr_id = tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(node));

    srv6_locator_t *loc = &node_info->loc;

    switch (ipc_minor_code_event)
    {
        case  IPC_SRV6_LOCATOR_DEL:
        {
            memcpy(ips_srv6_data->u.locator.prefix.addr, loc->sid.addr, 16);
            ips_srv6_data->u.locator.prefix_len = loc->prefix_len;
            /* Rest of the fields do not matter, for deletion we only need locator key*/
            ips_srv6_data->u.locator.mt_id = 0;
            ips_srv6_data->u.locator.metric = 0;
            ips_srv6_data->u.locator.algorithm = 0;
            ips_srv6_data->u.locator.flags = flags;
            /* Route to be uninstalled*/
            memcpy(rt_addr.addr, loc->sid.addr, 16);
            rt_prefix_len = loc->prefix_len;
        }
        break;
        case IPC_SRV6_PREFIX_SID_DEL:
        {
            /* To delete the prefix sid, IGP should know whose locators prefix sid we are deleting, though we support 1 locator only*/
            memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
            ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;
            /* Now prefix sid*/
            memcpy (ips_srv6_data->u.prefix_sid.prefix.addr, pfxsid->addr, 16);
             /* Rest of the fields do not matter, for deletion we only need pfxsid key*/
             ips_srv6_data->u.prefix_sid.endfn = (Srv6_endpcode_t)0;
             ips_srv6_data->u.prefix_sid.flags = flags;
            /* Route to be uninstalled*/
            memcpy(rt_addr.addr, pfxsid->addr, 16);
            rt_prefix_len = pfxsid_len;
        }
        break;
        case IPC_SRV6_ADJ_SID_DEL:
        {
            memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
            ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;
            /* Now Adj sid*/
            memcpy(ips_srv6_data->u.adj_sid.prefix.addr, pfxsid->addr, 16);
            /* Rest of the fields do not matter, for deletion we only need adjsid key*/
            ips_srv6_data->u.adj_sid.flags = flags;
            ips_srv6_data->u.adj_sid.endfn =  (Srv6_endpcode_t)0;
            /* Route to be uninstalled*/
            memcpy(rt_addr.addr, pfxsid->addr, 16);
            rt_prefix_len = pfxsid_len; 
        }
        break;
        default:
            assert(0);
    }

        /* Send it to IGP */
      cp_ips_send (node, IPC_SRV6_INFO, 
                            ipc_minor_code_event,
                            (void *)ips_srv6_data, sizeof (ips_srv6_data_t), true);

        ipv6_route_uninstall(node, 
                            &rt_addr,
                            rt_prefix_len, 
                            gw, oif,
                            PROTO_SRv6);
}

uint32_t 
srv6_delete_all_pfx_sids (node_t *node)  {

    glthread_t *curr ;
    uint32_t count = 0;
    mtrie_node_t *mnode;
    srv6_pfxsid_t *pfxsid;
    ips_srv6_data_t *ips_srv6_data;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    if (!node_info || !node_info->configured_pfx_sids) return 0;

    curr = glthread_get_next(&node_info->configured_pfx_sids->list_head);

    while (curr)
    {
        mnode = list_glue_to_mtrie_node(curr);
        pfxsid = (srv6_pfxsid_t *)mnode->data;
        assert(pfxsid);

        srv6_local_sid_unconfig_pre_processing(node,
                                               &pfxsid->sid,
                                               pfxsid->prefix_len,
                                               pfxsid->endP,
                                               pfxsid->flags,
                                               0, 0, IPC_ISIS_SRV6_PREFIX_SID_DEL);

        XFREE(pfxsid);
        curr = mtrie_node_delete_while_traversal(node_info->configured_pfx_sids, mnode);
        count++;
    }

    assert (mtrie_is_leaf_node (node_info->configured_pfx_sids->root));
    mtrie_destroy (node_info->configured_pfx_sids);
    XFREE(node_info->configured_pfx_sids);
    node_info->configured_pfx_sids = NULL;
    return count;
}

uint32_t 
srv6_delete_all_adj_sids (node_t *node) {
    
    glthread_t *curr ;
    uint32_t count = 0;
    mtrie_node_t *mnode;
    srv6_adjsid_t *adjsid;
    ips_srv6_data_t *ips_srv6_data;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    if (!node_info || !node_info->configured_adj_sids) return 0;

    curr = glthread_get_next(&node_info->configured_adj_sids->list_head);

    while (curr)
    {
        mnode = list_glue_to_mtrie_node(curr);
        adjsid = (srv6_adjsid_t *)mnode->data;
        assert(adjsid);

        srv6_local_sid_unconfig_pre_processing(node,
                                               &adjsid->sid,
                                               adjsid->prefix_len,
                                               adjsid->endP,
                                               adjsid->flags,
                                               0, 0, IPC_ISIS_SRV6_ADJ_SID_DEL);
        
        cp_ips_send (node, IPC_SRV6_INFO, 
                            IPC_SRV6_PREFIX_SID_DEL, 
                            (void *) ips_srv6_data, sizeof (*ips_srv6_data), true);

        XFREE(adjsid);
        curr = mtrie_node_delete_while_traversal(node_info->configured_adj_sids, mnode);
        count++;
    }

    assert (mtrie_is_leaf_node (node_info->configured_adj_sids->root));
    mtrie_destroy (node_info->configured_adj_sids);
    XFREE(node_info->configured_adj_sids);
    node_info->configured_adj_sids = NULL;
    return count;
}
