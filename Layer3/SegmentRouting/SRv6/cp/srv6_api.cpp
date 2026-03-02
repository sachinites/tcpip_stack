#include <assert.h>
#include <ncurses.h>
#include "../../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../../mtrie/mtrie.h"
#include "../../../../router_init.h"
#include "../../../../net.h"
#include "../../../../utils.h"
#include "../../../../cp_ipc_struct.h"
#include "srv6_rtr.h"
#include "srv6_api.h"
#include "../../../../dpal/cp2dp.h"
#include "../../../../Tracer/tracer.h"
#include "srv6_sid_pool.h"
#include "../../../../lmm_enums.h"
#include "../../../../Interface/InterfaceUApi.h"
#include "srv6_rtm.h"

bool 
srv6_is_enable (node_t *node) {

    return (!(SRV6_NODE_INFO(node) == NULL));
}

void 
srv6_init (node_t *node) {

    char log_file_name[NODE_NAME_SIZE + 32] = {0};

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    node_info->configured_pfx_sids = (mtrie_t *)XCALLOC2 (0, 1, mtrie_t);
    init_mtrie(node_info->configured_pfx_sids, 128, 0);

    node_info->configured_adj_sids = (mtrie_t *)XCALLOC2 (0, 1, mtrie_t);
    init_mtrie(node_info->configured_adj_sids, 128, 0);    

    /* Enable Tracer*/
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-srv6-log.txt", node->node_name);
    node_info->tr = tracer_init ("srv6", log_file_name, node->node_name, STDOUT_FILENO, 0);
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

    char err_msg[256];
    pool_error_codes_t prc = SRv6_POOL_OK;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    srv6_locator_t *loc = &node_info->loc;

    if (srv6_pool_is_locator_being_used_by_any_client (
                    NODE_SRv6_SID_POOL(node), 
                    loc->name)) {

        cprintf ("Error : Locator is in use by other clients, Command Rejected.\n");
        return ;
    }

    /* Delete Configure Sids and its routes from RIB */
    srv6_delete_all_pfx_sids (node) ;
    /* Delete Configured Adj Sids and its routes from RIB */
    srv6_delete_all_adj_sids (node) ;

    /* Delete Locator Config and its route from RIB*/   
    srv6_rtm_route_install(node,
                           &loc->sid,
                           loc->prefix_len,
                           FIB_NH_FWD_F_LOCAL,
                           0, 0,
                           NULL, 0,
                           SRV6_END_FN_NONE,
                           RTM_PROTO_STATIC, false);

    prc = srv6_pool_delete_locator ( (NODE_SRv6_SID_POOL(node)), 
                                            loc->name,
                                            err_msg);

    assert (prc == SRv6_POOL_OK);

    memset (loc, 0, sizeof (*loc));
    
    /* Delete Tracer */
    tracer_deinit (node_info->tr);
    node_info->tr = NULL;

    /* check and delete srv6 node info*/
    check_and_delete_srv6_node_info (node);
    cprintf ("\nSRv6 shutdown Successfully");
}

uint32_t 
srv6_delete_all_pfx_sids (node_t *node)  {

    glthread_t *curr ;
    uint32_t count = 0;
    char err_msg[256];
    mtrie_node_t *mnode;
    srv6_pfxsid_t *pfxsid;
    ips_srv6_data_t *ips_srv6_data;
    pool_error_codes_t prc = SRv6_POOL_OK;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    if (!node_info || !node_info->configured_pfx_sids) return 0;

    curr = glthread_get_next(&node_info->configured_pfx_sids->list_head);

    while (curr)
    {
        mnode = list_glue_to_mtrie_node(curr);
        pfxsid = (srv6_pfxsid_t *)mnode->data;
        assert(pfxsid);

        srv6_rtm_route_install(node, 
                            &pfxsid->sid,
                            pfxsid->prefix_len,
                            FIB_NH_FWD_F_LOCAL,
                            0, 0, NULL, 0,
                            pfxsid->endP,
                            RTM_PROTO_STATIC, false);    

        prc = srv6_release_sid (
                                    (NODE_SRv6_SID_POOL(node)), 
                                    &pfxsid->sid,
                                    srv6_sid_client_srv6,
                                    err_msg);

        assert (prc == SRv6_POOL_OK);    

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
    char err_msg[256];
    mtrie_node_t *mnode;
    srv6_adjsid_t *adjsid;
    ips_srv6_data_t *ips_srv6_data;
    pool_error_codes_t prc = SRv6_POOL_OK;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    if (!node_info || !node_info->configured_adj_sids) return 0;

    curr = glthread_get_next(&node_info->configured_adj_sids->list_head);

    while (curr)
    {
        mnode = list_glue_to_mtrie_node(curr);
        adjsid = (srv6_adjsid_t *)mnode->data;
        assert(adjsid);

        srv6_rtm_route_install(node, 
                            &adjsid->sid,
                            adjsid->prefix_len,
                            adjsid->flags,
                            &adjsid->gw,
                            node_get_intf_by_ifindex (node, adjsid->ifindex),
                            NULL, 0,
                            adjsid->endP,
                            RTM_PROTO_STATIC, false); 
        
        prc = srv6_release_sid (
                                    (NODE_SRv6_SID_POOL(node)), 
                                    &adjsid->sid,
                                    srv6_sid_client_srv6,
                                    err_msg);

        assert (prc == SRv6_POOL_OK);    

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
