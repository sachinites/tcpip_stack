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

            ipv6_route_uninstall(node, 
                            &loc->sid,
                            loc->prefix_len,
                            0, 0,
                            PROTO_SRv6);
 
        memset (loc, 0, sizeof (*loc));
    }

    /* Delete Tracer */
    tracer_deinit (node_info->tr);
    node_info->tr = NULL;

    /* check and delete srv6 node info*/
    check_and_delete_srv6_node_info (node);
    cprintf ("SRv6 shutdown Successfully\n");
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

        ipv6_route_uninstall(node, 
                            &pfxsid->sid,
                            pfxsid->prefix_len,
                            0, 0,
                            PROTO_SRv6);        

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

        ipv6_route_uninstall(node, 
                            &adjsid->sid,
                            adjsid->prefix_len,
                            0, 0,
                            PROTO_SRv6);

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


void 
External_srv6_import_locator_config (
        node_t *node,
        const char *loc_name, 
        ipv6_addr_t *prefix, 
        uint8_t *prefix_len,
        uint32_t *metric,
        uint16_t *mt_id,
        uint8_t *algorithm,
        uint8_t *flags) {

    memset (prefix, 0, sizeof (*prefix));
    *prefix_len = 0;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    if (!node_info) {
        return;
    }

    srv6_locator_t *loc = &node_info->loc;
    
    if (loc->name[0] == '\0') {
        return;
    }

    if (strncmp (loc->name, loc_name, sizeof (loc->name))) {
        return;
    }

    memcpy (prefix, &loc->sid, sizeof(*prefix));
    *prefix_len = loc->prefix_len;
    *metric = 0;
    *mt_id = 0;
    *algorithm = loc->algo;
    *flags = 0;
}