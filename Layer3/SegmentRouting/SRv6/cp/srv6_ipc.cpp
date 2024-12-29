#include "../../../../mtrie/mtrie.h"
#include "../../../../graph.h"
#include "../../../../cp_ipc.h"
#include "srv6_struct.h"
#include "srv6_rtr.h"
#include "srv6_api.h"

/* Publish all locator, prefix sids and Adj sids */
static uint32_t
srv6_ips_publish_all_local_sids(node_t *node, uint32_t minor_code) {

    glthread_t *curr;
    uint32_t count = 0;
    mtrie_node_t *mnode;
    srv6_pfxsid_t *pfxsid;
    srv6_adjsid_t *adjsid;
    ips_srv6_data_t *ips_srv6_data;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
    srv6_locator_t *loc = &node_info->loc;

    do {

        if (!(minor_code & IPC_REQ_SRV6_PUBLISH_PFX_SIDS)) break;

        /* Ist send the locator */
        
        ips_srv6_data = new ips_srv6_data_t;
        ips_srv6_data->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
        memcpy(ips_srv6_data->u.locator.prefix.addr, loc->sid.addr, 16);
        ips_srv6_data->u.locator.mt_id = 0; /* Default */
        ips_srv6_data->u.locator.algorithm = 0; /* Default*/
        ips_srv6_data->u.locator.flags = 0;
        ips_srv6_data->u.locator.prefix_len = loc->prefix_len;
        ips_srv6_data->u.locator.metric = 0;
        
        cp_ipc_send(node, IPC_SRV6_INFO,
                    IPC_SRV6_LOCATOR_ADD,
                    (void *)ips_srv6_data, sizeof(ips_srv6_data_t), true);
        count++;

        /* Now send the Prefix Sids */
        if (!node_info->configured_pfx_sids) break;

        ITERATE_GLTHREAD_BEGIN(&node_info->configured_pfx_sids->list_head, curr)
        {
            mnode = list_glue_to_mtrie_node(curr);
            pfxsid = (srv6_pfxsid_t *)mnode->data;
            assert(pfxsid);

            ips_srv6_data = new ips_srv6_data_t;
            ips_srv6_data->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
            /* Locator as a key*/
            memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
            ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;

            memcpy (ips_srv6_data->u.prefix_sid.prefix.addr, pfxsid->sid.addr, 16);
            ips_srv6_data->u.prefix_sid.endfn = pfxsid->endP;
            ips_srv6_data->u.prefix_sid.flags = pfxsid->flavor;

            cp_ipc_send(node, IPC_SRV6_INFO,
                        IPC_SRV6_PREFIX_SID_ADD,
                        (void *)ips_srv6_data, sizeof(*ips_srv6_data), true);

            count++;
        }
        ITERATE_GLTHREAD_END(&node_info->configured_pfx_sids->list_head, curr);

    } while (0);

    /* Now send the Adjacency Sids */
    if ((minor_code & IPC_REQ_SRV6_PUBLISH_ADJ_SIDS) 
            && node_info->configured_adj_sids)
    {

        ITERATE_GLTHREAD_BEGIN(&node_info->configured_adj_sids->list_head, curr)
        {
            mnode = list_glue_to_mtrie_node(curr);
            adjsid = (srv6_adjsid_t *)mnode->data;
            assert(adjsid);

            ips_srv6_data = new ips_srv6_data_t;
            ips_srv6_data->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
            /* Locator as a key*/
            memcpy (ips_srv6_data->u.prefix_sid.loc.addr, loc->sid.addr, 16);
            ips_srv6_data->u.prefix_sid.loc_prefix_len = loc->prefix_len;            

            memcpy(ips_srv6_data->u.adj_sid.prefix.addr, adjsid->sid.addr, 16);
            ips_srv6_data->u.adj_sid.flags = adjsid->flavor;
            ips_srv6_data->u.adj_sid.endfn = adjsid
            ->endP;

            cp_ipc_send(node, IPC_SRV6_INFO,
                        IPC_SRV6_ADJ_SID_ADD,
                        (void *)ips_srv6_data, sizeof(*ips_srv6_data), true);

            count++;
        }
        ITERATE_GLTHREAD_END(&node_info->configured_pfx_sids->list_head, curr);
    }

    return count;
}


static void
srv6_process_srv6_igp_tlv (node_t *node, uint32_t minor_code) {

}

void 
srv6_recv_ips_updates(node_t *node, 
                                      ips_major_code_t major_code, 
                                      uint32_t minor_code, 
                                      void *msg, uint32_t msg_size) {


    switch (major_code) {

        case IPC_IGP_REQUEST_SRV6_PUBLISH_SIDs:
            srv6_ips_publish_all_local_sids (node, minor_code);
        break;
        case IPC_ISIS_SRV6_LSDB_INFO:
            srv6_process_srv6_igp_tlv(node, minor_code);
        break;
        default: ;
    }
} 