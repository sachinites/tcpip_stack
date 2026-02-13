#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_rtr.h"
#include "isis_ips_struct.h"

extern  void 
 isis_interface_ipc_updates(node_t *node, uint32_t minor_code, ipc_interface_t *msg);
 
extern  void 
 isis_gre_tunnel_ipc_updates (node_t *node, uint32_t minor_code, ipc_gre_t *msg);

extern  void 
isis_access_lst_ipc_updates (node_t *node, uint32_t minor_code, ipc_access_lst_t *msg) ;

void isis_recv_ipc_updates (node_t *node, 
                                             ips_major_code_t major_code,
                                             uint32_t minor_code,
                                             void *msg,
                                             uint32_t msg_size) {

    switch (major_code) {

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

static void 
isis_lsp_ips_free_fn(node_t *node, void *lsp_pkt) {

    isis_deref_isis_pkt(node, (isis_lsp_pkt_t *)lsp_pkt);
}

void 
isis_ips_send_lsp_update (node_t *node, isis_lsp_pkt_t *lsp_pkt, bool add) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    if (lsp_pkt) {

        /* Dont create storm of LSP delete IPCs if protocol is shutting down. 
            During shut down ISIS may invoke this API for every LSP deleting 
            from lspdb. During shutdown, ISIS will generate only one IPS signal
            and that is  IPC_LFA_ISIS_LSP_DEL_ALL */
        if (isis_is_protocol_shutdown_in_progress (node)) return;

        isis_ref_isis_pkt(lsp_pkt);
        cp_ips_send (node, IPC_LFA_ISIS, 
            add ? IPC_LFA_ISIS_LSP_ADD : IPC_LFA_ISIS_LSP_DEL, 
            (void *)lsp_pkt, sizeof (*lsp_pkt), 
            true, isis_lsp_ips_free_fn);
            
        return;
    }

    cp_ips_send (node, IPC_LFA_ISIS, 
           IPC_LFA_ISIS_LSP_L1_DEL_ALL, 
            0, 0, false, 0);
}

void 
isis_ips_send_lsp_seqno_update (node_t *node, isis_lsp_pkt_t *lsp_pkt ) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    if (isis_is_protocol_shutdown_in_progress (node)) return;
    
    isis_ref_isis_pkt(lsp_pkt);
    cp_ips_send (node, IPC_LFA_ISIS, 
        IPC_LFA_ISIS_LSP_SEQNO_UPDATE,
        (void *)lsp_pkt, sizeof (*lsp_pkt), 
        true, isis_lsp_ips_free_fn);
}

void 
isis_ips_send_frr_config (node_t *node, uint8_t pvt_code, 
                                            bool frr_enable,
                                            uint32_t ifindex,
                                            isis_system_id_t system_id,
                                            bool node_link_degradation,
                                            bool rlfa, 
                                            bool use_spring, bool tilfa) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (isis_is_protocol_shutdown_in_progress (node)) return;

    isis_ips_frr_config_t *frr_config = (isis_ips_frr_config_t *)
                            calloc(1, sizeof(isis_ips_frr_config_t));

    frr_config->code = pvt_code;
    frr_config->system_id.rtr_id = NODE_LO_ADDR_INT(node);
    frr_config->system_id.pn_id = 0;

    switch (pvt_code) {

        case ISIS_PVT_IPS_CODE_FRR_ENABLE :
            frr_config->u.frr_enable = frr_enable;
            break;
        case ISIS_PVT_IPS_CODE_FRR_LINK_PROTECTION:
            frr_config->u.ifindex = ifindex;
            break;
        case ISIS_PVT_IPS_CODE_FRR_NODE_PROTECTION:
            frr_config->u.rtr_id = system_id.rtr_id;
            frr_config->u.pn_no = system_id.pn_id;
            break; 
        case ISIS_PVT_IPS_CODE_FRR_NODE_LINK_DEGRADATION:
            frr_config->u.node_link_degradation = node_link_degradation;
            break;
        case ISIS_PVT_IPS_CODE_FRR_ENABLE_RLFA:
            frr_config->u.rlfa = rlfa;
            break;
        case ISIS_PVT_IPS_CODE_FRR_USE_SPRING:
            frr_config->u.use_spring = use_spring;
            break;
        case ISIS_PVT_IPS_CODE_FRR_TILFA:
            frr_config->u.tilfa = tilfa;
            break;
        default:
            assert(0);
    }

    cp_ips_send (node, IPC_LFA_ISIS, 
        IPC_LFA_ISIS_FRR_CONFIG_UPDATE,
        (void *)frr_config, sizeof (*frr_config), 
        true, 0);

}