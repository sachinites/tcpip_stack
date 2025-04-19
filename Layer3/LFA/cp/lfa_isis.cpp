#include <assert.h>
#include <stdint.h>
#include "../../../tcp_public.h"

#include "lfaconst.h"
#include "lfa.h"
#include "lfa_isis.h"

#include "../isis/isis_pkt.h"
#include "../isis/isis_lspdb.h"
#include "../isis/isis_ted.h"

static void 
 lfa_isis_lsp_updates(node_t *node,
                          ips_major_code_t major_code,
                          uint32_t minor_code,
                          void *msg,
                          uint32_t msg_size);

ted_db_t *
lfa_get_isis_teddb (node_t *node, uint8_t level)
{
    lfa_t *lfa;

    if ((lfa = LFA_NODE_INFO(node)) == NULL) return NULL;
    if (!lfa->enable) return NULL;

    lfa_config_t *lfa_config = &lfa->lfa_config[level == 1 ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX];
    return &lfa_config->u.isis.topo;
}

static int
lfa_isis_ted_db_cmp_fn (const avltree_node_t *n1, const avltree_node_t *n2) {

    ted_node_t *node1 = avltree_container_of (n1, ted_node_t, avl_glue);
    ted_node_t *node2 = avltree_container_of (n2, ted_node_t, avl_glue);

    if (node1->rtr_id < node2->rtr_id) return  CMP_PREFERRED;
    if (node1->rtr_id > node2->rtr_id) return  CMP_NOT_PREFERRED;
    if (node1->pn_no < node2->pn_no) return  CMP_PREFERRED;
    if (node1->pn_no > node2->pn_no) return  CMP_NOT_PREFERRED;
   return CMP_PREF_EQUAL;
}

static void 
lfa_isis_lfa_data_cleanup_fn (ted_node_t *ted_node) {

        void *data = ted_node->proto_data[TED_ISIS_PROTO];
        ted_node->proto_data[TED_ISIS_PROTO] = NULL;

        // ToDo : free fata
}

void 
lfa_isis_init (node_t *node, lfa_t *lfa, uint8_t level) {

    assert (level == 1 || level == 2);
    uint8_t index = (level == 1) ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX;
    lfa_config_t *isis_lfa_config = &lfa->lfa_config[index];

    ted_init_teddb(&isis_lfa_config->u.isis.topo, 
            lfa_isis_ted_db_cmp_fn, lfa_isis_lfa_data_cleanup_fn );
    
    cp_ips_join (node, IPC_LFA_ISIS, 
        IPC_LFA_ISIS_LSP_ADD | 
        IPC_LFA_ISIS_LSP_DEL |
        IPC_LFA_ISIS_LSP_L1_DEL_ALL |
        IPC_LFA_ISIS_LSP_L2_DEL_ALL | 
        IPC_LFA_ISIS_LSP_SEQNO_UPDATE,
        lfa_isis_lsp_updates);
}

void 
lfa_isis_deinit (node_t *node, lfa_t *lfa, uint8_t level) {

    assert (level == 1 || level == 2);
    uint8_t prot_index = (level == 1) ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX;
    lfa_config_t *isis_lfa_config = &lfa->lfa_config[prot_index];
    lfa_cleanup(node, prot_index);
    cp_ips_unjoin(node, IPC_LFA_ISIS, lfa_isis_lsp_updates);
}

 void 
 lfa_isis_lsp_updates (node_t *node,
                          ips_major_code_t major_code,
                          uint32_t minor_code,
                          void *msg,
                          uint32_t msg_size)
 {
 
    ted_db_t *ted_db ;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    assert (major_code == IPC_LFA_ISIS);

    isis_lsp_pkt_t *lsp_pkt = (isis_lsp_pkt_t *)msg;

    isis_print_lsp_id (lsp_pkt, lsp_id_str);

    /* Get level from this LSP pkt*/
    isis_pkt_type_t lsp_pkt_type = isis_get_pdu_type(lsp_pkt);

    uint8_t level = (lsp_pkt_type == ISIS_L1_LSP_PKT_TYPE) ? 1 : 2;

    if (!lfa_is_enabled (node)) return ;
    
    ted_db = lfa_get_isis_teddb(node, level);
    lfa_config_t *lfa_config = lfa_get_config(node, 
            level == 1 ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX);

    switch (minor_code) {

        case IPC_LFA_ISIS_LSP_ADD:
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
                "%s : LSP %s Level-%d ADD\n",  LFA_ISIS_LSP_LOG, lsp_id_str, level);
            lfa_config->u.isis.lsp_add_update_recvd++;
            isis_ted_update_or_install_lsp(node, ted_db, lsp_pkt);
            break;
        case IPC_LFA_ISIS_LSP_DEL:
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
                "%s : LSP %s Level-%d DEL\n",  LFA_ISIS_LSP_LOG, lsp_id_str, level);
            lfa_config->u.isis.lsp_del_recvd++;
            isis_ted_uninstall_lsp (node, ted_db, lsp_pkt);
            break;
        case IPC_LFA_ISIS_LSP_L1_DEL_ALL:
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
                "%s : LSP DEL ALL Level-1\n",  LFA_ISIS_LSP_LOG);
            lfa_cleanup (node, ISIS_L1_LFA_INFEX);
            break;
            case IPC_LFA_ISIS_LSP_L2_DEL_ALL:
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
                "%s : LSP DEL ALL Level-2\n",  LFA_ISIS_LSP_LOG);
            lfa_cleanup (node, ISIS_L2_LFA_INFEX);
            break;
        case IPC_LFA_ISIS_LSP_SEQNO_UPDATE:
        {
            lfa_config->u.isis.lsp_add_update_recvd++;
            uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
            uint8_t pn_no = isis_get_lsp_pkt_pn_id (lsp_pkt);
            uint32_t *seq_no = isis_get_lsp_pkt_seq_no (lsp_pkt);
            ted_node_t *ted_node = ted_lookup_node(ted_db, *rtr_id, pn_no);
            assert(ted_node);
            ted_node->seq_no = *seq_no;
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
                "%s : LSP %s Level-%d SEQNO UPDATE to %u\n", 
                     LFA_ISIS_LSP_LOG, lsp_id_str, level,  ted_node->seq_no);
        }
            break;
        default:
            tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE | TR_LFA_ERROR, 
                "%s : Error : LSP UNKNOWN IPS\n",  LFA_ISIS_LSP_LOG);
            break;
    }

 }