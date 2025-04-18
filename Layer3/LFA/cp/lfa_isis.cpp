#include <assert.h>
#include <stdint.h>

#include "../../../cp_ipc.h"
#include "../../../cp_ipc_struct.h"
#include "../../../Tracer/tracer.h"

#include "../../../graph.h"
#include "lfaconst.h"
#include "lfa.h"
#include "lfa_isis.h"

static void 
 lfa_isis_lsp_updates(node_t *node,
                          ips_major_code_t major_code,
                          uint32_t minor_code,
                          void *msg,
                          uint32_t msg_size);

void 
lfa_isis_init (node_t *node, lfa_t *lfa, uint8_t level) {

    assert (level == 1 || level == 2);
    uint8_t index = (level == 1) ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX;
    lfa_config_t *isis_lfa_config = &lfa->lfa_config[index];
    if (isis_lfa_config->u.isis.enable) return;
    isis_lfa_config->u.isis.enable = true;
    cp_ips_join (node, IPC_LFA_ISIS, 
        IPC_LFA_ISIS_LSP_ADD | 
        IPC_LFA_ISIS_LSP_DEL |
        IPC_LFA_ISIS_LSP_DEL_ALL,
        lfa_isis_lsp_updates);
}

void 
lfa_isis_deinit (node_t *node, lfa_t *lfa, uint8_t level) {

    assert (level == 1 || level == 2);
    uint8_t prot_index = (level == 1) ? ISIS_L1_LFA_INFEX : ISIS_L2_LFA_INFEX;
    lfa_config_t *isis_lfa_config = &lfa->lfa_config[prot_index];
    if (!isis_lfa_config->u.isis.enable) return;
    lfa_cleanup(node, isis_lfa_config, prot_index);
    isis_lfa_config->u.isis.enable = false;
    cp_ips_unjoin(node, IPC_LFA_ISIS, lfa_isis_lsp_updates);
}

void 
 lfa_isis_cleanup (node_t *node, lfa_config_t *lfa_config) {

 }

 void 
 lfa_isis_lsp_updates (node_t *node,
                          ips_major_code_t major_code,
                          uint32_t minor_code,
                          void *msg,
                          uint32_t msg_size)
 {
 
    tracer(LFA_TR(node), TR_LFA_ISIS | TR_LFA_DB_UPDATE, 
        "%s : Rcvd LSP , Opn %d\n",  LFA_ISIS_LSP_LOG, minor_code);
 }