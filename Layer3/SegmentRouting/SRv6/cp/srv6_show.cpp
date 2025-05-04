#include <assert.h>
#include "../../../../CLIBuilder/libcli.h"
#include "../../../../graph.h"
#include "srv6_cmds.h"
#include "srv6_api.h"
#include "srv6_struct.h"
#include "srv6_rtr.h"
#include "../../../ipv6/ipv6_utils.h"
#include "srv6_sid_pool.h"

extern graph_t *topo;

int
srv6_show_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CMD_CODE_SHOW_SRV6_SIDS:
        {
            srv6_show_locator (NODE_SRv6_SID_POOL(node), NULL);
        }
        break;
        default:
            assert(0);
    }

    return 0;
}
