#include <ctype.h>
#include "graph.h"
#include "CLIBuilder/libcli.h"

extern graph_t *topo;

typedef struct event_dispatcher_ event_dispatcher_t;
extern event_dispatcher_t gev_dis;

event_dispatcher_t *
node_get_ev_dispatcher (Stack_t *tlv_stack) ;

event_dispatcher_t *
node_get_ev_dispatcher (Stack_t *tlv_stack) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id (tlv->leaf_id, "node-name")) {
            node_name = tlv->value;
            break;
        }
    }TLV_LOOP_END;

    if (!node_name) return &gev_dis;

    node = node_get_node_by_name(topo, node_name);
    assert(node);

    return &node->ev_dis;
}

