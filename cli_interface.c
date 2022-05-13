#include "graph.h"
#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"

extern graph_t *topo;

typedef struct event_dispatcher_ event_dispatcher_t;
extern event_dispatcher_t gev_dis;

extern event_dispatcher_t *
node_get_ev_dispatcher (ser_buff_t *tlv_buff) {

    node_t *node;
    tlv_struct_t *tlv;
    char *node_name = NULL;

    TLV_LOOP_BEGIN(tlv_buff, tlv) {

        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
            node_name = tlv->value;
            break;
        }
    }TLV_LOOP_END;

    if (!node_name) return &gev_dis;

    node = node_get_node_by_name(topo, node_name);
    assert(node);

    return &node->ev_dis;
}

