#include <ctype.h>
#include "graph.h"
#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"

extern graph_t *topo;

typedef struct event_dispatcher_ event_dispatcher_t;
extern event_dispatcher_t gev_dis;

event_dispatcher_t *
node_get_ev_dispatcher (ser_buff_t *tlv_buff) ;

event_dispatcher_t *
node_get_ev_dispatcher (ser_buff_t *tlv_buff) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_BEGIN(tlv_buff, tlv) {

        if (string_compare(tlv->leaf_id, "node-name", NODE_NAME_SIZE) == 0) {
            node_name = tlv->value;
            break;
        }
    }TLV_LOOP_END;

    if (!node_name) return &gev_dis;

    node = node_get_node_by_name(topo, node_name);
    assert(node);

    return &node->ev_dis;
}

void
parser_config_commit_internal (void *_node, ser_buff_t *tlv_ser_buff, op_mode enable_or_disable) {

    int i = 0;
    tlv_struct_t *tlv = NULL;
    PGresult *sql_query_result;
    unsigned char config_stmt[256];
    unsigned char node_name[NODE_NAME_SIZE];

    node_t *node = (node_t *)_node;

    do
    {
        node_name[i] = tolower(node->node_name[i]);
        i++;
    } while (i < NODE_NAME_SIZE);
    
    memset(config_stmt, 0, sizeof(config_stmt));

    if (enable_or_disable == CONFIG_ENABLE) {
        snprintf (config_stmt, sizeof (config_stmt),  "insert into %sconfig values ('", node_name);
    }
    else {
        snprintf (config_stmt, sizeof (config_stmt),  "delete from %sconfig where statement like '", node_name);
    }

    i = 0;

    TLV_LOOP_BEGIN(tlv_ser_buff, tlv){

       print_tlv_content (tlv);

        /* Skip Ist three TLVs : config node <node-name> */
        if (i < 3) {
            i++;
            continue;
        }

        switch (tlv->tlv_type) {
            case TLV_TYPE_NORMAL:
                strcat (config_stmt, tlv->value);
                strcat (config_stmt, " ");
                break;
            case TLV_TYPE_CMD_NAME:
                strcat (config_stmt, tlv->value);
                strcat (config_stmt, " ");
                break;
            default:
                assert(0);
        }

    } TLV_LOOP_END;

    if (enable_or_disable == CONFIG_ENABLE) {
        strcat (config_stmt, "')");
    }
    else {
        strcat (config_stmt, "%'");
    }

    printf ("sql = %s\n", config_stmt);
    sql_query_result = PQexec(node->conn, config_stmt);
    assert (PQresultStatus(sql_query_result) == PGRES_COMMAND_OK);
}