#include "CLIBuilder/libcli.h"
#include "CLIBuilder/cmdtlv.h"
#include "../RDBMSImplementation/uapi/sql_api.h"
#include "graph.h"

#define CMDCODE_SQL_QUERY 1
#define SQL_QUERY_MAX_SIZE 256

extern graph_t *topo;
extern int cprintf (const char* format, ...) ;

static int
sql_query_handler (int cmdcode, 
                                Stack_t *tlv_stack,
                                op_mode enable_or_disable){

    int rc = 0;
    node_t *node;
    tlv_struct_t *tlv;
    
    char err_msg[128] = {0};
    char sql_query[SQL_QUERY_MAX_SIZE];

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id (tlv->leaf_id, "node-name")) {
            node = node_get_node_by_name(topo, tlv->value);
        }
        else if  (parser_match_leaf_id (tlv->leaf_id, "sql-token")) {
            rc += snprintf (sql_query + rc, SQL_QUERY_MAX_SIZE - rc, "%s ", tlv->value);
        }

        if (rc >= (SQL_QUERY_MAX_SIZE - 1 )) {
            cprintf ("Error : SQL Query too long\n");
            return -1;
        }

    } TLV_LOOP_END;

    sql_query[rc - 1] = '\n';
    sql_query[rc] = '\0';

    if (sql_query_exec (node->sql_db, sql_query, err_msg) < 0 ) {
        cprintf ("Error : %s\n", err_msg);
        return -1;
    }

    return 0;
}

void 
sql_build_cli_tree (param_t *root) {

    {
        static param_t q;
        init_param(&q, CMD, "sql-query", 0, 0, INVALID, 0, "Trigger Sql Query");
        libcli_register_param(root, &q);
        {
            static param_t sql_token;
            init_param(&sql_token, LEAF, 0, sql_query_handler, 0, STRING, "sql-token", "SQL Query Tokens");
            libcli_register_param(&q, &sql_token);
            libcli_param_recursive(&sql_token);
            libcli_set_param_cmd_code(&sql_token, CMDCODE_SQL_QUERY);
        }
    }

}