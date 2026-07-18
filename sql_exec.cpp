#include <stdint.h>
#include "CLIBuilder/libcli.h"

#define SQL_QUERY_MAX_SIZE 512

#include "router.h"
#include "router_init.h"
#include "../RDBMSImplementation/uapi/sql_api.h"

extern graph_t *topo;

int
sql_query_processing_cli_hander(int64_t cmdcode, 
                                Stack_t *tlv_stack, 
                                op_mode enable_or_disable);

int
sql_query_processing_cli_hander(int64_t cmdcode, 
                                Stack_t *tlv_stack, 
                                op_mode enable_or_disable) 
{
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

    if (sql_query_exec (node->cp_rdbms, sql_query, err_msg) < 0 ) {
        cprintf ("Error : %s\n", err_msg);
        return -1;
    }

    return 0;    

}