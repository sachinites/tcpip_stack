#include <ctype.h>
#include "graph.h"
#include "CLIBuilder/libcli.h"

extern graph_t *topo;

typedef struct event_dispatcher_ event_dispatcher_t;
extern event_dispatcher_t gev_dis;

/* With N-Curses we will disable async mode of CLI submission to backend app*/
#define ASYNC_MODE_DISABLED

void
task_invoke_appln_cbk_handler (param_t *param,
                                                      Stack_t  *tlv_stack,
                                                      op_mode enable_or_disable) ;

typedef struct unified_cli_data_{
    
        param_t *param;
        cmd_callback cbk;
        int cmdcode;
        int rc;
        Stack_t  *tlv_stack;
        op_mode enable_or_disable;
} unified_cli_data_t;

extern void 
parser_config_commit_internal (void *node, Stack_t  *tlv_stack, op_mode enable_or_disable);

static void
parser_config_commit(void *node, Stack_t  *tlv_stack, op_mode enable_or_disable) {

    if (!node) return; // for global commands such as config global stdout
    parser_config_commit_internal (node, tlv_stack, enable_or_disable);
}

static void
task_cbk_handler_internal (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size){

    int rc;
    tlv_struct_t *tlv;

    unified_cli_data_t *unified_cli_data =
        (unified_cli_data_t *)arg;

    unified_cli_data->rc = unified_cli_data->cbk(
        unified_cli_data->cmdcode,
        unified_cli_data->tlv_stack,
        unified_cli_data->enable_or_disable);

    /* Config Commit now*/
    if (!rc && unified_cli_data->enable_or_disable != OPERATIONAL) {

        parser_config_commit(ev_dis->app_data, unified_cli_data->tlv_stack, unified_cli_data->enable_or_disable);
    }

#ifndef ASYNC_MODE_DISABLED
    if ((unified_cli_data->enable_or_disable == CONFIG_ENABLE ||
        unified_cli_data->enable_or_disable == CONFIG_DISABLE))
    {
        while ((tlv = (tlv_struct_t *)pop(unified_cli_data->tlv_stack)))
        {
            free(tlv);
        }
    }
#endif 
    /*  Free the memory now */
    free_stack(unified_cli_data->tlv_stack);
    free(unified_cli_data);
}

static event_dispatcher_t *
node_get_ev_dispatcher (Stack_t *tlv_stack) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name")) {
            node_name = tlv->value;
            break;
        }
    }
    TLV_LOOP_END;

    if (!node_name)
        return &gev_dis;

    node = node_get_node_by_name(topo, node_name);
    assert(node);

    return &node->ev_dis;
}


/* Public API to be called by CLIBuilder*/
void
task_invoke_appln_cbk_handler (param_t *param,
                                                     Stack_t  *tlv_stack,
                                                     op_mode enable_or_disable) {

        int i = 0;
        tlv_struct_t *tlv;

        unified_cli_data_t *unified_cli_data =
                (unified_cli_data_t *)calloc(1, sizeof(unified_cli_data_t));

        //unified_cli_data->param = param;
        unified_cli_data->cbk = param->callback;
        unified_cli_data->cmdcode = param->CMDCODE;
        unified_cli_data->tlv_stack = (Stack_t *)get_new_stack();
        unified_cli_data->enable_or_disable = enable_or_disable;

#ifndef ASYNC_MODE_DISABLED
        if (enable_or_disable == OPERATIONAL) {
#else 
        if (true) {
#endif 
            for (i = 0; i <= tlv_stack->top; i++) {

                unified_cli_data->tlv_stack->slot[i] = tlv_stack->slot[i];
            }
            unified_cli_data->tlv_stack->top = tlv_stack->top;

            task_create_new_job_synchronous(
                node_get_ev_dispatcher(tlv_stack),
                (void *)unified_cli_data,
                task_cbk_handler_internal,
                TASK_ONE_SHOT,
                 enable_or_disable == OPERATIONAL ? 
                     TASK_PRIORITY_OPERATIONAL_CLI :
                     TASK_PRIORITY_CONFIG_CLI);
            }

        else {

            for (i = 0; i <= tlv_stack->top; i++) {

                tlv = (tlv_struct_t *)calloc(1, sizeof(tlv_struct_t));
                memcpy(tlv, tlv_stack->slot[i], sizeof(tlv_struct_t));
                unified_cli_data->tlv_stack->slot[i] = tlv;
            }

            unified_cli_data->tlv_stack->top = tlv_stack->top;

            task_create_new_job(
                node_get_ev_dispatcher(tlv_stack),
                (void *)unified_cli_data,
                task_cbk_handler_internal,
                TASK_ONE_SHOT,
                TASK_PRIORITY_CONFIG_CLI);
        }
}
