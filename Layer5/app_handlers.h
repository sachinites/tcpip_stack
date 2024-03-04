#ifndef __APP_HANDLERS__
#define __APP_HANDLERS__

#include "../CLIBuilder/libcli.h"

typedef struct stack Stack_t ;

int
spf_algo_handler(int cmdcode, Stack_t *tlv_stack,
                          op_mode enable_or_disable);

int
ddcp_config_cli_tree(param_t *param);

int
ddcp_show_cli_tree(param_t *param);

int
ddcp_run_cli_tree(param_t *param);

int
nmp_config_cli_tree(param_t *param);

int
nmp_show_cli_tree(param_t *param);

/*isis protocol CLI registration fns*/
int
isis_config_cli_tree(param_t *param);

int
isis_show_cli_tree(param_t *param) ;

int
isis_clear_cli_tree(param_t *param) ;

int
isis_run_cli_tree(param_t *param) ;

int
isis_debug_cli_tree(param_t *param) ;

#endif /* __APP_HANDLERS__ */
