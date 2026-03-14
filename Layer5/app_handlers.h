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

int
srv6_build_global_config_cli_tree (param_t *root) ;

int
srv6_build_cli_show_tree (param_t *root);

int
lfa_show_cli_tree(param_t *param);

int
lfa_config_cli_tree(param_t *param) ;

param_t *
vrf_build_config_tree (param_t *node_name);

int
show_arp_cli_tree(param_t *param);

int
ping_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable);

#endif /* __APP_HANDLERS__ */
