#ifndef __APP_HANDLERS__
#define __APP_HANDLERS__

#include "../CommandParser/libcli.h"

int
spf_algo_handler(param_t *param, ser_buff_t *tlv_buf,
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

#endif /* __APP_HANDLERS__ */
