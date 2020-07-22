#ifndef __APP_HANDLERS__
#define __APP_HANDLERS__

#include "../CommandParser/libcli.h"

int
nbrship_mgmt_handler(param_t *param, ser_buff_t *tlv_buf,
                op_mode enable_or_disable);

#endif /* __APP_HANDLERS__ */
