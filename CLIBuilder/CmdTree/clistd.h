#ifndef __CLISTD__ 
#define __CLISTD__

#include "../cli_const.h"

typedef struct tlv_struct  tlv_struct_t;
typedef struct stack Stack_t;
typedef struct _param_t_ param_t;

extern leaf_validation_rc_t clistd_validate_leaf (tlv_struct_t *tlv);

int
clistd_config_device_default_handler (param_t *param, Stack_t *tlv_stack, op_mode enable_or_disable);

int
show_help_handler (param_t *param,  Stack_t *tlv_stack, op_mode enable_or_disable) ;

int
show_history_handler (param_t *param,  Stack_t *tlv_stack, op_mode enable_or_disable) ;

#endif