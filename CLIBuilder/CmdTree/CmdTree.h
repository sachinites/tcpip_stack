#ifndef __CMDTREE__
#define __CMDTREE__

#include <stdbool.h>
#include <stdint.h>
#include "../cli_const.h"
#include "../../gluethread/glthread.h"
#include "CmdTreeEnums.h"

typedef struct _param_t_ param_t;
typedef struct serialized_buffer ser_buff_t;
typedef struct tlv_struct  tlv_struct_t;
typedef struct stack Stack_t;

typedef int (*user_validation_callback)(Stack_t *, unsigned char *leaf_value);
typedef void (*display_possible_values_callback)(param_t *, Stack_t *);
typedef int (*cmd_callback)(int cmdcode, 
                                              Stack_t *tlv_stack,
                                              op_mode enable_or_diable);

typedef struct cmd{
    char cmd_name[CMD_NAME_SIZE];
    int len;
} cmd_t;

typedef struct leaf {
    leaf_type_t leaf_type;
    user_validation_callback user_validation_cb_fn;
    char leaf_id[LEAF_ID_SIZE];/*Within a single command, it should be unique*/
    char reg_ex[LEAF_REG_EX_MAX_LEN];
} leaf_t;


typedef union _param_t{
    cmd_t *cmd;
    leaf_t *leaf;
} _param_t;

struct _param_t_{
    param_type_t param_type;
    _param_t cmd_type;
    cmd_callback callback;
    char help[PARAM_HELP_STRING_SIZE];
    struct _param_t_ *options[MAX_OPTION_SIZE];
    struct _param_t_ *parent;
    display_possible_values_callback disp_callback;
    int CMDCODE;
    uint8_t flags;
    glthread_t glue;
};
GLTHREAD_TO_STRUCT (glue_to_param, param_t, glue);

#define GET_PARAM_CMD(param)    (param->cmd_type.cmd)
#define GET_PARAM_LEAF(param)   (param->cmd_type.leaf)
#define IS_PARAM_NO_CMD(param)  (param->param_type == NO_CMD)
#define IS_PARAM_CMD(param)     (param->param_type == CMD)
#define IS_PARAM_LEAF(param)    (param->param_type == LEAF)
#define GET_LEAF_TYPE_STR(param)    (get_str_leaf_type(GET_PARAM_LEAF(param)->leaf_type))
#define GET_LEAF_TYPE(param)        (GET_PARAM_LEAF(param)->leaf_type)
#define GET_CMD_NAME(param)         (GET_PARAM_CMD(param)->cmd_name)
#define GET_PARAM_HELP_STRING(param) (param->help)
#define GET_LEAF_ID(param)          (GET_PARAM_LEAF(param)->leaf_id)

#define PARAM_F_NO_EXPAND   1
#define PARAM_F_NO_DISPLAY_QUESMARK 2
#define PARAM_F_DISABLE_PARAM   4
#define PARAM_F_CONFIG_BATCH_CMD   8
#define PARAM_F_RECURSIVE   16
#define PARAM_F_REG_EX_MATCH    32

void 
cmd_tree_init ();

/* Function to be used to get access to above hooks*/

param_t *
libcli_get_root_hook(void);

param_t *
libcli_get_show_hook(void);

param_t *
libcli_get_debug_hook(void);

param_t *
libcli_get_config_hook(void);

param_t *
libcli_get_clear_hook(void);

param_t *
libcli_get_run_hook(void);

param_t *
libcli_get_refresh_hook(void);

param_t *
libcli_get_refresh_val_hook(void);

param_t *
libcli_get_clrscr_hook(void);

bool
cmd_tree_leaf_char_save (unsigned char *curr_leaf_value, unsigned char c, int index);

tlv_struct_t *
cmd_tree_convert_param_to_tlv (param_t *param, unsigned char *curr_leaf_value);

void
cmd_tree_display_all_complete_commands(
                                                    param_t *root, 
                                                    unsigned int index);

void 
cmd_tree_install_universal_params (param_t *param, param_t *branch_hook);

void 
cmd_tree_uninstall_universal_params (param_t *param);

bool 
param_is_hook (param_t *param);

bool 
cmd_tree_is_token_a_hook (char *token) ;

param_t*
cmd_tree_find_matching_param (param_t **options, const char *cmd_name);

bool 
cmd_tree_is_param_pipe (param_t *param);

bool 
cmd_tree_is_filter_param (param_t *param);

#endif 
