/*
 * =====================================================================================
 *
 *       Filename:  cmd_hier.h
 *
 *    Description:  This file defines the structure for maintaining cmd hierarchy
 *
 *        Version:  1.0
 *        Created:  Thursday 03 August 2017 02:08:10  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#ifndef __CMD_HIER__
#define __CMD_HIER__

#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "libcliid.h"
#include "clistd.h"

#include "cliconst.h"

typedef struct serialized_buffer ser_buff_t;
typedef int (*cmd_callback)(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_diable);
typedef int (*user_validation_callback)(char *leaf_value);
typedef void (*display_possible_values_callback)(param_t *, ser_buff_t *);

typedef struct _param_t_ param_t;

typedef struct cmd{
    char cmd_name[CMD_NAME_SIZE];
} cmd_t;

typedef struct leaf{
    leaf_type_t leaf_type;
    char value_holder[LEAF_VALUE_HOLDER_SIZE];
    user_validation_callback user_validation_cb_fn;
    char leaf_id[LEAF_ID_SIZE];/*Within a single command, it should be unique*/
} leaf_t;

typedef CLI_VAL_RC (*leaf_type_handler)(leaf_t *leaf, char *value_passed);

typedef enum{
    CMD,
    LEAF,
    NO_CMD
} param_type_t;

typedef union _param_t{
    cmd_t *cmd;
    leaf_t *leaf;
} _param_t;

struct _param_t_{
    param_type_t param_type;
    _param_t cmd_type;
    cmd_callback callback;
    char ishidden;
    char help[PARAM_HELP_STRING_SIZE];
    param_t *options[MAX_OPTION_SIZE];
    param_t *parent;
    display_possible_values_callback disp_callback;
    int CMDCODE;
};

char*
get_str_leaf_type(leaf_type_t leaf_type);


#define MIN(a,b)    (a < b ? a : b)

#define GET_PARAM_CMD(param)    (param->cmd_type.cmd)
#define GET_PARAM_LEAF(param)   (param->cmd_type.leaf)
#define IS_PARAM_NO_CMD(param)  (param->param_type == NO_CMD)
#define IS_PARAM_CMD(param)     (param->param_type == CMD)
#define IS_PARAM_LEAF(param)    (param->param_type == LEAF)
#define GET_LEAF_TYPE_STR(param)    (get_str_leaf_type(GET_PARAM_LEAF(param)->leaf_type))
#define GET_LEAF_VALUE_PTR(param)   (GET_PARAM_LEAF(param)->value_holder)
#define GET_LEAF_TYPE(param)        (GET_PARAM_LEAF(param)->leaf_type)
#define GET_CMD_NAME(param)         (GET_PARAM_CMD(param)->cmd_name)
#define GET_PARAM_HELP_STRING(param) (param->help)
#define GET_LEAF_ID(param)          (GET_PARAM_LEAF(param)->leaf_id)

#define IS_LEAF_USER_VALIDATION_CALLBACK_REGISTERED(param)  \
                    (param->cmd_type.leaf->user_validation_cb_fn)

#define IS_APPLICATION_CALLBACK_HANDLER_REGISTERED(param)   (param->callback)

#define _INVOKE_LEAF_USER_VALIDATION_CALLBACK(param, arg) \
                    (param->cmd_type.leaf->user_validation_cb_fn(arg))

#define INVOKE_LEAF_LIB_VALIDATION_CALLBACK(param, arg) \
                    (leaf_handler_array[GET_LEAF_TYPE(param)](GET_PARAM_LEAF(param), arg))

#define INVOKE_APPLICATION_CALLBACK_HANDLER(param, arg, enable_or_disable) \
                    param->callback(param, arg, enable_or_disable);

#define IS_PARAM_MODE_ENABLE(param_ptr)         (param_ptr->options[MODE_PARAM_INDEX] != NULL)
#define IS_PARAM_SUBOPTIONS_ENABLE(param_ptr)   (param_ptr->options[SUBOPTIONS_INDEX] != NULL)


/*True if user is not operating in root level*/
int
is_user_in_cmd_mode();

param_t *
libcli_get_no_hook(void);

param_t *
libcli_get_do_hook(void);

param_t *
libcli_get_root(void);

param_t *
libcli_get_mode_param();

param_t *
libcli_get_suboptions_param();

param_t *
libcli_get_cmd_expansion_param();

param_t *
libcli_get_repeat_hook(void);

param_t *
libcli_get_show_brief_extension_param(void);

static inline param_t **
get_child_array_ptr(param_t *param){
    return &param->options[0];
}

static inline int
INVOKE_LEAF_USER_VALIDATION_CALLBACK(param_t *param, char *leaf_value) {

    assert(param);
    assert(leaf_value);

    /*If validation fn is not registered, then validation is assumed to be passed*/
    if(!IS_LEAF_USER_VALIDATION_CALLBACK_REGISTERED(param))
        return 0;

    return _INVOKE_LEAF_USER_VALIDATION_CALLBACK(param, leaf_value);
}


#define PRINT_TABS(n)     \
do{                       \
   unsigned short _i = 0; \
   for(; _i < n; _i++)    \
       printf("  ");      \
} while(0);

/*Command Mode implementation*/

param_t *
get_current_branch_hook(param_t *current_param);


#define IS_CURRENT_MODE_SHOW()      (get_current_branch_hook(get_cmd_tree_cursor()) == libcli_get_show_hook())
#define IS_CURRENT_MODE_DEBUG()     (get_current_branch_hook(get_cmd_tree_cursor()) == libcli_get_debug_hook())
#define IS_CURRENT_MODE_CONFIG()    (get_current_branch_hook(get_cmd_tree_cursor()) == libcli_get_config_hook())
#define IS_CURRENT_MODE_CLEAR()     (get_current_branch_hook(get_cmd_tree_cursor()) == libcli_get_clear_hook())

void
reset_cmd_tree_cursor();

void
goto_top_of_cmd_tree(param_t *curr_cmd_tree_cursor);

void
go_one_level_up_cmd_tree(param_t *curr_cmd_tree_cursor);

void
set_cmd_tree_cursor(param_t *param);

param_t *
get_cmd_tree_cursor();

param_t*
find_matching_param(param_t **options, const char *cmd_name);

void
build_mode_console_name(param_t *dst_param);

/*Source and Destination command MUST be in the same branch AND
 * Source must be at higher level as compared to Destination*/
void
build_cmd_tree_leaves_data(ser_buff_t *tlv_buff,/*Output serialize buffer*/ 
                            param_t *src_param, /*Source command*/
                            param_t *dst_param);/*Destination command*/

static inline int 
is_cmd_string_match(param_t *param,
                    const char *str,
                    bool *ex_match) {

    *ex_match = false;
    int str_len = strlen(str);
    int str_len_param = strlen(param->cmd_type.cmd->cmd_name);

    int rc =  (strncmp(param->cmd_type.cmd->cmd_name, 
                str, str_len));

    if ( !rc && (str_len == str_len_param )) {
        *ex_match = true;
    }   
    return rc; 
}

#endif
