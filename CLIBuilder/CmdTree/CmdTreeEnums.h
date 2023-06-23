#ifndef __CMDTEE_ENUMS__
#define __CMDTEE_ENUMS__

typedef enum cmdt_cursor_op_res_ {

    cmdt_cursor_ok,
    cmdt_cursor_no_match_further,
    cmdt_cursor_done_auto_completion
} cmdt_cursor_op_res_t;

typedef enum{
    CMD,
    LEAF,
    NO_CMD
} param_type_t;

#endif