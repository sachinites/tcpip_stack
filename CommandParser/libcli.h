/*
 * =====================================================================================
 *
 *       Filename:  libcli.h
 *
 *    Description:  User interface Header file.
 *
 *        Version:  1.0
 *        Created:  Saturday 05 August 2017 11:23:15  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#ifndef __LIBCLI__
#define __LIBCLI__

#include "libcliid.h"
#include "cmd_hier.h"


void
init_libcli();

void
set_device_name(const char *cons_name);

/*import functions. These functions to be used to get access to 
 * library global variables - the zero level command hooks */

param_t *
libcli_get_show_hook(void);

param_t *
libcli_get_debug_hook(void);

param_t *
libcli_get_debug_show_hook(void);

param_t *
libcli_get_config_hook(void);

param_t *
libcli_get_clear_hook(void);

param_t *
libcli_get_run_hook(void);

void
enable_show_extension_param_brief(param_t *param);

void
set_param_cmd_code(param_t *param, int cmd_code);

/*See the definition of this fn to know about arguments*/
void
init_param(param_t *param,              
           param_type_t param_type,     
           char *cmd_name,              
           cmd_callback callback,
           user_validation_callback user_validation_cb_fn,
           leaf_type_t leaf_type,
           char *leaf_id,
           char *help);

void 
libcli_register_param(param_t *parent, param_t *child);

void
libcli_register_display_callback(param_t *param,
                                 display_possible_values_callback disp_callback);

show_ext_t
get_show_extension_type(ser_buff_t *b);
/*After this call, libcli_register_param MUST not be invoked on param*/
void
support_cmd_negation(param_t *param);

void
dump_cmd_tree();

void
start_shell(void);

#define HIDE_PARAM(param_ptr)   ((param_ptr)->ishidden = 1)
#define IS_PARAM_HIDDEN(param_ptr)  ((param_ptr)->ishidden == 1)

#endif
