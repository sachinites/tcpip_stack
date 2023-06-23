/*
 * =====================================================================================
 *
 *       Filename:  clistd.h
 *
 *    Description:  All Validation functions for leaves and standard default callbacks are defined in this file
 *
 *        Version:  1.0
 *        Created:  Sunday 06 August 2017 05:56:03  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#include <signal.h>
#include "cmd_hier.h"
#include "clistd.h"
#include "cmdtlv.h"
#include "libcli.h"
#include "css.h"
#include "clicbext.h"
#include "string_util.h"
#include "../FSMImplementation/std_fsm.h"
#include "../EventDispatcher/event_dispatcher.h"

int GL_FD_OUT = STDOUT_FILENO;

extern CMD_PARSE_STATUS
parse_input_cmd(char *input, unsigned int len, bool *is_repeat_cmd);

extern char *
get_last_command();

extern char temp[ LEAF_ID_SIZE + 2];

static void
dump_all_commands(param_t *root, unsigned int index){

        if(!root)
            return;

        if(IS_PARAM_NO_CMD(root))
            return;

        if(IS_PARAM_CMD(root)){
            untokenize(index);
            tokenize(GET_CMD_NAME(root), strlen(GET_CMD_NAME(root)), index);
        }
        else if(IS_PARAM_LEAF(root)){
            untokenize(index);
            memset(temp, 0, sizeof(temp));
            sprintf(temp, "<%s>", GET_LEAF_ID(root));
            tokenize(temp, strlen(GET_LEAF_ID(root)) + 2, index);
        }

        unsigned int i = CHILDREN_START_INDEX;

        for( ; i <= CHILDREN_END_INDEX; i++)
            dump_all_commands(root->options[i], index+1);
        
        if(IS_APPLICATION_CALLBACK_HANDLER_REGISTERED(root)){
            print_tokens(index + 1);
            printw("\n");
        }
}

/*Default validation handlers for Data types*/

CLI_VAL_RC
int_validation_handler(leaf_t *leaf, char *value_passed){
    /*printw("%s is called for leaf type = %s, leaf value = %s\n", __FUNCTION__,
     *                             get_str_leaf_type(leaf->leaf_type), value_passed);*/
    if (fsm_is_integer (value_passed, strlen(value_passed)))
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}


CLI_VAL_RC
string_validation_handler(leaf_t *leaf, char *value_passed){
    /*printw("%s is called for leaf type = %s, leaf value = %s\n", __FUNCTION__,
     *                             get_str_leaf_type(leaf->leaf_type), value_passed);*/
    return VALIDATION_SUCCESS;
}


CLI_VAL_RC
ipv4_validation_handler(leaf_t *leaf, char *value_passed){
    /*printw("%s is called for leaf type = %s, leaf value = %s\n", __FUNCTION__,
     *                             get_str_leaf_type(leaf->leaf_type), value_passed);*/
    if (ip_validate(value_passed)) {
        return VALIDATION_SUCCESS;
    }
    return VALIDATION_FAILED;

}


CLI_VAL_RC
ipv6_validation_handler(leaf_t *leaf, char *value_passed){
    /*printw("%s is called for leaf type = %s, leaf value = %s\n", __FUNCTION__,
     *                             get_str_leaf_type(leaf->leaf_type), value_passed);*/
    return VALIDATION_SUCCESS;
}


CLI_VAL_RC
float_validation_handler(leaf_t *leaf, char *value_passed){
    /*printw("%s is called for leaf type = %s, leaf value = %s\n", __FUNCTION__,
     *                             get_str_leaf_type(leaf->leaf_type), value_passed);*/
    return VALIDATION_SUCCESS;
}

CLI_VAL_RC
boolean_validation_handler(leaf_t *leaf, char *value_passed){

    if((strncmp(value_passed, "true", strlen("true")) == 0) || 
            (strncmp(value_passed, "false", strlen("false")) ==0))
        return VALIDATION_SUCCESS;

    return VALIDATION_FAILED;
}

int
enable_disable_validation_handler(char *value_passed){

     if((strncmp(value_passed, "enable", strlen("enable")) == 0) || 
            (strncmp(value_passed, "disable", strlen("disable")) ==0))
        return VALIDATION_SUCCESS;

    return VALIDATION_FAILED;
}


/* Default command handlers */
/*config console name <cons name>*/
extern char console_name[TERMINAL_NAME_SIZE];

 int
config_console_name_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(b, tlv){
        if(enable_or_disable == CONFIG_ENABLE)
            set_device_name(tlv->value);
        else{
            if(strncmp(tlv->value, console_name, strlen(tlv->value)) == 0)
                set_device_name(DEFAULT_DEVICE_NAME);
            else
                printw("Error : Incorrect device name\n");
        }
    }TLV_LOOP_END;
    return 0;
}

/*repeat*/
 int
repeat_last_command(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
    bool is_repeat_cmd;
    static char new_line_consume[2];
    char *last_cmd = get_last_command();
    printw("prev : %s", last_cmd);
    scanf("%c", new_line_consume);;
    parse_input_cmd(last_cmd, strlen(last_cmd), &is_repeat_cmd);
    return 0;
}

extern void
task_invoke_appln_cbk_handler(param_t *param,
						 ser_buff_t *tlv_buff,
						 op_mode enable_or_disable) ;

 int
mode_enter_callback(param_t *param, ser_buff_t *tlv_buff, op_mode enable_or_disable){
 
    if(param == libcli_get_root()){
        printw(ANSI_COLOR_YELLOW "Info : Mode not supported at root level\n" ANSI_COLOR_RESET);
        return 0;   
    }
    set_cmd_tree_cursor(param);
    build_mode_console_name(param);

    if (IS_APPLICATION_CALLBACK_HANDLER_REGISTERED(param))
    {
#ifndef ENABLE_EVENT_DISPATCHER
        INVOKE_APPLICATION_CALLBACK_HANDLER(param, tlv_buff, enable_or_disable);
#else
        task_invoke_appln_cbk_handler(param, tlv_buff, enable_or_disable);
        printw("CLI returned\n");
#endif
    }
    return 0;
}
 
 
 int
display_sub_options_callback(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
    
    int i = 0;
    tlv_struct_t dummy;

    if(IS_APPLICATION_CALLBACK_HANDLER_REGISTERED(param))
        printw("<Enter>\n");

    for(i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++){
        if(param->options[i]){

            if(IS_PARAM_HIDDEN(param->options[i]))
                continue;

            if(IS_PARAM_CMD(param->options[i]) || IS_PARAM_NO_CMD(param->options[i])){
                printw(ANSI_COLOR_MAGENTA "nxt cmd  -> %-31s   |   %s\n" ANSI_COLOR_RESET, GET_CMD_NAME(param->options[i]), GET_PARAM_HELP_STRING(param->options[i]));
                continue;
            }
            printw(ANSI_COLOR_CYAN "nxt leaf -> %-32s  |   %s\n" ANSI_COLOR_RESET, GET_LEAF_TYPE_STR(param->options[i]), GET_PARAM_HELP_STRING(param->options[i]));
            continue;
        }
        break;
    }

    /*Means param is a leaf*/
    if(param->disp_callback){

        /*Add a dummy TLV to compensate for the cmd code TLV*/
        memset(&dummy, 0, sizeof(tlv_struct_t));
        collect_tlv(b, &dummy);
        printw(ANSI_COLOR_YELLOW "possible values :\n");
        param->disp_callback(param, b);
        printw(ANSI_COLOR_RESET);
    }
    return 0;
}


 int
display_cmd_expansion_callback(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    re_init_tokens(MAX_CMD_TREE_DEPTH);
    unsigned int index = 0;

    dump_all_commands(param, index);
    return 0;
}   


/* show history calback*/

static char file_cmsd_size[FILE_CMD_SIZE_MAX];

 int
show_history_callback(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
   
    int cmd_counter = 0;
    bool is_repeat_cmd;

    unsigned long cmd_offset[MAX_SAVED_CMDS];

    memset(&cmd_offset, 0, MAX_SAVED_CMDS * sizeof(unsigned long));
    FILE *f = fopen(CMD_HIST_RECORD_FILE, "r");
    
    if(!f){
        printw("Error : History file could not be read\n");
        return 0;
    }
   
   memset(file_cmsd_size, 0, FILE_CMD_SIZE_MAX);
  
   cmd_offset[cmd_counter++] = ftell(f);
   while(fgets(file_cmsd_size, FILE_CMD_SIZE_MAX, f) != NULL) {
       printw("%d. %s", cmd_counter - 1, file_cmsd_size);
       cmd_offset[cmd_counter++] = ftell(f);
       memset(file_cmsd_size, 0, FILE_CMD_SIZE_MAX);
   } 
 
    int cmd_choice;
    printw("Enter command no to trigger : ");
    scanf("%d", &cmd_choice);
    if(!(cmd_choice >= 0 && cmd_choice < cmd_counter)){
        printw("Invalid choice\n");
        fclose(f) ;
        return 0;
    }

    
   fseek(f, cmd_offset[cmd_choice], SEEK_SET);
   memset(file_cmsd_size, 0, FILE_CMD_SIZE_MAX);
   fgets(file_cmsd_size, FILE_CMD_SIZE_MAX, f);
   file_cmsd_size[FILE_CMD_SIZE_MAX -1] = '\0';

   printw("Command to be triggered : %s", file_cmsd_size); 
   parse_input_cmd(file_cmsd_size, strlen(file_cmsd_size), &is_repeat_cmd);   

   fclose(f) ;
   return 0; 
}

 void
record_command(const char *hist_file, char *cons_input_buffer, unsigned int cmd_len){

    assert(hist_file || cons_input_buffer || !cmd_len);
    
    static unsigned int cmd_counter = 0;
    
    if(cmd_counter == MAX_SAVED_CMDS){
        return;
    }
    FILE *f = fopen(CMD_HIST_RECORD_FILE, "a");
    fwrite(cons_input_buffer, cmd_len, 1, f);
    fwrite("\n", 1, 1, f);
    cmd_counter++;
    fclose(f);
}

int
clear_screen_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
    
    system("clear");
    return 0;   
}

int
exit_cmd_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
   
    go_one_level_up_cmd_tree(get_cmd_tree_cursor());
    return 0;
}

int
end_cmd_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    goto_top_of_cmd_tree(get_cmd_tree_cursor());    
    return 0;
}

int
config_mode_enter_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    set_cmd_tree_cursor(param);
    build_mode_console_name(param);
    mark_checkpoint_serialize_buffer(b);
    return 0;
}

extern void
parse_file(char *file_name);

int
load_file_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

	char *file_name = NULL;
	tlv_struct_t *tlv = NULL;

    printw("No Op - Full type the command\n");
    return 0;

	TLV_LOOP_BEGIN(b, tlv) {

		if (strncmp(tlv->leaf_id, "file-name",
				strlen("file-name")) == 0) {

			file_name = tlv->value;
		}
	} TLV_LOOP_END;

	assert(file_name);
	
	parse_file(file_name);	
	return 0;
}

int
negate_callback(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
    printw("Command Negation - Type the cmd following to Negate\n");
    return 0;
}

int
supportsave_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    switch(enable_or_disable){
        case CONFIG_ENABLE:
            signal(SIGTERM, terminate_signal_handler);/*When process is killed*/
            signal(SIGSEGV, terminate_signal_handler);/*When process access illegal memory*/
            signal(SIGABRT, terminate_signal_handler);/*when process abort itself*/
            break;
        case CONFIG_DISABLE:
            signal(SIGTERM, SIG_DFL);/*When process is killed*/
            signal(SIGSEGV, SIG_DFL);/*When process access illegal memory*/
            signal(SIGABRT, SIG_DFL);/*when process abort itself*/
            break;
        default:
            assert(0);
    }
    return 0;
}

int
cli_terminate_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    printw("Bye Bye\n");
    exit(0);
}

extern unsigned int cli_count;

int
show_help_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    printw("Welcome to Help Wizard\n");
    printw("========================\n");
    printw("1. Use '%s' Character after the command to enter command mode\n", MODE_CHARACTER);
    printw("2. Use '%s' Character after the command to see possible follow up suboptions\n", SUBOPTIONS_CHARACTER);
    printw("3. Use '%s' from within the config branch to directly trigger operational commands\n", DO);
    printw("4. Use '%s' Character after the command to see possible complete command completions\n", CMD_EXPANSION_CHARACTER);
    printw("5. Built-in commands:\n");
    printw("    a. %s - clear screen\n", CLEAR_SCR_STRING);
    printw("    b. %s - jump to top of cmd tree\n", GOTO_TOP_STRING);
    printw("    c. %s - jump one level up of command tree\n", GOTO_ONE_LVL_UP_STRING);
    printw("    d. config [%s] console name <console name> - set/unset new console name\n", NEGATE_CHARACTER);
    printw("    e. config [%s] supportsave enable - enable/disable supportsave facility\n", NEGATE_CHARACTER);
    printw("    f. debug show cmdtree - Show entire command tree\n");
    printw("    g. show history - show history of commands triggered\n");
    printw("    h. repeat - repeat the last command\n");
	printw(ANSI_COLOR_YELLOW "                      Author : Abhishek Sagar\n" ANSI_COLOR_RESET);
	printw(ANSI_COLOR_YELLOW "                      Visit : www.csepracticals.com for more courses and projects\n" ANSI_COLOR_RESET);
    return 0;
}


int
show_resgistered_cmd_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){
    
    /*Implement DFS and dump all complete commands*/
    re_init_tokens(MAX_CMD_TREE_DEPTH);

    param_t *root = libcli_get_root();
    
    unsigned int index = 0;
    dump_all_commands(root, index);
    printw ("Number of Registered CLIs : %u\n", cli_count);
    return 0;
}

int
show_cmd_tree(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

        dump_cmd_tree();
        return 0;
}

int
show_extension_param_handler(param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    tlv_struct_t tlv;
    memset(&tlv, 0, sizeof(tlv_struct_t));

    if(param == libcli_get_show_brief_extension_param()){
        put_value_in_tlv((&tlv), SHOW_EXTENSION_PARAM_BRIEF);
        tlv.leaf_type = INVALID;
        strncpy((char *)tlv.leaf_id, SHOW_EXTENSION_PARAM, strlen("SHOW_EXTENSION_PARAM"));
        collect_tlv(b, &tlv);
    }
    return 0;
}

int
grep_pattern_validation(char *value_passed){

    int i = 0;
    while (value_passed[i] != '\0') {
        if (value_passed[i]  == ' ' ) return VALIDATION_FAILED;
        i++;
    }
    return VALIDATION_SUCCESS;
}

int
pipe_handler (param_t *param, ser_buff_t *b, op_mode enable_or_disable){

    printw ("%s() called \n", __FUNCTION__);
    return 0;
}
