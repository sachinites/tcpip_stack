/*
 * =====================================================================================
 *
 *       Filename:  cmd_hier.c
 *
 *    Description:  This file defines the structure for maintaining cmd hierarchy
 *
 *        Version:  1.0
 *        Created:  Thursday 03 August 2017 02:12:46  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cmdtlv.h"
#include "libcli.h"
#include "clistd.h"
#include "string_util.h"
#include "css.h"
#include <signal.h>

leaf_type_handler leaf_handler_array[LEAF_MAX];
ser_buff_t *tlv_buff;
static param_t *cmd_tree_cursor = NULL;

/*Default zero level commands hooks. */
static param_t root;
static param_t do_hook;
static param_t show;
static param_t debug;
static param_t debug_show;
static param_t config;
static param_t clear;
static param_t run;
static param_t repeat;
static param_t show_brief_extension;

/* Default param Capabilities*/

static param_t mode_param;
static param_t suboptions_param;
static param_t cmd_expansion_param;

param_t *
libcli_get_mode_param(){
    return &mode_param;
}


param_t *
libcli_get_suboptions_param(){
    return &suboptions_param;
}

param_t *
libcli_get_cmd_expansion_param(){
    return &cmd_expansion_param;
}

/* Function to be used to get access to above hooks*/

param_t *
libcli_get_root(void){
    return &root;
}

param_t *
libcli_get_do_hook(void){
    return &do_hook;
}

param_t *
libcli_get_show_hook(void){
    return &show;
}

param_t *
libcli_get_debug_hook(void){
    return &debug;
}

param_t *
libcli_get_debug_show_hook(void){
    return &debug_show;
}

param_t *
libcli_get_config_hook(void){
    return &config;
}

param_t *
libcli_get_clear_hook(void){
    return &clear;
}

param_t *
libcli_get_run_hook(void){
    return &run;
}

param_t *
libcli_get_repeat_hook(void){
    return &repeat;
}

param_t *
libcli_get_show_brief_extension_param(void){
    return &show_brief_extension;
}

void
enable_show_extension_param_brief(param_t *param){
    assert(IS_APPLICATION_CALLBACK_HANDLER_REGISTERED(param));
    libcli_register_param(param, libcli_get_show_brief_extension_param());
}
/* Cursor functions*/
void
reset_cmd_tree_cursor(){
    cmd_tree_cursor = &root;
    reset_serialize_buffer(tlv_buff);
}


void
set_cmd_tree_cursor(param_t *param){
    assert(param);
    cmd_tree_cursor = param;
}

param_t *
get_cmd_tree_cursor(){
    return cmd_tree_cursor;
}

int
is_user_in_cmd_mode(){
        return (get_cmd_tree_cursor() != &root);
}

extern char *
get_last_command();

extern char console_name[TERMINAL_NAME_SIZE];

extern CMD_PARSE_STATUS
parse_input_cmd(char *input, unsigned int len);

extern void
place_console(char new_line);

void
libcli_register_display_callback(param_t *param, 
                                display_possible_values_callback disp_callback){

    if(IS_PARAM_NO_CMD(param))
        assert(0);
    param->disp_callback = disp_callback;
}


char*
get_str_leaf_type(leaf_type_t leaf_type){

    switch(leaf_type){
        case INT:
            return "INT";
        case STRING:
            return "STRING";
        case IPV4:
            return "IPV4";
        case FLOAT:
            return "FLOAT";
        case IPV6:
            return "IPV6";
        case BOOLEAN:
            return "BOOLEAN";
        case LEAF_MAX:
            return "LEAF_MAX";
        default:
            return "Unknown";
    }
    return NULL;
}


static void
ctrlC_signal_handler(int sig){
    printf("Ctrl-C pressed\n");
    printf("Bye Bye\n");
    exit(0);
}

show_ext_t
get_show_extension_type(ser_buff_t *b){
    
    assert(b);
    unsigned int tlv_units = get_serialize_buffer_size(b)/sizeof(tlv_struct_t);
    tlv_struct_t *show_ext_tlv = NULL;

    if(tlv_units == 0)
        return none;

    if(tlv_units == 1){
        show_ext_tlv = (tlv_struct_t *)(b->b);
    }
    else{
        show_ext_tlv = (tlv_struct_t *)(b->b) + (tlv_units -2);
    }
    assert(show_ext_tlv);

    if(strncmp(show_ext_tlv->leaf_id, SHOW_EXTENSION_PARAM, strlen(SHOW_EXTENSION_PARAM)))
        return none;
    if(strncmp(show_ext_tlv->value, SHOW_EXTENSION_PARAM_BRIEF, strlen(SHOW_EXTENSION_PARAM_BRIEF)) == 0)
        return brief;
    if(strncmp(show_ext_tlv->value, SHOW_EXTENSION_PARAM_DETAIL, strlen(SHOW_EXTENSION_PARAM_DETAIL)) == 0)
        return detail;
    if(strncmp(show_ext_tlv->value, SHOW_EXTENSION_PARAM_EXTENSIVE, strlen(SHOW_EXTENSION_PARAM_EXTENSIVE)) == 0)
        return extensive;
    assert(0);
    return none;
}

void 
init_libcli(){

    init_param(&root, CMD, "ROOT", 0, 0, INVALID, 0, "ROOT");
    
    /*Intialised serialized buffer to collect leaf values in TLV format*/
    init_serialized_buffer_of_defined_size(&tlv_buff, TLV_MAX_BUFFER_SIZE);
    //init_serialized_buffer_of_defined_size(&file_read_buffer, TLV_MAX_BUFFER_SIZE);

    reset_cmd_tree_cursor();

    /*Leaf datatypes standard Validation callbacks registration*/
    leaf_handler_array[INT]     = int_validation_handler;
    leaf_handler_array[STRING]  = string_validation_handler;
    leaf_handler_array[IPV4]    = ipv4_validation_handler;
    leaf_handler_array[IPV6]    = ipv6_validation_handler;
    leaf_handler_array[FLOAT]   = float_validation_handler;
    leaf_handler_array[BOOLEAN] = boolean_validation_handler;

    set_device_name(DEFAULT_DEVICE_NAME);
   
    /*Initialize the token array*/
    init_token_array();
     
    /*Initialise Capablities Params*/
    init_param(&mode_param, CMD, MODE_CHARACTER, mode_enter_callback , 0, INVALID, 0, "ENTER MODE");
    init_param(&suboptions_param, CMD, SUBOPTIONS_CHARACTER, display_sub_options_callback, 0, INVALID, 0, "Sub-Options");
    init_param(&cmd_expansion_param, CMD, CMD_EXPANSION_CHARACTER, display_cmd_expansion_callback, 0, INVALID, 0, "All possible Command expansions"); 

    /*Registering Zero level default command hooks*/
    /*Show hook*/
    init_param(&show, CMD, "show", 0, 0, INVALID, 0, "show cmds");
    libcli_register_param(&root, &show);

    static param_t help;
    init_param(&help, CMD, "help", show_help_handler, 0, INVALID, 0, "help how to use this CLI");
    libcli_register_param(&show, &help);
    set_param_cmd_code(&help, SHOW_HELP);

    /*show history*/
    static param_t show_history;
    init_param(&show_history, CMD, "history", show_history_callback, 0, INVALID, 0, "Command history");
    libcli_register_param(&show, &show_history);
    set_param_cmd_code(&show_history, SHOW_HISTORY);

    static param_t no_of_commands;
    init_param(&no_of_commands, LEAF, "N", show_history_callback, 0, INT, "N", "No Of Commands to fetch");  
    libcli_register_param(&show_history, &no_of_commands);
    set_param_cmd_code(&no_of_commands, SHOW_HISTORY_N);

    /*show registered commands*/
    static param_t show_resgistered;
    init_param(&show_resgistered, CMD, "registered", 0, 0, INVALID, 0, "registered");
    libcli_register_param(&show, &show_resgistered);

    static param_t show_resgistered_cmds;
    init_param(&show_resgistered_cmds, CMD, "commands", show_resgistered_cmd_handler, 0, INVALID, 0, "commands");
    libcli_register_param(&show_resgistered, &show_resgistered_cmds); 
    set_param_cmd_code(&show_resgistered_cmds, SHOW_REGISTERED_COMMANDS);

    /*debug hook*/
    init_param(&debug, CMD, "debug", 0, 0, INVALID, 0, "debug cmds");
    libcli_register_param(&root, &debug);

    /*debug show cmdtree*/

    init_param(&debug_show, CMD, "show", 0, 0, INVALID, 0, "debug show commands");
    libcli_register_param(&debug, &debug_show);

    static param_t debug_show_cmdtree;
    init_param(&debug_show_cmdtree, CMD, "cmdtree", show_cmd_tree, 0, INVALID, 0, "Display command tree");
    libcli_register_param(&debug_show, &debug_show_cmdtree);
    set_param_cmd_code(&debug_show_cmdtree, DEBUG_SHOW_CMDTREE);

    /*configure hook*/
    init_param(&config, CMD, "config", config_mode_enter_handler, 0, INVALID, 0, "config cmds");
    libcli_register_param(&root, &config);

    static param_t supportsave;
    init_param(&supportsave, CMD, "supportsave", 0 , 0, INVALID, 0, "Collect Support Save Data");
    libcli_register_param(&config, &supportsave);

    static param_t supportsave_enable;
    init_param(&supportsave_enable, CMD, "enable", supportsave_handler , 0, INVALID, 0, "enable/disable Support Save Data Collection");
    libcli_register_param(&supportsave, &supportsave_enable);
    set_param_cmd_code(&supportsave_enable, CONFIG_SUPPORTSAVE_ENABLE);

    /*clear hook*/
    init_param(&clear, CMD, "clear", 0, 0, INVALID, 0, "clear cmds");
    libcli_register_param(&root, &clear);

    /*run hook*/
    init_param(&run, CMD, "run", 0, 0, INVALID, 0, "run cmds");
    libcli_register_param(&root, &run);

    /*Hook up the show/debug/clear operational command in Do Hook*/
    init_param(&do_hook, CMD, "DO_HOOK", 0, 0, INVALID, 0, "operational commands shortcut");
    do_hook.options[MODE_PARAM_INDEX] = libcli_get_suboptions_param(); // A hack, just fill it 
    do_hook.options[SUBOPTIONS_INDEX] = libcli_get_suboptions_param();
    do_hook.options[CMD_EXPANSION_INDEX] = libcli_get_cmd_expansion_param(); 
    do_hook.options[CHILDREN_START_INDEX] = &show;
    do_hook.options[CHILDREN_START_INDEX+1] = &debug;
    do_hook.options[CHILDREN_START_INDEX+2] = &clear; 
    
    /*configure repeat*/
    init_param(&repeat, CMD, "repeat", repeat_last_command, 0, INVALID, 0, "repeat");
    libcli_register_param(&root, &repeat);
    
    /*config console name <new name>*/
    static param_t config_console;
    init_param(&config_console, CMD, "console", 0, 0, INVALID, 0, "console");
    libcli_register_param(&config, &config_console);

    
    static param_t config_console_name;
    init_param(&config_console_name, CMD, "name", 0, 0, INVALID, 0, "name");
    libcli_register_param(&config_console, &config_console_name);

    static param_t config_console_name_name;
    init_param(&config_console_name_name, LEAF, 0, config_console_name_handler, 0, STRING, "cons-name", "Name of Console"); 
    libcli_register_param(&config_console_name, &config_console_name_name);
    set_param_cmd_code(&config_console_name_name, CONFIG_CONSOLEN_NAME_NAME);

    /* Install clear command "cls"*/
    static param_t cls;
    init_param(&cls, CMD, CLEAR_SCR_STRING, clear_screen_handler, 0, INVALID, 0, "clear screen");
    HIDE_PARAM(&cls);
    libcli_register_param(0, &cls);

    static param_t exit_cmd;
    init_param(&exit_cmd, CMD, GOTO_ONE_LVL_UP_STRING, exit_cmd_handler, 0, INVALID, 0, "Move One Level Up");
    HIDE_PARAM(&exit_cmd);
    libcli_register_param(0, &exit_cmd);

    static param_t end_cmd;
    init_param(&end_cmd, CMD, GOTO_TOP_STRING, end_cmd_handler, 0, INVALID, 0, "Goto Top level");
    HIDE_PARAM(&end_cmd);
    libcli_register_param(0, &end_cmd);

    /*initialise show extension params*/
    init_param(&show_brief_extension, CMD, "brief", show_extension_param_handler, 0, INVALID, 0, "brief output");
    /*Command Negation API Should be called by application and not by infra
     * else application would not be allowed to add more children into config 
     * param*/
    //support_cmd_negation(&config);
    
    /* Resgister CTRL-C signal handler*/
    signal(SIGINT, ctrlC_signal_handler);
}

void
init_param(param_t *param,                               /* pointer to static param_t variable*/
        param_type_t param_type,                         /* CMD|LEAF*/
        char *cmd_name,                                  /* <command name> | NULL*/
        cmd_callback callback,                           /* Callback field*/
        user_validation_callback user_validation_cb_fn,  /* NULL | <callback ptr>*/
        leaf_type_t leaf_type,                           /* INVALID | leaf type*/
        char *leaf_id,                                   /* NULL, <STRING>*/
        char *help){                                     /* Help String*/

    int i = 0;
    if(param_type == CMD){
        GET_PARAM_CMD(param) = calloc(1, sizeof(cmd_t));
        param->param_type = CMD;
        strncpy(GET_CMD_NAME(param), cmd_name, MIN(CMD_NAME_SIZE, strlen(cmd_name)));
        GET_CMD_NAME(param)[CMD_NAME_SIZE -1] = '\0';
    }
    else if(param_type == LEAF){
        GET_PARAM_LEAF(param) = calloc(1, sizeof(leaf_t));
        param->param_type = LEAF;
        GET_PARAM_LEAF(param)->leaf_type = leaf_type;
        param->cmd_type.leaf->user_validation_cb_fn = user_validation_cb_fn;
        strncpy(GET_LEAF_ID(param), leaf_id, MIN(LEAF_ID_SIZE, strlen(leaf_id)));
        GET_LEAF_ID(param)[LEAF_ID_SIZE -1] = '\0';
    }
    else if(param_type == NO_CMD){
        GET_PARAM_CMD(param) = calloc(1, sizeof(cmd_t));
        param->param_type = NO_CMD;
        strncpy(GET_CMD_NAME(param), NEGATE_CHARACTER, strlen(NEGATE_CHARACTER));
        GET_CMD_NAME(param)[CMD_NAME_SIZE -1] = '\0';
    }

    param->ishidden = 0;
    param->parent = NULL;
    param->callback = callback;
    strncpy(GET_PARAM_HELP_STRING(param), help, MIN(PARAM_HELP_STRING_SIZE, strlen(help)));
    GET_PARAM_HELP_STRING(param)[PARAM_HELP_STRING_SIZE -1] = '\0';
    param->disp_callback = NULL;

    for(; i < MAX_OPTION_SIZE; i++){
        param->options[i] = NULL;
    }

    param->CMDCODE = -1;
}

void
set_param_cmd_code(param_t *param, int cmd_code){

    if(param->callback == NULL)
        assert(0);
    param->CMDCODE = cmd_code;
}

void
support_cmd_negation(param_t *param){
    
    int i = 0;
    assert(param);
    assert(get_current_branch_hook(param) == libcli_get_config_hook());

    param_t *negate_param = find_matching_param(&param->options[0], NEGATE_CHARACTER);

    if(negate_param && IS_PARAM_NO_CMD(negate_param)){
        printf("Error : Attempt to add Duplicate Negate param in cmd : %s\n", GET_CMD_NAME(param));
        return;
    }

    param_t *no_param = calloc(1, sizeof(param_t));
    init_param(no_param, NO_CMD, NEGATE_CHARACTER, negate_callback, 0, INVALID, 0, "Command Negation");
   
    /*We cant leave the MODE_PARAM_INDEX empty, 
     * so a hack - fill it with suboptions param. I dont see any implication of this.
     * We dont support MODE with negate cmd*/ 

    no_param->options[MODE_PARAM_INDEX] = libcli_get_suboptions_param();//libcli_get_mode_param();
    no_param->options[SUBOPTIONS_INDEX] = libcli_get_suboptions_param();
    no_param->options[CMD_EXPANSION_INDEX] = libcli_get_cmd_expansion_param();
     
    for(i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++){
        if(param->options[i]){
            no_param->options[i] = param->options[i];
            continue;
        }
        break;
    }

    assert(i <= CHILDREN_END_INDEX);
    param->options[i] = no_param;
    no_param->parent = param;
    return;
}


void
set_device_name(const char *cons_name){
    
    char** tokens = NULL;
    size_t token_cnt = 0;    

    assert(cons_name);

    if(strlen(console_name))
        tokens = tokenizer(console_name, '>', &token_cnt);
    
    sprintf(console_name, "%s>", cons_name);
    
    if(token_cnt > 1){
        strcat(console_name, " ");
        string_space_trim(tokens[1]);
        strcat(console_name, tokens[1]);
    }
}


void
libcli_register_param(param_t *parent, param_t *child){
    
    int i = 0;
    if(!parent)
        parent = &root;
        
    if(!IS_PARAM_MODE_ENABLE(parent)){
        parent->options[MODE_PARAM_INDEX] = libcli_get_mode_param();
    }

    if(!IS_PARAM_SUBOPTIONS_ENABLE(parent)){
        parent->options[SUBOPTIONS_INDEX] = libcli_get_suboptions_param();
    }

    if(parent->options[CMD_EXPANSION_INDEX] == NULL)
        parent->options[CMD_EXPANSION_INDEX] = libcli_get_cmd_expansion_param();

    for(i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++){
        if(parent->options[i])
            continue;
        
        parent->options[i] = child;
        if(child != libcli_get_show_brief_extension_param())
            child->parent = parent;
        child->parent = parent;
        return;
    }

    printf("%s() : Error : No space for new command\n", __FUNCTION__);
    assert(0);
}

static void
_dump_one_cmd(param_t *param, unsigned short tabs){

    int i = 0;

    PRINT_TABS(tabs);

    if(IS_PARAM_CMD(param) || IS_PARAM_NO_CMD(param))
        printf("-->%s(%d)", GET_CMD_NAME(param), tabs);
    else
        printf("-->%s(%d)", GET_LEAF_TYPE_STR(param), tabs);

    for(; i < MAX_OPTION_SIZE; i++){
        if(param->options[i]){
            printf("\n");
            _dump_one_cmd(param->options[i], ++tabs);
            --tabs;
        }
        else
            break;
    }
}

void
dump_cmd_tree(){
    _dump_one_cmd(&root, 0);
}

extern 
void command_parser(void);

extern 
void  enhanced_command_parser(void);

void
start_shell(void){
    command_parser();
}

/* Command Mode implementation */

param_t*
get_current_branch_hook(param_t *current_param){
    assert(current_param);
    assert(current_param != &root);
    while(current_param->parent != &root){
        current_param = current_param->parent;
    }
    return current_param;;
}


/*-----------------------------------------------------------------------------
 *  This fn resets the current cmd tree cursor to root and flush the leaf value 
 *  present in the branch of tree from root to curr_cmd_tree_cursor
 *-----------------------------------------------------------------------------*/
void
goto_top_of_cmd_tree(param_t *curr_cmd_tree_cursor){

    char** tokens = NULL;
    size_t token_cnt = 0;

    assert(curr_cmd_tree_cursor);
    
    if(curr_cmd_tree_cursor == &root){
        printf(ANSI_COLOR_BLUE "Info : At Roof top Already\n" ANSI_COLOR_RESET);
        return;
    }

    do{
        if(IS_PARAM_CMD(curr_cmd_tree_cursor)){
            curr_cmd_tree_cursor = curr_cmd_tree_cursor->parent;
            continue;
        }
        memset(GET_LEAF_VALUE_PTR(curr_cmd_tree_cursor), 0, LEAF_VALUE_HOLDER_SIZE);
        curr_cmd_tree_cursor = curr_cmd_tree_cursor->parent;
    } while(curr_cmd_tree_cursor != &root);
    
    reset_cmd_tree_cursor();
    tokens = tokenizer(console_name, '>', &token_cnt);
    sprintf(console_name, "%s>", tokens[0]);
}

void
go_one_level_up_cmd_tree(param_t *curr_cmd_tree_cursor){

    char** tokens = NULL;
    size_t token_cnt = 0;

    assert(curr_cmd_tree_cursor);

    if(curr_cmd_tree_cursor == &root){
        printf(ANSI_COLOR_BLUE "Info : At Roof top Already\n" ANSI_COLOR_RESET);
        return;
    }

    if(IS_PARAM_LEAF(curr_cmd_tree_cursor)){
        memset(GET_LEAF_VALUE_PTR(curr_cmd_tree_cursor), 0, LEAF_VALUE_HOLDER_SIZE);
        serialize_buffer_skip(tlv_buff, -1 * (int)sizeof(tlv_struct_t));/*Rewind*/
        mark_checkpoint_serialize_buffer(tlv_buff);
    }

     set_cmd_tree_cursor(curr_cmd_tree_cursor->parent);

     if(get_cmd_tree_cursor() == &root){
        tokens = tokenizer(console_name, '>', &token_cnt);
        sprintf(console_name, "%s>", tokens[0]);
        reset_serialize_buffer(tlv_buff);
        return;
     }
    
     build_mode_console_name(get_cmd_tree_cursor());
}


/*-----------------------------------------------------------------------------
 *  Build new console name when entered into MODE from root to dst_parm(incl)
 *-----------------------------------------------------------------------------*/
void
build_mode_console_name(param_t *dst_param){

    assert(dst_param);
    assert(dst_param != &root);/*This fn should not be called for root*/

    int i = MAX_CMD_TREE_DEPTH -1;
    size_t token_cnt = 0;
    
    char** tokens = NULL;
    char *append_string = NULL;

    static char cmd_names[MAX_CMD_TREE_DEPTH][LEAF_VALUE_HOLDER_SIZE];
    char *admin_set_console_name = NULL;

    tokens = tokenizer(console_name, '>', &token_cnt);
    admin_set_console_name = tokens[0];
    sprintf(console_name, "%s> ", admin_set_console_name);
    
    do{
        assert(i != -1); 
        if(IS_PARAM_CMD(dst_param))
            append_string = GET_CMD_NAME(dst_param);
        else
            append_string = GET_LEAF_VALUE_PTR(dst_param);

        strncpy(cmd_names[i], append_string, strlen(append_string));
        i--;
        dst_param = dst_param->parent;
    }while(dst_param != &root);

    for(i = i+1; i < MAX_CMD_TREE_DEPTH -1; i++){
        strcat(console_name, cmd_names[i]);
        strcat(console_name, "-");
    }

    strcat(console_name, cmd_names[i]);
    memset(cmd_names, 0, MAX_CMD_TREE_DEPTH * LEAF_VALUE_HOLDER_SIZE);
}

/*Source and Destination command MUST be in the same branch AND
 *  * Source must be at higher level as compared to Destination*/
void
build_cmd_tree_leaves_data(ser_buff_t *tlv_buff,/*Output serialize buffer*/
        param_t *src_param, /*Source command*/
        param_t *dst_param){/*Destination command*/

    assert(tlv_buff);
    assert(src_param);
    assert(dst_param);

    tlv_struct_t tlv, *tlv_temp = NULL;
    unsigned int tlv_units = 0, i = 0, j = 0;

    memset(&tlv, 0, sizeof(tlv_struct_t));
    reset_serialize_buffer(tlv_buff);

    while(dst_param != src_param){
        if(IS_PARAM_CMD(dst_param)){
            dst_param = dst_param->parent;
            continue;
        }

        prepare_tlv_from_leaf(GET_PARAM_LEAF(dst_param), (&tlv));
        put_value_in_tlv((&tlv), GET_LEAF_VALUE_PTR(dst_param)); 
        collect_tlv(tlv_buff, &tlv);
        memset(&tlv, 0, sizeof(tlv_struct_t));

        dst_param = dst_param->parent;
    }

    if(IS_PARAM_LEAF(dst_param)){
        prepare_tlv_from_leaf(GET_PARAM_LEAF(dst_param), (&tlv));
        put_value_in_tlv((&tlv), GET_LEAF_VALUE_PTR(dst_param)); 
        collect_tlv(tlv_buff, &tlv);
    }

    /*Now reverse the TLV buffer*/
    if(get_serialize_buffer_size(tlv_buff) < (sizeof(tlv_struct_t) << 1)){
        return;
    }

    tlv_units = get_serialize_buffer_size(tlv_buff)/sizeof(tlv_struct_t);
    tlv_temp = (tlv_struct_t *)(tlv_buff->b);
    j = tlv_units -1;

    for(; i < (tlv_units >> 1); i++, j--){
        swap_tlv_units(tlv_temp+i, tlv_temp +j);
    }
}
