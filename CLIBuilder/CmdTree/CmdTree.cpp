#include <stddef.h>
#include <stdint.h>
#include <ncurses.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "CmdTree.h"
#include "CmdTreeCursor.h"
#include "../string_util.h"
#include "cmdcodes_def.h"
#include "clistd.h"
#include "../cmdtlv.h"

extern int
ut_test_handler (int cmdcode,
                            Stack_t *tlv_stack,
                            op_mode enable_or_disable) ;

/*Default zero level commands hooks. */
static param_t root;
static param_t show;
static param_t debug;
static param_t config;
static param_t clearp;
static param_t run;

/* Working with Filters */
static param_t pipe;
static param_t count;
static param_t save;
static param_t save_file;
static param_t include;
static param_t include_leaf;
static param_t exclude;
static param_t exclude_leaf;
static param_t grepx;
static param_t grepx_leaf;
static param_t refreshx;
static param_t refresh_val;
static param_t clrscr;


static param_t *universal_params[] = {&show, &config};

void
init_param(param_t *param,    
           param_type_t param_type,    
           const char *cmd_name,    
           cmd_callback callback,
           user_validation_callback user_validation_cb_fn,
           leaf_type_t leaf_type,
           const char *leaf_id,
           const char *help);

void 
libcli_register_param(param_t *parent, param_t *child);

void 
libcli_set_param_cmd_code(param_t *param, int cmd_code) ;

void
libcli_support_cmd_negation (param_t *param);

void 
libcli_set_tail_config_one_shot (param_t *param);

void
init_param(param_t *param,    
           param_type_t param_type,    
           const char *cmd_name,    
           cmd_callback callback,
           user_validation_callback user_validation_cb_fn,
           leaf_type_t leaf_type,
           const char *leaf_id,
           const char *help) {

    int i = 0;
    if (param_type == CMD)
    {   
        GET_PARAM_CMD(param) = (cmd_t *)calloc(1, sizeof(cmd_t));
        param->param_type = CMD;
        strncpy((char *)GET_CMD_NAME(param), cmd_name, MIN(CMD_NAME_SIZE, strlen(cmd_name)));
        GET_CMD_NAME(param)[CMD_NAME_SIZE - 1] = '\0';
        GET_PARAM_CMD(param)->len = strlen (GET_CMD_NAME(param));
    }
    else if (param_type == LEAF)
    {
        GET_PARAM_LEAF(param) = (leaf_t *)calloc(1, sizeof(leaf_t));
        param->param_type = LEAF;
        GET_PARAM_LEAF(param)->leaf_type = leaf_type;
        param->cmd_type.leaf->user_validation_cb_fn = user_validation_cb_fn;
        strncpy((char *)GET_LEAF_ID(param), leaf_id, MIN(LEAF_ID_SIZE, strlen(leaf_id)));
        GET_LEAF_ID(param)[LEAF_ID_SIZE - 1] = '\0';
    }
    else if (param_type == NO_CMD)
    {   
        GET_PARAM_CMD(param) = (cmd_t *)calloc(1, sizeof(cmd_t));
        param->param_type = NO_CMD;
        strncpy((char *)GET_CMD_NAME(param), NEGATE_CHARACTER, strlen(NEGATE_CHARACTER));
        GET_CMD_NAME(param)[CMD_NAME_SIZE - 1] = '\0';
        GET_PARAM_CMD(param)->len = strlen (GET_CMD_NAME(param));
    }

    param->callback = callback;

    strncpy(GET_PARAM_HELP_STRING(param), help, MIN(PARAM_HELP_STRING_SIZE, strlen(help)));
    GET_PARAM_HELP_STRING(param)[PARAM_HELP_STRING_SIZE - 1] = '\0';
    param->disp_callback = NULL;

    for (; i < MAX_OPTION_SIZE; i++) {   
        param->options[i] = NULL;
    }

    param->CMDCODE = -1;
    init_glthread (&param->glue);
}

void 
libcli_register_param(param_t *parent, param_t *child) {

    int i = 0;

    if (!parent) parent = libcli_get_root_hook();

    /* You cannot add a LEAF param as child of Recursive param because Recursive
        param itself is its own child, Wierd but true*/
    if ( (parent != child) && 
            parent->flags & PARAM_F_RECURSIVE) {
        assert (!IS_PARAM_LEAF (child));
    }

    for (i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++) {
        if (parent->options[i])
            continue;
        parent->options[i] = child;
        child->parent = parent;
        return;
    }   
    assert(0);
}

void 
libcli_set_param_cmd_code(param_t *param, int cmd_code) {

    if (param->callback == NULL)
        assert(0);
    param->CMDCODE = cmd_code;
}

void 
libcli_param_recursive (param_t *param) {

    assert (IS_PARAM_LEAF (param));
    param_t *parent = param->parent;
    libcli_register_param (param, param);
    param->parent = parent;
    param->flags |= PARAM_F_RECURSIVE;
}

void 
libcli_set_tail_config_batch_processing (param_t *param) {

    param_t *origp = param;

    while ( param != libcli_get_config_hook () ) {

            if (param->flags & PARAM_F_CONFIG_BATCH_CMD) break;
            
            if (param->callback ) {
                param->flags |= PARAM_F_CONFIG_BATCH_CMD;
            }
            
            param = param->parent;
    }

    /* This is required while copy-pasting the param sub-trees across branches in
        config tree*/
    if (!origp->callback) {
        param->flags &= ~PARAM_F_CONFIG_BATCH_CMD;
    }
}

static void 
 libcli_build_default_cmdtree() {

    param_t *root_hook = libcli_get_root_hook();
    init_param(root_hook, CMD, "ROOT", 0, 0, INVALID, 0, "ROOT");

    param_t *chook = libcli_get_show_hook();
    init_param(chook, CMD, "show", 0, 0, INVALID, 0, "show cmds");
    libcli_register_param (root_hook, chook);

    chook = libcli_get_config_hook();
    init_param(chook, CMD, "config", NULL, 0, INVALID, 0, "config cmds");
    libcli_register_param (root_hook, chook);
   
    chook = libcli_get_debug_hook();
    init_param(chook, CMD, "debug", 0, 0, INVALID, 0, "debug cmds");
    libcli_register_param (root_hook, chook);

    chook = libcli_get_clear_hook();
    init_param(chook, CMD, "clear", 0, 0, INVALID, 0, "clear cmds");
    libcli_register_param (root_hook, chook);

    chook = libcli_get_run_hook();
    init_param(chook, CMD, "run", 0, 0, INVALID, 0, "run cmds");
    libcli_register_param (root_hook, chook);

    param_t *hook = libcli_get_config_hook();

    {
         /* config host-name <name>*/
         /* config host-name ...*/
        static param_t hostname;
        init_param (&hostname, CMD, "host-name", NULL, NULL, INVALID, NULL, "host-name");
        libcli_register_param (hook, &hostname);
        {
            /* config host-name <name> */
            static param_t name;
            init_param(&name, LEAF, NULL, clistd_config_device_default_handler, NULL, STRING, "host-name", "Host Name");
            libcli_register_param(&hostname, &name);
            libcli_set_param_cmd_code(&name, CONFIG_DEVICE_HOSTNAME);
        }
    }

    hook = libcli_get_show_hook();

    {
        /*show help*/
        static param_t help;
        init_param (&help, CMD, "help", show_help_handler, NULL, INVALID, NULL, "KYC (Know Your CLI)");
        libcli_register_param(hook, &help);
        libcli_set_param_cmd_code(&help, SHOW_CLI_HELP);
    }
    {
        /*show history*/
        static param_t history;
        init_param (&history, CMD, "history", show_history_handler, NULL, INVALID, NULL, "CLI history");
        libcli_register_param(hook, &history);
        libcli_set_param_cmd_code(&history, SHOW_CLI_HISTORY);        
    }

    hook = libcli_get_run_hook();

    {   
        /* run ut <file path> <tc no> */
        static param_t ut; 
        init_param(&ut, CMD, "ut", 0, 0, INVALID, 0, "Unit Test");
        libcli_register_param(hook, &ut);
        {   
            static param_t ut_file_path;
            init_param(&ut_file_path, LEAF, 0, 0, 0, STRING, "ut-file-name", "UT file name");
            libcli_register_param(&ut, &ut_file_path);
            {   
                static param_t tc_no;
                init_param(&tc_no, LEAF, 0, ut_test_handler, 0, INT, "tc-no", "Test Case Number");
                libcli_register_param(&ut_file_path, &tc_no);
                libcli_set_param_cmd_code(&tc_no, CMDCODE_RUN_UT_TC);
            }   
        }   
    }

    {
        /* run terminate*/
        static param_t terminate;
        init_param(&terminate, CMD, "term", cli_terminate_handler, 0, INVALID, 0, "Terminate appln");
        libcli_register_param(&run, &terminate);
    }

    hook = libcli_get_debug_hook();

    {
        static param_t ut;
        init_param(&ut, CMD, "ut", 0, 0, INVALID, 0, "debug ut");
        libcli_register_param(&debug, &ut);
        {
            static param_t enable;
            init_param(&enable, LEAF, 0, ut_test_handler, NULL,  STRING, "ut-enable", "enable | disable");
            libcli_register_param(&ut, &enable);
            libcli_set_param_cmd_code(&enable, CMDCODE_DEBUG_UT);
        }
    }
 }


/* Function to be used to get access to above hooks*/

param_t *
libcli_get_root_hook(void)
{
    return &root;
}

param_t *
libcli_get_show_hook(void)
{
    return &show;
}

param_t *
libcli_get_debug_hook(void)
{
    return &debug;
}

param_t *
libcli_get_config_hook(void)
{
    return &config;
}

param_t *
libcli_get_clear_hook(void)
{
    return &clearp;
}

param_t *
libcli_get_run_hook(void)
{
    return &run;
}

param_t *
libcli_get_refresh_hook(void)
{
    return &refreshx;
}

param_t *
libcli_get_refresh_val_hook(void)
{
    return &refresh_val;
}

param_t *
libcli_get_clrscr_hook(void)
{
    return &clrscr;
}

bool
cmd_tree_leaf_char_save (unsigned char *curr_leaf_value, unsigned char c, int index) {

    if (index == LEAF_VALUE_HOLDER_SIZE) return false;
    curr_leaf_value[index] = c;
    return true;
}

tlv_struct_t *
cmd_tree_convert_param_to_tlv (param_t *param, unsigned char *curr_leaf_value) {

     tlv_struct_t *tlv = (tlv_struct_t *)calloc (1, sizeof (tlv_struct_t));

    if (IS_PARAM_CMD (param)) {
        
        tlv->tlv_type = TLV_TYPE_CMD_NAME;
        tlv->leaf_type = STRING;
        put_value_in_tlv((tlv), GET_CMD_NAME(param));
    }
    else if (IS_PARAM_NO_CMD (param)) {
        
        tlv->tlv_type = TLV_TYPE_NEGATE;
        tlv->leaf_type = STRING;
        put_value_in_tlv((tlv), GET_CMD_NAME(param));
    }
    else {
        
        tlv->tlv_type = TLV_TYPE_NORMAL;
        prepare_tlv_from_leaf(GET_PARAM_LEAF(param), (tlv));
        put_value_in_tlv((tlv), (const char *)curr_leaf_value);
    }
    return tlv;
}

static unsigned char temp[ LEAF_ID_SIZE + 2]; // 2 for < > 
void
cmd_tree_display_all_complete_commands(
                param_t *root, unsigned int index) {

        if (!root)
            return;

        if (root->flags & PARAM_F_NO_EXPAND) return;
        
        if (IS_PARAM_CMD(root)){
            untokenize(index);
            tokenize(GET_CMD_NAME(root), GET_PARAM_CMD(root)->len, index);
        }

        else if (IS_PARAM_LEAF(root)){
            untokenize(index);
            memset(temp, 0, sizeof(temp));
            sprintf((char *)temp, "<%s>", GET_LEAF_ID(root));
            tokenize((char *)temp, strlen(GET_LEAF_ID(root)) + 2, index);
        }   

        unsigned int i = CHILDREN_START_INDEX;

        for ( ; i <= CHILDREN_END_INDEX; i++) {
            if (root->options[i] && (root->options[i]->flags & PARAM_F_RECURSIVE)) continue;
            cmd_tree_display_all_complete_commands(
                    root->options[i], index+1);
        }
    
        if (root->callback){
            print_tokens(index + 1); 
            printw("\n");
        }   
}

void 
cmd_tree_install_universal_params (param_t *param, param_t *branch_hook) {

    int i = 0, j = 0;
    int k = sizeof (universal_params) / sizeof(universal_params[0]);
    
    while (true) {

        /* If it assers here, it means you have run out of space, consider increase
            the value of MAX_OPTION_SIZE */
        if (i > CHILDREN_END_INDEX) assert(0);

        if (param->options[i]) {
            i++;
            continue;
        }

        if (universal_params[j] == branch_hook) j++;
        if (j == k) return;
        param->options[i++] = universal_params[j++]; 
        param->options[i - 1]->flags |= PARAM_F_NO_EXPAND; 
        if (j == k) return;
    }
}

void 
cmd_tree_uninstall_universal_params (param_t *param) {

    int i, j;
    int k = sizeof (universal_params) / sizeof(universal_params[0]);

    for (i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++) {
        if (!param->options[i]) continue;
        for ( j = 0; j < k; j++) {
            if (param->options[i] == universal_params[j]) {
                universal_params[j]->flags &= ~PARAM_F_NO_EXPAND;
                param->options[i] = NULL;
                break;
            }
        }
    }
}

bool 
param_is_hook (param_t *param) {

    return (    param == libcli_get_config_hook () ||
         param == libcli_get_clear_hook () ||
         param == libcli_get_show_hook () ||
         param == libcli_get_run_hook () ||
         param == libcli_get_debug_hook () );

}

bool 
cmd_tree_is_token_a_hook (char *token) {

    param_t *root = libcli_get_root_hook ();
    return (cmd_tree_find_matching_param (&root->options[0], token) != NULL); 
}

static param_t*
array_of_possibilities[POSSIBILITY_ARRAY_SIZE];

static inline int
is_cmd_string_match(param_t *param, const char *str, bool *ex_match){
    
    *ex_match = false;
    int str_len = strlen(str);
    int str_len_param = param->cmd_type.cmd->len;

    int rc =  (strncmp(param->cmd_type.cmd->cmd_name, 
                   str, str_len));

    if ( !rc && (str_len == str_len_param )) {
        *ex_match = true;
    }
    return rc;
}

param_t*
cmd_tree_find_matching_param (param_t **options, const char *cmd_name){
    
    int i = 0,
         j = 0,
        choice = -1,
        leaf_index = -1;
         
    bool ex_match = false;
    
    memset(array_of_possibilities, 0, POSSIBILITY_ARRAY_SIZE * sizeof(param_t *));

    for (; options[i] && i <= CHILDREN_END_INDEX; i++) {

        if (IS_PARAM_LEAF(options[i])) {
            leaf_index = i;
            continue;
        }

        if (is_cmd_string_match(options[i], cmd_name, &ex_match) == 0) {

            if (ex_match) {
                 array_of_possibilities[ 0 ] = options[i];
                 j = 1;
                break;
            }
            array_of_possibilities[ j++ ] = options[i];
            assert (j < POSSIBILITY_ARRAY_SIZE);
            continue;
        }
    }

    if(leaf_index >= 0 && j == 0)
        return options[leaf_index];

    if( j == 0)
        return NULL;

    if(j == 1)
        return array_of_possibilities[0];

    /* More than one param matched*/
    printw("%d possibilities :\n", j);
    for(i = 0; i < j; i++)
        printw("%-2d. %s\n", i, GET_CMD_NAME(array_of_possibilities[i]));

    printw("Choice [0-%d] : ? ", j-1);
    scanw("%d", &choice);
    
    if(choice < 0 || choice > (j-1)){
        printw("\nInvalid Choice");
        return NULL;
    }
    return array_of_possibilities[choice];   
}

void 
libcli_support_cmd_negation (param_t *param) {   

    int i = 0;
    assert(param);

    param_t *negate_param = cmd_tree_find_matching_param(
                            &param->options[0], NEGATE_CHARACTER);

    if (negate_param && IS_PARAM_NO_CMD(negate_param)) {

        printw ("Error : Attempt to add Duplicate Negate param in cmd : %s\n",
                        GET_CMD_NAME(param));
        assert(0);
    }

    negate_param = (param_t *)calloc (1, sizeof (param_t));
    init_param (negate_param , NO_CMD, NEGATE_CHARACTER, NULL, NULL, INVALID, NULL, "Cmd Negation");

    for (i = CHILDREN_START_INDEX; i <= CHILDREN_END_INDEX; i++) {

        if (param->options[i]) {
            negate_param->options[i] = param->options[i];
            continue;
        }
        break;
    }

    assert(i <= CHILDREN_END_INDEX);
    param->options[i] = negate_param;
    negate_param->flags = PARAM_F_NO_EXPAND;
}

static void 
libcli_cleanup_parent_pointers_internal (param_t *param) {

    int i;

    if (!param) return;
    if (param == &pipe) return;

    for (i = CHILDREN_START_INDEX ; i <= CHILDREN_END_INDEX; i++) {
        if (param->options[i] && (param->options[i]->flags & PARAM_F_RECURSIVE)) continue;
        libcli_cleanup_parent_pointers_internal (param->options[i]);
    }

    /* In our library design, param->parent is suppose to be null during normal
        opn*/
    param->parent = NULL;
}

static void 
libcli_cleanup_parent_pointers () {

    libcli_cleanup_parent_pointers_internal (libcli_get_root_hook());
}

static void
cmd_tree_construct_filter_subtree () {

    init_param (&pipe, CMD, "|", NULL, NULL, INVALID, NULL, "pipe");
    pipe.flags |= (PARAM_F_NO_EXPAND );
    init_param (&count, CMD, "count", NULL, NULL, INVALID, NULL, "count lines");
    init_param (&save, CMD, "save", NULL, NULL, INVALID, NULL, "save to a file");
    init_param (&save_file, LEAF, NULL, NULL, NULL, STRING, "sfile-name", "file name");

    {
        libcli_register_param (&save, &save_file);
    }
    {
        libcli_register_param (&pipe, &count);
    }
    {
        libcli_register_param (&pipe, &save);
    }
    {
        init_param (&include,  CMD, "include", NULL, NULL, INVALID, NULL, "Include Pattern");
        libcli_register_param (&pipe, &include);
        {
            init_param (&include_leaf,  LEAF, NULL, NULL, NULL, STRING, "incl-pattern", "Include Pattern");
            libcli_register_param (&include, &include_leaf);
            libcli_register_param (&include_leaf, &pipe);
        }
    }
    {
        init_param (&exclude,  CMD, "exclude", NULL, NULL, INVALID, NULL, "Exclude Pattern");
        libcli_register_param (&pipe, &exclude);
        {
            init_param (&exclude_leaf,  LEAF, NULL, NULL, NULL, STRING, "excl-pattern", "Exclude Pattern");
            libcli_register_param (&exclude, &exclude_leaf);
            libcli_register_param (&exclude_leaf, &pipe);
        }
    }
    {
        init_param(&grepx, CMD, "grep", NULL, NULL, INVALID, NULL, "grep RegEx Pattern");
        libcli_register_param(&pipe, &grepx);
        {
            init_param(&grepx_leaf, LEAF, NULL, NULL, NULL, STRING, "grep-pattern", "Grep Pattern");
            libcli_register_param(&grepx, &grepx_leaf);
            libcli_register_param(&grepx_leaf, &pipe);
        }
    }
    {
        init_param (&refreshx, CMD, "refresh", NULL, NULL, INVALID, NULL, "Refresh the command repeatedly");
        init_param (&refresh_val, LEAF, NULL, NULL, NULL, INT, "refresh-val", "Refresh Time Interval in Sec");
        libcli_register_param (&refreshx, &refresh_val);
        libcli_register_param (&pipe, &refreshx);
        libcli_register_param (&refresh_val, &pipe);
        {
             init_param (&clrscr, CMD, "cls", NULL, NULL, INVALID, NULL, "Clear the screen");
             libcli_register_param (&refresh_val, &clrscr);
        }
    }
}

static void 
libcli_augment_show_cmds_internal (param_t *param) {

    int i;
    if (!param) return;
    if (param->flags & PARAM_F_NO_EXPAND) return;
    if (param == &pipe) return;

    for (i = CHILDREN_START_INDEX ; i <= CHILDREN_END_INDEX; i++) {
        libcli_augment_show_cmds_internal (param->options[i]);
    }

    if (param->callback) {
        libcli_register_param (param, &pipe);
    }
}

static void 
 libcli_augment_show_cmds () {

    param_t *show_param = libcli_get_show_hook();
    libcli_augment_show_cmds_internal (show_param);
 }

 void 
cmd_tree_init () {

    init_token_array();
    libcli_build_default_cmdtree();
    cmd_tree_init_cursors () ;
}

void 
libcli_init_done () {

    cmd_tree_construct_filter_subtree();
    libcli_augment_show_cmds ();
    libcli_support_cmd_negation (libcli_get_config_hook());
    libcli_cleanup_parent_pointers ();
}

bool 
cmd_tree_is_param_pipe (param_t *param) {

    return param == &pipe;
}

bool 
cmd_tree_is_filter_param (param_t *param) {

    return (param == &pipe || param == &count || param == &save ||
                param == &save_file || param == &include || 
                param == &include_leaf || param == &exclude ||
                param == &exclude_leaf ||
                param == &grepx || param == &grepx_leaf);
}

void 
libcli_register_display_callback (param_t *param, display_possible_values_callback cbk) {

    param->disp_callback = cbk;
}

void 
libcli_param_match_regex (param_t *param, char *reg_ex) {

    assert (!cmd_tree_is_filter_param(param));
    assert (IS_PARAM_LEAF (param));
    assert (!(param->flags & PARAM_F_REG_EX_MATCH));
    param->flags |= PARAM_F_REG_EX_MATCH;
    strncpy (param->cmd_type.leaf->reg_ex, reg_ex, LEAF_REG_EX_MAX_LEN);
}