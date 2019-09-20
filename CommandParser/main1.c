#include "CommandParser/cmdtlv.h"
#include "CommandParser/libcli.h"


int
main(int argc, char **argv){

    init_libcli();
    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *clear  = libcli_get_clear_hook();
    param_t *run    = libcli_get_run_hook();


    support_cmd_negation(config);
    /*Do not add any param in config command tree after above line*/
    start_shell();
    return 0;
}
