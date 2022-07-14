#include "CommandParser/cmdtlv.h"
#include "CommandParser/libcli.h"

#define CMDODE_SHOW_NODE 1
#define CMDODE_SHOW_NODE_LOOPBACK 2

int
node_callback_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
    printf("%s() is called ...\n", __FUNCTION__);
    return 0;
}

int
validate_node_name(char *value){

    printf("%s() is called with value = %s\n", __FUNCTION__, value);
    return VALIDATION_SUCCESS; /*else return VALIDATION_FAILED*/
}


int
node_loopback_callback_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
    printf("%s() is called ...\n", __FUNCTION__);
    return 0;
}

int
validate_loopback_address(char *value){

    printf("%s() is called with value = %s\n", __FUNCTION__, value);
    return VALIDATION_SUCCESS; /*else return VALIDATION_FAILED*/
}

int
main(int argc, char **argv){

    init_libcli();
    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *clear  = libcli_get_clear_hook();
    param_t *run    = libcli_get_run_hook();

    /*Implementing CMD1 : show node <node-name>*/
    {
        /*show node*/
        static param_t node;    /*Get the param_t variable, either a static memory or heap memory, not stack memory*/
        init_param(&node,       /*Address of the current param*/ 
                CMD,            /*CMD for command param, LEAF for leaf param*/
                "node",         /*Name of the param, this string is what is displayed in command line*/
                0,              /*callback : pointer to application function. Null in this case since 'show node' is not a complete command*/
                0,              /*Applicable only for LEAF params. Always NULL for CMD param*/
                INVALID,        /*Always INVALID for CMD params*/
                0,              /*Always NULL for CMD params*/
                "Help : node"); /*Help String*/

        libcli_register_param(show, &node); /*Add node param as suboption of show param*/

        {
            /*show node <node-name>*/
            static param_t node_name;   /*Get the param_t variable, either a static memory or heap memory, not stack memory*/
            init_param(&node_name,      /*Address of the current param*/
                      LEAF,             /*CMD for command param, LEAF for leaf param. Since it is a leaf param which takes node names, hence pass LEAF*/
                      0,                /*Always NULL for LEAF param*/
                      node_callback_handler, /*Since this is complete command, it should invoke application routine. Pass the pointer to that routine here.*/
                      validate_node_name,    /*Optional : can be NULL. This is also application specific routine, and perform validation test 
                                             to the value entered by the user for this leaf param. If validation pass, then only node_callback_handler routine is invoked*/
                      STRING,               /*leaf param value type. Node name is string, hence pass STRING*/
                      "node-name",          /*Applicable only for LEAF param. Give some name to leaf-params. It is this string that we will parse in application code to find the value passed by the user*/
                      "Help : Node name");  /*Help String*/
            libcli_register_param(&node, &node_name);   /*Add node_name leaf param as suboption of node param. Note that: show --> node --> node_name has been chained*/
            /*The below API should be called for param upto which the command is supposed to invoke application callback rouine. 
             * The CMDODE_SHOW_NODE code is sent to application using which we find which command was triggered, and accordingly what 
             * are expected leaf params we need to parse. More on this ater.*/
            set_param_cmd_code(&node_name, CMDODE_SHOW_NODE);

            /*Implementing CMD2*/

            {
                /*show node <node-name> loopback*/ 
                static param_t loopback;    /*Get the param_t variable, either a static memory or heap memory, not stack memory*/
                init_param(&loopback,       /*Address of the current param*/ 
                        CMD,            /*CMD for command param, LEAF for leaf param*/
                        "loopback",     /*Name of the param, this string is what is displayed in command line*/
                        0,              /*callback : pointer to application function. Null in this case since 'show node <node-name> loopback' is not a complete command*/
                        0,              /*Applicable only for LEAF params. Always NULL for CMD param*/
                        INVALID,        /*Always INVALID for CMD params*/
                        0,              /*Always NULL for CMD params*/
                        "Help : loopback"); /*Help String*/

                libcli_register_param(&node_name, &loopback); /*Add loopback param as suboption of <node-name> param*/

                {
                    /*show node <node-name> loopback <loopback-address>*/ 
                    static param_t loopback_address;   /*Get the param_t variable, either a static memory or heap memory, not stack memory*/
                    init_param(&loopback_address,      /*Address of the current param*/
                            LEAF,                      /*CMD for command param, LEAF for leaf param. Since it is a leaf param which takes node names, hence pass LEAF*/
                            0,                         /*Always NULL for LEAF param*/
                            node_loopback_callback_handler, /*Since this is complete command, it should invoke application routine. Pass the pointer to that routine here.*/
                            validate_loopback_address,      /*Optional : can be NULL. This is also application specific routine, and perform validation test 
                                                              to the value entered by the user for this leaf param. If validation pass, then only node_loopback_callback_handler routine is invoked*/
                            IPV4,                    /*leaf param value type. loopback address is IPV4 type, hence pass IPV4*/
                            "lo-address",           /*Applicable only for LEAF param. Give some name to leaf-params. It is this string that we will parse in application code to find the value passed by the user*/
                            "Help : Node's loopback address");  /*Help String*/
                    libcli_register_param(&loopback, &loopback_address);   /*Add node_name leaf param as suboption of <node-name> param. Note that: show --> node --> node_name --> lo-address has been chained*/
                    /* The below API should be called for param at which the command is supposed to invoke application callback rouine. 
                     * This CMDODE_SHOW_NODE_LOOPBACK code is sent to application using which we find which command was triggered, and accordingly what 
                     * are expected leaf params we need to parse. More on this ater.*/
                    set_param_cmd_code(&node_name, CMDODE_SHOW_NODE_LOOPBACK);
                }
            }
        }
    }   

    support_cmd_negation(config);
    /*Do not add any param in config command tree after above line*/
    start_shell();
    return 0;
}
