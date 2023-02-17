#ifndef __ISIS_CLI_C__
#define __ISIS_CLI_C__
#include"isis_cmdcodes.h"
#include "../app_handlers.h"
#include "../../cmdcodes.h"
#include "isis_cmd.h"
/* show node <node-name> protocol isis */

int isis_config_cli_tree(param_t *param){
	static param_t isis_proto;
	init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	libcli_register_param(param, &isis_proto);
	set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
	{
		static param_t interface;
		init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
		libcli_register_param(&isis_proto, &interface);
		{
			static param_t all;
			init_param(&all, CMD, "all", isis_intf_config_handler, 0, INVALID, 0, "all interface");
			libcli_register_param(&interface, &all);
			set_param_cmd_code(&all, CMDCODE_CONFIG_ISIS_PROTO_ALL_INTF_ENABLE);
		}
		{
			static param_t if_name;
			init_param(&if_name,LEAF,0, isis_intf_config_handler, 0, INVALID,"if-name", "interface name");
			libcli_register_param(&interface, &if_name);
			set_param_cmd_code(&if_name, CMDCODE_CONFIG_ISIS_PROTO_INTF_ENABLE);
		}
	}

}

int isis_show_cli_tree(param_t *param){
	static param_t isis_proto;
	init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
	libcli_register_param(param, &isis_proto);
	set_param_cmd_code(&isis_proto, ISIS_SHOW_NODE_ENABLE);
}
#endif

