
#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_pkt.h"
#include "isis_cmd.h"


void isis_init(node_t *node){
	isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
	if (isis_node_info)
		return;
	isis_node_info = calloc(1, sizeof(isis_node_info_t));
	node->node_nw_prop.isis_node_info = isis_node_info;
	tcp_stack_register_l2_pkt_trap_rule(node,isis_pkt_trap_rule,isis_pkt_receive);
}

void isis_de_init(node_t *node){
	printf("Function triggered %s\n", __func__);
	isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

	if (!isis_node_info)
		return;
	free(isis_node_info);
	node->node_nw_prop.isis_node_info = NULL;
	if (ISIS_NODE_INFO(node) == NULL)
		printf("memeory is freed\n");
}

int isis_config_handler(param_t *param,
		ser_buff_t *tlv_buf,
		op_mode enable_or_disable){

	tlv_struct_t *tlv;
	char *node_name;
	node_t *node;
	TLV_LOOP_BEGIN(tlv_buf, tlv)
	{
		if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
		{
			node_name = tlv->value;
		}
		else
		{
			assert(0);
		}
	}
	TLV_LOOP_END;
	printf("Node name : %s\n", node_name);
	node = node_get_node_by_name(topo, node_name);
	int cmdcode = EXTRACT_CMD_CODE(tlv_buf);
	printf("CMDCODE : %d\n", cmdcode);
	switch (cmdcode)
	{
		case ISIS_CONFIG_NODE_ENABLE:
			switch (enable_or_disable)
			{
				case CONFIG_ENABLE:
					isis_init(node);
					break;
				case CONFIG_DISABLE:
					isis_de_init(node);
					break;
				default:
					break;
			}
		default:
			break;
	}

	return 0;
}

int isis_show_handler(param_t *param, ser_buff_t *tlv_buf,
		op_mode enable_or_disable){
	tlv_struct_t *tlv;
	char *node_name;
	node_t *node;
	interface_t *intf;
	int i = 0;
	TLV_LOOP_BEGIN(tlv_buf, tlv)
	{
		if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
		{
			node_name = tlv->value;
		}
		else
		{
			assert(0);
		}
	}
	TLV_LOOP_END;
	node = node_get_node_by_name(topo, node_name);
	switch (EXTRACT_CMD_CODE(tlv_buf))
	{
		case ISIS_SHOW_NODE_ENABLE:
			isis_show_node_protocol_state(node);
			for (i=0; i < MAX_INTF_PER_NODE; i++)
			{
				intf = node->intf[i];
				if (!intf)
					continue;
				isis_show_intf_protocol_state(intf);
			} 

			break;

		default:
			break;
	}

	return 0;
}

int isis_intf_config_handler(param_t *param, ser_buff_t *tlv_buf,
		op_mode enable_or_disable){
	tlv_struct_t *tlv;
	char *node_name;
	node_t *node;
	char *if_name;
	interface_t *intf;
	int i=0;
	TLV_LOOP_BEGIN(tlv_buf, tlv)
	{
		if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
		{
			node_name = tlv->value;
		}
		else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0)
		{
			if_name = tlv->value;
		}
		else
		{
			assert(0);
		}
	}
	TLV_LOOP_END;
	printf("Node name : %s\n", node_name);
	node = node_get_node_by_name(topo, node_name);
	int cmdcode = EXTRACT_CMD_CODE(tlv_buf);
	printf("CMDCODE : %d\n", cmdcode);

	switch (cmdcode)
	{
		case CMDCODE_CONFIG_ISIS_PROTO_ALL_INTF_ENABLE:
			switch (enable_or_disable)
			{
				case CONFIG_ENABLE:
					for (i=0; i <MAX_INTF_PER_NODE; i++)
					{
						intf = node->intf[i];
						printf("intf name %s \n",intf->if_name);
						if (!intf)
							continue;
						isis_config_enable_on_intf(intf);
					}
					printf("Loop ending\n");
					break;
				case CONFIG_DISABLE:
					for (i=0; i <MAX_INTF_PER_NODE; i++)
					{
						intf = node->intf[i];
						if (!intf)
							continue;
						isis_config_disable_on_intf(intf);
					}
					break;
				default:
					break;
			}
			break;
		case CMDCODE_CONFIG_ISIS_PROTO_INTF_ENABLE:
			intf = node_get_node_by_name(node, if_name);
			switch (enable_or_disable)
			{
				case CONFIG_ENABLE:
					isis_config_enable_on_intf(intf);
					break;
				case CONFIG_DISABLE:
					isis_config_disable_on_intf(intf);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
}
