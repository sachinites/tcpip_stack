#include <assert.h>
#include "../../../../CLIBuilder/libcli.h"
#include "../../../../graph.h"
#include "srv6_cmds.h"
#include "srv6_api.h"
#include "srv6_struct.h"
#include "srv6_rtr.h"
#include "../../../ipv6/ipv6_utils.h"

extern graph_t *topo;

#if 0

https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k-r7-5/segment-routing/configuration/guide/b-segment-routing-cg-asr9000-75x/configure-srv6-full-length-sid.html

#endif 


/*
SRv6-LF1# show segment-routing srv6 locator 
Mon Aug 12 20:54:15.414 EDT
Name                  ID       Algo  Prefix                    Status 
--------------------  -------  ----  ------------------------  -------
Loc1-BE               17       0     2001:db8:0:a2::/64        Up     
Loc1-LL               18       128   2001:db8:1:a2::/64        Up

*/
static void 
srv6_show_locator (node_t *node) {

    char ipv6_addr_str[48];

    if (!srv6_is_enable (node)) return;

    srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

    srv6_locator_t *loc = &node_info->loc;

    cprintf ("%-32s    %-4d   %-40s\n",  
        loc->name, loc->algo, inet_ntop6 (&loc->sid, ipv6_addr_str));
}





int
srv6_show_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CMD_CODE_SHOW_SRV6_LOCAL_ROUTES:
        {
            srv6_show_locator (node);
        }
        break;
        default:
            assert(0);
    }

    return 0;
}
