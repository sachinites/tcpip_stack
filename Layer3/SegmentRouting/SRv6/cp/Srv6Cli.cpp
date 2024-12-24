#include <arpa/inet.h>
#include "../../../../CLIBuilder/libcli.h"
#include "../../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../../graph.h"
#include "../../../../Interface/InterfaceUApi.h"
#include "../../../../common/l3_hdrs.h"
#include "../../../ipv6/ipv6_utils.h"
#include "../../../ipv6/ipv6_route.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../../pkt_block.h"
#include "../../../../common/cp2dp.h"
#include "srv6_api.h" 
#include "srv6_rtr.h"

extern graph_t *topo;

/* /* config node <node-name> ipv6 srv6 */
#define IPV6_SRV6_ENABLE_CONFIG  1

/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end [flavor [psp|usp|usd]]*/
#define IPV6_SRV6_PREFIX_SID_CONFIG  2

/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x <oif-name> [flavor [psp | usp | usd ]]*/
#define IPV6_SRV6_ADJ_SID_CONFIG  3

/* config node <node-name> protocol source-packet-routing srv6 locator <loc-name> <ipv6-address> <[prefix-len]>*/
#define IPV6_SRV6_LOCATOR_CONFIG  4

/* run node <node-name> ping6 srv6 <seg1> <seg2> <seg3> <seg4> . . .  */
 #define CMDCODE_PING6_SRV6 5

/* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-encaps segment-list <seg1> <seg2> <seg3> .... <segn> [flavor [psp | usp | usd ]] */
#define IPV6_SRV6_END_B6_ENCAPS_SID_CONFIG 6

/* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-x-encaps segment-list <seg1> <seg2> <seg3> .... <segn> nexthop <oif-name> [flavor [psp | usp | usd ]]*/
#define IPV6_SRV6_END_B6_ENCAPS_X_SID_CONFIG 7

/* config node <node-name> ipv6 route <v6-address> <mask>  binding-sid <v6-address>*/ 
#define IPV6_SRV6_BINDING_SID_CONFIG 8

static int
srv6_config_enable
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        
    } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
            if (node_info) return 0;
            SRV6_NODE_INFO(node) = (srv6_node_info_t *) XCALLOC (0, 1 , srv6_node_info_t);
            srv6_init (node);
        }
        break;
        case CONFIG_DISABLE:
            {
                srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
                if (!node_info) return 0;
                srv6_de_init (node);
            }
        break;
    }
    return 0;
}

static int
srv6_locator_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    
    tlv_struct_t *tlv;
    c_string locator_name = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    uint8_t prefix_len = 0;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "prefix-len"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "loc-name"))
            locator_name = tlv->value;

    } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            if (!srv6_is_enable(node)) {
                cprintf ("Error : srv6 not enabled\n");
                return -1;
            }

            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
            srv6_locator_t *loc = &node_info->loc;

            if (!is_ipv6_addr_unspecified(&loc->sid.addr)) {
                cprintf ("Error : Locator already configured\n");
                return -1;
            }

            inet_pton(AF_INET6, (char *)ipv6_addr,  &loc->sid.addr);
            strncpy(loc->name,  (const char *)locator_name,  sizeof (loc->name));
            loc->prefix_len = prefix_len;
            loc->data_block_prefix_len = SRV6_DATA_BLOCK_SIZE;
            loc->flavor = DEFAULT_FLAVOR;

            /* Locator post config processing */
            srv6_local_sid_config_post_processing (node,
                    &loc->sid,
                    loc->prefix_len,
                    END,
                    loc->flavor,
                    NULL,
                    NULL);
        }
        break;
        case CONFIG_DISABLE:
        {
            if (!srv6_is_enable(node)) {
                cprintf ("Error : srv6 not enabled\n");
                return -1;
            }

            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
            srv6_locator_t *loc = &node_info->loc;
            mtrie_node_t *mnode;
            srv6_pfxsid_t *pfxsid;

            if (is_ipv6_addr_unspecified(&loc->sid.addr)) {
                return 0;
            }

        /* Remove all local prefix sids and Adj sids routes from RIB,
            also send delete ips */
            srv6_delete_all_pfx_sids (node) ;
            srv6_delete_all_adj_sids (node) ;

            /* Dont delete remote routes learnt from IGP. Only local routes
                calculation is stopped when user disable locator */
            
            //srv6_delete_all_igp_routes (node);

            /* now delete the locator route and send IPS to IGP */
            srv6_local_sid_unconfig_pre_processing(node,
                                               &loc->sid,
                                               loc->prefix_len,
                                               loc->endP,
                                               loc->flavor,
                                               0, 0);
            
            /* Remove the locator config */
            memset (loc, 0, sizeof (*loc));
        }
        break;
    }

    return 0;
}

uint8_t 
srv6_route_flag (node_t *node, uint8_t (*prefix)[16]) ;

uint8_t 
srv6_route_flag (node_t *node, uint8_t (*prefix)[16]) {

    if (node->node_nw_prop.srv6_locator.locator_name[0] == '\0') 
        return SRV6_REMOTE_RT;

    if (ipv6_address_is_subnet (
            &node->node_nw_prop.srv6_locator.locator, 
            node->node_nw_prop.srv6_locator.prefix_len,
            prefix)) {

        return SRV6_LOCAL_RT;
    }

    return SRV6_REMOTE_RT;
}

static int
srv6_prefix_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    tlv_struct_t *tlv;
    uint8_t prefix_len = 0;
    node_t *node = NULL;
    Interface *intf = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    c_string oif_name = NULL;
    c_string flavor1 = NULL;
    c_string flavor2 = NULL;
    c_string flavor3 = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "mask"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor1 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor2 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor3 = tlv->value;
         else if  (parser_match_leaf_id (tlv->leaf_id, "oif-name"))
            oif_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (oif_name) {

        intf = node_get_intf_by_name(node, (const char *)oif_name);

        if (!intf) {
            cprintf ("Error : Interface %s not found\n", oif_name);
            return -1;
        }
    }

    uint8_t flavor = DEFAULT_FLAVOR;

    if (flavor1) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor = PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor = PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor = USD;
    }

    if (flavor2) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    if (flavor3) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            ipv6_route_install  (node,
                                &prefix,
                                prefix_len,
                                srv6_route_flag (node, &prefix.addr),
                                NULL,
                                intf,
                                0,
                                0, END, flavor,
                                PROTO_SRv6);
        }
        break;

        case CONFIG_DISABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            ipv6_route_uninstall (node,
                                &prefix,
                                prefix_len,
                                NULL,
                                NULL,
                                PROTO_SRv6);
        }
        break;
    }
    return 0;
}

static int
srv6_adjacency_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {


    tlv_struct_t *tlv;
    uint8_t prefix_len = 0;
    node_t *node = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    c_string flavor1 = NULL;
    c_string flavor2 = NULL;
    c_string flavor3 = NULL;
    c_string oif_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "mask"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "oif-name"))
            oif_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor1 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor2 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor3 = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    Interface *intf = node_get_intf_by_name(node, (const char *)oif_name);

    if (!intf) {
        cprintf ("Error : Interface %s not found\n", oif_name);
        return -1;
    }

    uint8_t flavor = DEFAULT_FLAVOR;

    if (flavor1) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor = PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor = PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor = USD;
    }

    if (flavor2) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    if (flavor3) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            ipv6_route_install (node,
                                &prefix,
                                prefix_len,
                                srv6_route_flag (node, &prefix.addr),
                                NULL,
                                intf,
                                0,
                                0, END_X, flavor,
                                PROTO_SRv6);
        }
        break;

        case CONFIG_DISABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            ipv6_route_uninstall (node,
                                &prefix,
                                prefix_len,
                                NULL,
                                intf,
                                PROTO_SRv6);
        }
        break;
    }
    return 0;
}

static int 
srv6_flavor_validation (Stack_t *tlv_stack, unsigned char *leaf_value) {

    if (strncmp((const char *)leaf_value, "psp", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    if (strncmp((const char *)leaf_value, "usp", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    if (strncmp((const char *)leaf_value, "usd", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static void 
srv6_flavor_cli_subtree_hookup (param_t *root, int cmdcode, cmd_callback cbk) {

    param_t *flavor = (param_t *)calloc(1, sizeof(param_t));
    init_param(flavor, CMD, "flavor", NULL, NULL, INVALID, NULL, "Configure SRv6 EndPoint Flavor");
    libcli_register_param(root, flavor);
    {
        param_t *flavors_value = (param_t *)calloc(1, sizeof(param_t));
        init_param(flavors_value, LEAF, NULL, cbk, 
            srv6_flavor_validation , 
            STRING, "flavor", "Flavor Values [ psp | usp | usd ]");
        libcli_register_param( flavor , flavors_value);
        libcli_param_recursive(flavors_value);
        libcli_set_param_cmd_code(flavors_value, cmdcode);
        //libcli_set_tail_config_batch_processing (flavors_value);
    }
}

static int
srv6_end_b6_encaps_config_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    int i = 0;
    node_t *node;
    uint8_t prefix_len;
    c_string node_name;
    c_string flavor1 = NULL;
    c_string flavor2 = NULL;
    c_string flavor3 = NULL;
    c_string ipv6_route_str;
    tlv_struct_t *tlv = NULL;
    ipv6_addr_t segment_lst[16] = {0};

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "segment")) 
            inet_pton6 ((char *)tlv->value, &segment_lst[i++]);
        else if (parser_match_leaf_id(tlv->leaf_id, "ipv6-address"))
            ipv6_route_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "mask"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor1 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor2 = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor"))
            flavor3 = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    uint8_t flavor = DEFAULT_FLAVOR;

    if (flavor1) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor = PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor = PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor = USD;
    }

    if (flavor2) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    if (flavor3) {
        if (strncmp((const char *)flavor1, "psp", 3) == 0) flavor |= PSP;
        if (strncmp((const char *)flavor1, "usp", 3) == 0) flavor |= PSD;
        if (strncmp((const char *)flavor1, "usd", 3) == 0) flavor |= USD;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_route_str, &prefix);
            ipv6_route_install (node,
                                &prefix,
                                prefix_len,
                                srv6_route_flag (node, &prefix.addr),
                                NULL,
                                0,
                                &segment_lst,
                                0, END_B6_ENCAP, flavor,
                                PROTO_SRv6);            
        }
        break;

        case CONFIG_DISABLE:
        {

        }
        break;
    }

    return 0;        
}


static int
srv6_end_b6_x_encaps_config_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}


void srv6_build_cli_tree(param_t *root)
{
    {
        /*...  srv6 endpoint end-sid ... */
        static param_t srv6;
        init_param(&srv6, CMD, "srv6", 0, NULL, INVALID, NULL, "Configure SRv6");
        libcli_register_param(root, &srv6);
        {
            static param_t endpoint;
            init_param(&endpoint, CMD, "endpoint", NULL, NULL, INVALID, NULL, "Configure SRv6 Endpoint");
            libcli_register_param(&srv6, &endpoint);
            {
                /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end ...*/
                static param_t end;
                init_param(&end, CMD, "end-sid", srv6_prefix_sid_config_handler,
                           NULL, INVALID, NULL, "Configure SRv6 Endpoint: END");
                libcli_register_param(&endpoint, &end);
                libcli_set_param_cmd_code(&end, IPV6_SRV6_PREFIX_SID_CONFIG);
                {
                    /* . .. nexthop <if-name>*/
                    static param_t nexthop;
                    init_param(&nexthop, LEAF, NULL, NULL, NULL, STRING, "nexthop", "Next Hop Interface Name");
                    libcli_register_param(&end, &nexthop);
                    {
                            static param_t oif_name;
                            init_param(&oif_name, LEAF, NULL, srv6_prefix_sid_config_handler, 
                                NULL, STRING, "oif-name", "Outgoing Interface Name");
                            libcli_register_param(&nexthop, &oif_name);
                            libcli_set_param_cmd_code(&oif_name, IPV6_SRV6_PREFIX_SID_CONFIG);
                            srv6_flavor_cli_subtree_hookup(&oif_name, 
                                IPV6_SRV6_PREFIX_SID_CONFIG, srv6_prefix_sid_config_handler);
                    }
                }
                srv6_flavor_cli_subtree_hookup(&end, 
                    IPV6_SRV6_PREFIX_SID_CONFIG, srv6_prefix_sid_config_handler);
            }

            {
                /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x-sid  . .. */
                static param_t end_x;
                init_param(&end_x, CMD, "end-x-sid", NULL,
                           NULL, INVALID, NULL, "Configure SRv6 Endpoint: END-X");
                libcli_register_param(&endpoint, &end_x);
                {
                    /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x <oif-name> ... */
                    static param_t oif_name;
                    init_param(&oif_name, LEAF, NULL, srv6_adjacency_sid_config_handler, NULL, STRING, "oif-name", "Outgoing Interface Name");
                    libcli_register_param(&end_x, &oif_name);
                    libcli_set_param_cmd_code(&oif_name, IPV6_SRV6_ADJ_SID_CONFIG);
                    srv6_flavor_cli_subtree_hookup(&oif_name, IPV6_SRV6_ADJ_SID_CONFIG, srv6_adjacency_sid_config_handler);
                }
            }

            {
                /* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-encaps segment-list <seg1> <seg2> <seg3> .... <segn> [flavor [psp | usp | usd ]] */
                static param_t end_b6_encaps;
                init_param(&end_b6_encaps, CMD, "end-b6-encaps", NULL,
                           NULL, INVALID, NULL, "Configure SRv6 Endpoint: END-B6-ENCAPS");
                libcli_register_param(&endpoint, &end_b6_encaps);
                {
                    static param_t seg_lst;
                    init_param(&seg_lst, CMD, "segment-list", NULL,
                            NULL, INVALID, NULL, "Configure SRv6 Segment List");
                    libcli_register_param(&end_b6_encaps, &seg_lst);
                    {
                        static param_t segment;
                        init_param(&segment, LEAF, NULL, srv6_end_b6_encaps_config_handler, NULL, IPV6, "segment", "ipv6-address segment");                        
                        libcli_register_param(&seg_lst, &segment);
                        libcli_set_param_cmd_code(&segment, IPV6_SRV6_END_B6_ENCAPS_SID_CONFIG);
                        libcli_param_recursive(&segment);
                        srv6_flavor_cli_subtree_hookup(&segment, 
                            IPV6_SRV6_END_B6_ENCAPS_SID_CONFIG, srv6_end_b6_encaps_config_handler);
                    }                    
                }                
            }


            {
                /* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-x-encaps segment-list <seg1> <seg2> <seg3> .... <segn> nexthop <oif-name> [flavor [psp | usp | usd ]]*/
                static param_t end_b6_x_encaps;
                init_param(&end_b6_x_encaps, CMD, "end-b6-x-encaps", NULL,
                           NULL, INVALID, NULL, "Configure SRv6 Endpoint: END-B6-X-ENCAPS");
                libcli_register_param(&endpoint, &end_b6_x_encaps);
                {
                    static param_t seg_lst;
                    init_param(&seg_lst, CMD, "segment-list", NULL,
                            NULL, INVALID, NULL, "Configure SRv6 Segment List");
                    libcli_register_param(&end_b6_x_encaps, &seg_lst);
                    {
                        static param_t segment;
                        init_param(&segment, LEAF, NULL, NULL, NULL, IPV6, "segment", "ipv6-address segment");                        
                        libcli_register_param(&seg_lst, &segment);
                        libcli_param_recursive(&segment);
                        {
                            /* . .. nexthop <if-name>*/
                            static param_t nexthop;
                            init_param(&nexthop, CMD, "nexthop", NULL, NULL, INVALID, NULL, "Next Hop Interface Name");
                            libcli_register_param(&segment, &nexthop);
                            {
                                    static param_t oif_name;
                                    init_param(&oif_name, LEAF, NULL, srv6_end_b6_x_encaps_config_handler, 
                                        NULL, STRING, "oif-name", "Outgoing Interface Name");
                                    libcli_register_param(&nexthop, &oif_name);
                                    libcli_set_param_cmd_code(&oif_name, IPV6_SRV6_END_B6_ENCAPS_X_SID_CONFIG);
                                    srv6_flavor_cli_subtree_hookup(&oif_name, 
                                        IPV6_SRV6_END_B6_ENCAPS_X_SID_CONFIG, srv6_end_b6_x_encaps_config_handler);
                            }
                        }
                    }                    
                }                
            }

        }
    }
}

int
srv6_build_global_config_cli_tree (param_t *root) {

    {
        /* . . . source-packet-routing srv6 locator <loc-name> <ipv6-address> <[prefix-len]> . .*/
        static param_t spring;
        init_param(&spring, CMD, "source-packet-routing", NULL, NULL, INVALID, NULL, "Configure Source Packet Routing");
        libcli_register_param(root, &spring);
        {
            static param_t srv6;
            init_param(&srv6, CMD, "srv6", srv6_config_enable, NULL, INVALID, NULL, "Configure SRv6");
            libcli_register_param(&spring, &srv6);
            libcli_set_param_cmd_code(&srv6, IPV6_SRV6_ENABLE_CONFIG);
            {
                static param_t locator;
                init_param(&locator, CMD, "locator", NULL, NULL, INVALID, NULL, "Configure SRv6 Locator");
                libcli_register_param(&srv6, &locator);
                {
                    static param_t loc_name;
                    init_param(&loc_name, LEAF, NULL, NULL, NULL, STRING, "loc-name", "Locator Name");
                    libcli_register_param(&locator, &loc_name);
                    {
                        static param_t ipv6_addr;
                        init_param(&ipv6_addr, LEAF, NULL, NULL, NULL, IPV6, "ipv6-address", "IPv6 Address");
                        libcli_register_param(&loc_name, &ipv6_addr);
                        {
                            static param_t prefix_len;
                            init_param(&prefix_len, LEAF, NULL, srv6_locator_handler, NULL, INT, "prefix-len", "Prefix Length");
                            libcli_register_param(&ipv6_addr, &prefix_len);
                            libcli_set_param_cmd_code(&prefix_len, IPV6_SRV6_LOCATOR_CONFIG);
                            libcli_set_tail_config_batch_processing(&prefix_len);
                        }
                    }
                }
            }
        }
    }

    return 0;
}


static int
srv6_ping6_handler
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    int i = 0;
    node_t *node;
    c_string node_name;
    c_string ipv6_addr_str[16];
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "segment"))
            ipv6_addr_str[i++] = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    pkt_size_t srh_hdr_size = sizeof (srh_hdr_t ) + (i * 16);
    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer (srh_hdr_size);
    pkt_block_set_starting_hdr_type (pkt_block, SRH_HDR);
    srh_hdr_t *srh_hdr = (srh_hdr_t *)pkt_block_get_pkt(pkt_block, NULL);

    srh_hdr->nexthdr = ICMP6_PROTO;
    srh_hdr->hdrlen = srh_hdr_size;
    srh_hdr->type = 4;
    srh_hdr->segments_left = i -1;
    srh_hdr->first_segment = 0;
    srh_hdr->flags = 0;
    srh_hdr->tag = 0;

    for (int j = 0; j < i; j++)  
        inet_pton(AF_INET6, (const char *)ipv6_addr_str[j], srh_hdr->segments[i - j - 1]);

    ipv6_addr_t dest_addr;
    memcpy (dest_addr.addr, srh_hdr->segments[srh_hdr->segments_left], 16);

    cp2dp_send_ip6_data (node, pkt_block, dest_addr, PROTO_SRH);
    pkt_block_dereference (pkt_block);
    return 0;
}

/* run node <node-name> ping6 srv6 <seg1> <seg2> <seg3> <seg4> . . .  */
void 
srv6_build_cli_run_tree (param_t *root)
{
        {
            static param_t srv6;
            init_param(&srv6, CMD, "srv6", NULL, NULL, INVALID, NULL, "SRv6 Ping");
            libcli_register_param(root, &srv6);
            {
                static param_t seg;
                init_param(&seg, LEAF, NULL, srv6_ping6_handler, NULL, IPV6, "segment", "SRv6 Segment");
                libcli_register_param(&srv6, &seg);
                libcli_set_param_cmd_code(&seg, CMDCODE_PING6_SRV6);
                libcli_param_recursive (&seg);
            }
        }
}
