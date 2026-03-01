#include <arpa/inet.h>
#include "../../../../CLIBuilder/libcli.h"
#include "../../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../../router_init.h"
#include "../../../../Interface/InterfaceUApi.h"
#include "../../../../common/l3_hdrs.h"
#include "../../../ipv6/ipv6_utils.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../../pkt_block.h"
#include "../../../../common/cp2dp.h"
#include "srv6_sid_pool.h"
#include "srv6_api.h" 
#include "srv6_rtr.h"
#include "srv6_cmds.h"
#include "srv6_rtm.h"
#include "../../../../mtrie/mtrie.h"

extern graph_t *topo;

static int
srv6_config_enable(int cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable)
{

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
    char err_msg[256];
    c_string locator_name = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    uint8_t prefix_len = 0;
    uint8_t algorithm = 0;
    pool_error_codes_t prc = SRv6_POOL_OK;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "prefix-len"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "loc-name"))
            locator_name = tlv->value;      
        else if  (parser_match_leaf_id (tlv->leaf_id, "algorithm"))
            algorithm = atoi((const char *)tlv->value);     

    } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);

    switch (cmdcode)
    {
    case IPV6_SRV6_LOCATOR_CONFIG:
    {
        switch (enable_or_disable)
        {
            case CONFIG_ENABLE:
            {
                if (!srv6_is_enable(node))
                {
                    cprintf("Error : srv6 not enabled\n");
                    return -1;
                }

                srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
                srv6_locator_t *loc = &node_info->loc;

                if (!is_ipv6_addr_unspecified(&loc->sid.addr))
                {
                    cprintf("Error : Locator already configured\n");
                    return -1;
                }

                inet_pton(AF_INET6, (char *)ipv6_addr, &loc->sid.addr);
                strncpy(loc->name, (const char *)locator_name, sizeof(loc->name));
                loc->prefix_len = prefix_len;

                /* Create the locator in SID pool library */
                prc = srv6_pool_create_locator ( (NODE_SRv6_SID_POOL(node)), 
                                            &loc->sid,
                                            prefix_len, 
                                            loc->name,
                                            err_msg);

                if (prc != SRv6_POOL_OK) {

                    cprintf ("%s, err-code : %d\n", err_msg, prc);
                    memset (&loc, 0, sizeof(loc));
                    return -1;
                }

                srv6_pool_set_locator_properties ((NODE_SRv6_SID_POOL(node)), 
                        loc->name, 0, 0, 0, 0);

                srv6_rtm_route_install (node, 
                                        &loc->sid,
                                        loc->prefix_len,
                                        FIB_NH_FWD_F_REJECT,
                                        0, 0,
                                        NULL, 0, 
                                        SRV6_END_FN_NONE,
                                        RTM_PROTO_STATIC, true);
            }
            break;
            case CONFIG_DISABLE:
            {
                if (!srv6_is_enable(node))
                {
                    cprintf("Error : srv6 not enabled\n");
                    return -1;
                }

                srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
                srv6_locator_t *loc = &node_info->loc;
                mtrie_node_t *mnode;
                srv6_pfxsid_t *pfxsid;

                if (is_ipv6_addr_unspecified(&loc->sid.addr))
                {
                    return 0;
                }

                if (srv6_pool_is_locator_being_used_by_any_client (
                    NODE_SRv6_SID_POOL(node), loc->name)) {

                        cprintf ("Error : Locator is in use by SRv6 clients\n");
                        return -1;
                }

                /* Remove all local prefix sids and Adj sids routes from RIB,
                    also send delete ips */
                srv6_delete_all_pfx_sids(node);
                srv6_delete_all_adj_sids(node);

                /* now delete the locator route and send IPS to IGP */
                srv6_rtm_route_install (node, 
                                        &loc->sid,
                                        loc->prefix_len,
                                        FIB_NH_FWD_F_REJECT,
                                        0, 0,
                                        NULL, 0, 
                                        SRV6_END_FN_NONE,
                                        RTM_PROTO_STATIC, false);

                /* Remove the locator config */
                prc = srv6_pool_delete_locator ( (NODE_SRv6_SID_POOL(node)), 
                                            loc->name,
                                            err_msg);

                assert (prc == SRv6_POOL_OK);                           
                memset(loc, 0, sizeof(*loc));
            }
            break;
        }
    }
    break;

    case IPV6_SRV6_LOCATOR_CONFIG_ALGORITHM:
    break;

    }
    return 0;
}

static int
srv6_prefix_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    tlv_struct_t *tlv;
    char flavor[3][4];
    char err_msg[256];
    uint8_t flavor_val = 0;
    uint8_t prefix_len = 128;
    node_t *node = NULL;
    c_string oif_name = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    pool_error_codes_t prc = SRv6_POOL_OK;

    flavor[0][0] = '\0';
    flavor[1][0] = '\0';
    flavor[2][0] = '\0';

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor")) {

            do {

                if (flavor[0][0] == '\0') {
                    strncpy(flavor[0], (const char *)(tlv->value), 3);
                    break; 
                }
                else if (flavor[1][0] == '\0') {
                    strncpy(flavor[1], (const char *)(tlv->value), 3);
                    break; 
                }
                else if (flavor[2][0] == '\0') {
                    strncpy(flavor[2], (const char *)(tlv->value), 3);
                    break; 
                }                                

            } while (0);
        }

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    flavor_val = DEFAULT_FLAVOR;

    if (flavor[0][0] != '\0 ') {
        if (strncmp((const char *)flavor[0], "psp", 3) == 0) flavor_val = PSP;
        if (strncmp((const char *)flavor[0], "usp", 3) == 0) flavor_val = USP;
        if (strncmp((const char *)flavor[0], "usd", 3) == 0) flavor_val = USD;
    }

    if (flavor[1][0] != '\0 ') {
        if (strncmp((const char *)flavor[1], "psp", 3) == 0) flavor_val |= PSP;
        if (strncmp((const char *)flavor[1], "usp", 3) == 0) flavor_val |= USP;
        if (strncmp((const char *)flavor[1], "usd", 3) == 0) flavor_val |= USD;
    }

    if (flavor[2][0] != '\0 ') {
        if (strncmp((const char *)flavor[2], "psp", 3) == 0) flavor_val |= PSP;
        if (strncmp((const char *)flavor[2], "usp", 3) == 0) flavor_val |= USP;
        if (strncmp((const char *)flavor[2], "usd", 3) == 0) flavor_val |= USD;
    }

    Srv6_endpcode_t endpCode = srv6_get_composite_END_endpcode (flavor_val);

    if (endpCode == SRV6_END_FN_NONE) {
        cprintf ("%s : Error : Invalid flavor\n", node->node_name);
        return -1;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {

            if (!srv6_is_enable(node)) {
                cprintf ("Error : srv6 not enabled\n");
                return -1;
            }
            
            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
            srv6_locator_t *loc = &node_info->loc;

            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);

            /* Pool Reservation */
            prc = srv6_pool_alloc_static_sid (
                                    (NODE_SRv6_SID_POOL(node)), 
                                    &prefix,
                                     srv6_sid_client_srv6,
                                     0,
                                     NULL,
                                     endpCode,
                                     err_msg);

            if (prc != SRv6_POOL_OK) {

                cprintf ("%s, err-code : %d\n", err_msg, prc);
                return -1;
            }

            srv6_pfxsid_t *pfxsid = (srv6_pfxsid_t *) XCALLOC (0, 1, srv6_pfxsid_t);

            pfxsid->sid = prefix;
            pfxsid->endP = endpCode;
            pfxsid->flags = 0;
            pfxsid->prefix_len = 128;
            pfxsid->n_seg_lst = 0;

            /* Now add pfxsid to the mtrie */
            mtrie_node_t *mnode;
            bitmap_t prefix_bm, mask_bm;
            mtrie_ops_result_code_t rc;
            bitmap_init(&prefix_bm, 128);
            bitmap_init(&mask_bm, 128);

            ipv6_copy_bitmap (&prefix.addr, &prefix_bm);
            for (int i = 0; i < prefix_len; i++)
                bitmap_set_bit_at(&mask_bm, i);
            bitmap_inverse (&mask_bm, 128);

            rc = mtrie_insert_prefix(node_info->configured_pfx_sids,
                             &prefix_bm,
                             &mask_bm,
                             prefix_len,
                             &mnode);
            
            bitmap_free_internal(&prefix_bm);
            bitmap_free_internal(&mask_bm);

            switch (rc) {
                case MTRIE_INSERT_SUCCESS:
                    break;
                case MTRIE_INSERT_DUPLICATE:
                    cprintf ("Error : Prefix sid already configured\n");
                    XFREE (pfxsid);
                    return -1;
                default:
                    cprintf ("Error : Prefix sid insertion failed, ret code = %d\n", rc);
                    XFREE (pfxsid);
                    return -1;
            }

            mnode->data = (void *)pfxsid;

             srv6_rtm_route_install (node, 
                                        &pfxsid->sid,
                                        pfxsid->prefix_len,
                                        FIB_NH_FWD_F_SRv6_FORWARD,
                                        0, 0,
                                        NULL, 0, 
                                        pfxsid->endP,
                                        RTM_PROTO_STATIC, true);
        }
        break;

        case CONFIG_DISABLE:
        {
            if (!srv6_is_enable(node)) {
                return 0;
            }

            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            
            /* Lookup prefix sid*/
            mtrie_node_t *mnode;
            bitmap_t prefix_bm, mask_bm;
            srv6_pfxsid_t *pfxsid;
            mtrie_ops_result_code_t rc;

            bitmap_init(&prefix_bm, 128);
            bitmap_init(&mask_bm, 128);

            ipv6_copy_bitmap (&prefix.addr, &prefix_bm);
            for (int i = 0; i < prefix_len; i++)
                bitmap_set_bit_at(&mask_bm, i);
            bitmap_inverse (&mask_bm, 128);

            rc = mtrie_delete_prefix(node_info->configured_pfx_sids,
                             &prefix_bm,
                             &mask_bm,
                             (void **)&pfxsid);

            bitmap_free_internal(&prefix_bm);
            bitmap_free_internal(&mask_bm);

            switch (rc) {
                case MTRIE_DELETE_SUCCESS:
                    /* Release pfx sid from pool*/
                    prc = srv6_release_sid (
                                    (NODE_SRv6_SID_POOL(node)), 
                                    &pfxsid->sid, srv6_sid_client_srv6,
                                    err_msg);

                    assert (prc == SRv6_POOL_OK);
                    break;
                case MTRIE_LOOKUP_FAILED:
                    cprintf ("Error : Prefix sid not found\n");
                    return -1;
                default:
                    cprintf ("Error : Prefix sid deletion failed, ret code = %d\n", rc);
                    return -1;
            }

            srv6_rtm_route_install(node,
                                   &pfxsid->sid,
                                   pfxsid->prefix_len,
                                   FIB_NH_FWD_F_SRv6_FORWARD,
                                   0, 0,
                                   NULL, 0,
                                   pfxsid->endP,
                                   RTM_PROTO_STATIC, false);

            XFREE (pfxsid);
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
    char flavor[3][4];
    char err_msg[256];
    uint8_t flavor_val = 0;
    uint8_t prefix_len = 128;
    node_t *node = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
    c_string oif_name = NULL;
    pool_error_codes_t prc = SRv6_POOL_OK;

    flavor[0][0] = '\0';
    flavor[1][0] = '\0';
    flavor[2][0] = '\0';

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "oif-name"))
            oif_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "flavor")) {

            do {

                if (flavor[0][0] == '\0') {
                    strncpy(flavor[0], (const char *)(tlv->value), 3);
                    break; 
                }
                else if (flavor[1][0] == '\0') {
                    strncpy(flavor[1], (const char *)(tlv->value), 3);
                    break; 
                }
                else if (flavor[2][0] == '\0') {
                    strncpy(flavor[2], (const char *)(tlv->value), 3);
                    break; 
                }                                

            } while (0);
        }

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    Interface *intf = node_interface_lookup_by_name(node, (const char *)oif_name);

    if (!intf) {
        cprintf ("Error : Interface %s not found\n", oif_name);
        return -1;
    }

    flavor_val = DEFAULT_FLAVOR;

    if (flavor[0][0] != '\0 ') {
        if (strncmp((const char *)flavor[0], "psp", 3) == 0) flavor_val = PSP;
        if (strncmp((const char *)flavor[0], "usp", 3) == 0) flavor_val = USP;
        if (strncmp((const char *)flavor[0], "usd", 3) == 0) flavor_val = USD;
    }

    if (flavor[1][0] != '\0 ') {
        if (strncmp((const char *)flavor[1], "psp", 3) == 0) flavor_val |= PSP;
        if (strncmp((const char *)flavor[1], "usp", 3) == 0) flavor_val |= USP;
        if (strncmp((const char *)flavor[1], "usd", 3) == 0) flavor_val |= USD;
    }

    if (flavor[2][0] != '\0 ') {
        if (strncmp((const char *)flavor[2], "psp", 3) == 0) flavor_val |= PSP;
        if (strncmp((const char *)flavor[2], "usp", 3) == 0) flavor_val |= USP;
        if (strncmp((const char *)flavor[2], "usd", 3) == 0) flavor_val |= USD;
    }

    Srv6_endpcode_t endpCode = srv6_get_composite_END_X_endpcode (flavor_val);
    
    if (endpCode == SRV6_END_FN_NONE) {
        cprintf ("Error : Invalid flavor\n");
        return -1;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            if ( !srv6_is_enable(node) ) {
                cprintf ("Error : srv6 not enabled\n");
                return -1;
            }
            
            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);
            srv6_locator_t *loc = &node_info->loc;

            if ( is_ipv6_addr_unspecified(&loc->sid.addr) ) {
                cprintf ("Error : Configure Locator first \n");
                return -1;
            }

            ipv6_addr_t prefix, gw;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            memset (&gw, 0, sizeof (gw));

            /* Pool Reservation */
            prc = srv6_pool_alloc_static_sid (
                                    (NODE_SRv6_SID_POOL(node)), 
                                    &prefix,
                                     srv6_sid_client_srv6,
                                     intf->ifindex,
                                     &gw,
                                     endpCode,
                                     err_msg);

            if (prc != SRv6_POOL_OK) {

                cprintf ("%s, err-code : %d\n", err_msg, prc);
                return -1;
            }

            srv6_adjsid_t *adjsid = (srv6_adjsid_t *) XCALLOC (0, 1, srv6_adjsid_t);

            adjsid->sid = prefix;
            adjsid->endP = endpCode;
            adjsid->flags = FIB_NH_FWD_F_SRv6_FORWARD;
            adjsid->prefix_len = prefix_len;
            adjsid->n_seg_lst = 0;
            adjsid->ifindex = intf->ifindex;
            memset (adjsid->gw.addr, 0, 16);

            /* Now add pfxsid to the mtrie */
            mtrie_node_t *mnode;
            bitmap_t prefix_bm, mask_bm;
            mtrie_ops_result_code_t rc;
            bitmap_init(&prefix_bm, 128);
            bitmap_init(&mask_bm, 128);

            ipv6_copy_bitmap (&prefix.addr, &prefix_bm);
            for (int i = 0; i < prefix_len; i++)
                bitmap_set_bit_at(&mask_bm, i);
            bitmap_inverse (&mask_bm, 128);

            rc = mtrie_insert_prefix(node_info->configured_adj_sids,
                             &prefix_bm,
                             &mask_bm,
                             prefix_len,
                             &mnode);
            
            bitmap_free_internal(&prefix_bm);
            bitmap_free_internal(&mask_bm);

            if (rc != MTRIE_INSERT_SUCCESS){
                cprintf ("Error : Adj sid insertion failed, ret code = %d\n", rc);
                XFREE (adjsid);
                return -1;
            }

            mnode->data = (void *)adjsid;

            srv6_rtm_route_install (node, 
                                        &adjsid->sid,
                                        adjsid->prefix_len,
                                        FIB_NH_FWD_F_SRv6_FORWARD,
                                        &adjsid->gw, intf,
                                        NULL, 0, 
                                        endpCode,
                                        RTM_PROTO_STATIC, true);

        }
        break;

        case CONFIG_DISABLE:
        {
            if (!srv6_is_enable(node)) {
                return 0;
            }

            srv6_node_info_t *node_info = SRV6_NODE_INFO(node);

            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_addr, &prefix);
            
            /* Lookup prefix sid*/
            mtrie_node_t *mnode;
            bitmap_t prefix_bm, mask_bm;
            srv6_adjsid_t *adjsid;
            mtrie_ops_result_code_t rc;

            bitmap_init(&prefix_bm, 128);
            bitmap_init(&mask_bm, 128);

            ipv6_copy_bitmap (&prefix.addr, &prefix_bm);
            for (int i = 0; i < prefix_len; i++)
                bitmap_set_bit_at(&mask_bm, i);
            bitmap_inverse (&mask_bm, 128);

            rc = mtrie_delete_prefix(node_info->configured_adj_sids,
                             &prefix_bm,
                             &mask_bm,
                             (void **)&adjsid);

            bitmap_free_internal(&prefix_bm);
            bitmap_free_internal(&mask_bm);

            if (rc != MTRIE_DELETE_SUCCESS){
                cprintf ("Error : Prefix sid deletion failed, ret code = %d\n", rc);
                return -1;
            }

            prc = srv6_release_sid (
                        (NODE_SRv6_SID_POOL(node)), 
                        &adjsid->sid, srv6_sid_client_srv6, err_msg);

            assert (prc == SRv6_POOL_OK);

            srv6_rtm_route_install (node, 
                                        &adjsid->sid,
                                        adjsid->prefix_len,
                                        FIB_NH_FWD_F_SRv6_FORWARD,
                                        &adjsid->gw, intf,
                                        NULL, 0, 
                                        endpCode,
                                        RTM_PROTO_STATIC, false);

            XFREE (adjsid);
        }
        break;
    }
    return 0;
}


static int
srv6_static_route_config_handler
                        (int cmdcode,
                        Stack_t *tlv_stack,
                        op_mode enable_or_disable) {

    
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

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            ipv6_addr_t prefix;
            inet_pton6 ((char *)ipv6_route_str, &prefix);
            srv6_rtm_route_install (node,
                                &prefix,
                                prefix_len,
                                FIB_NH_FWD_F_SRv6_FORWARD,
                                NULL,
                                0,
                                &segment_lst,
                                0, 
                                END_B6_ENCAP, 
                                RTM_PROTO_STATIC, true);            
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


int
srv6_build_global_config_cli_tree (param_t *root) {
    {
        static param_t spring;
        init_param(&spring, CMD, "source-packet-routing", NULL, NULL, INVALID, NULL, "Configure Source Packet Routing");
        libcli_register_param(root, &spring);
        {
            static param_t srv6;
            init_param(&srv6, CMD, "srv6", srv6_config_enable, NULL, INVALID, NULL, "Configure SRv6");
            libcli_register_param(&spring, &srv6);
            libcli_set_param_cmd_code(&srv6, IPV6_SRV6_ENABLE_CONFIG);
            {
                {
                    static param_t endpoint;
                    init_param(&endpoint, CMD, "endpoint", NULL, NULL, INVALID, NULL, "endpoint");
                    libcli_register_param(&srv6, &endpoint);
                    {
                        /* . . . source-packet-routing srv6 endpoint end . . .*/
                        static param_t end;
                        init_param(&end, CMD, "end-sid", NULL, NULL,  INVALID, NULL, "end Endpoint");
                        libcli_register_param(&endpoint, &end);
                        {
                             /* . . . source-packet-routing srv6 endpoint end <ipv6-address> [flavor [psp |usp | usd] ]*/
                            static param_t ipv6_addr;
                            init_param(&ipv6_addr, LEAF, NULL, NULL , NULL, IPV6, "ipv6-address", "SRv6 prefix sid");
                            libcli_register_param(&end, &ipv6_addr);
                            //libcli_set_param_cmd_code(&ipv6_addr, CMD_CODE_END_SID_CONFIG);
                            srv6_flavor_cli_subtree_hookup(&ipv6_addr, CMD_CODE_END_SID_CONFIG, srv6_prefix_sid_config_handler );
                        }
                    }

                    {
                        /* config node <node-name> protocol source-packet-routing srv6 endpoint  end-x-sid  . .. */
                        static param_t end_x;
                        init_param(&end_x, CMD, "end-x-sid", NULL,
                                NULL, INVALID, NULL, "Configure SRv6 Endpoint: END-X");
                        libcli_register_param(&endpoint, &end_x);
                        {
                             /* . . . source-packet-routing srv6 endpoint end-x-sid <ipv6-address> ... */
                            static param_t ipv6_addr;
                            init_param(&ipv6_addr, LEAF, NULL,  NULL,  NULL, IPV6,  "ipv6-address", "SRv6 end-x-sid");
                            libcli_register_param(&end_x, &ipv6_addr);
                            {
                                /*config node <node-name> protocol source-packet-routing srv6 endpoint end-x-sid 
                                    <ipv6-address>  <oif-name> [flavor [psp |usp | usd] ]*/
                                static param_t oif_name;
                                init_param(&oif_name, LEAF, NULL, NULL, 
                                    NULL, STRING, "oif-name", "Outgoing Interface Name");
                                libcli_register_param(&ipv6_addr, &oif_name);
                                //libcli_set_param_cmd_code(&oif_name, IPV6_SRV6_ADJ_SID_CONFIG);
                                srv6_flavor_cli_subtree_hookup(&oif_name, 
                                    IPV6_SRV6_ADJ_SID_CONFIG, srv6_adjacency_sid_config_handler);
                            }
                        }
                    }

                    {
                        /* config node <node-name> protocol source-packet-routing srv6 endpoint 
                            end-b6-encaps segment-list <seg1> <seg2> <seg3> .... <segn> nexthop 
                            <oif-name> [flavor [psp | usp | usd ]] */
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
                            }                    
                        }                
                    }

                    {
                        /* config node <node-name> protocol source-packet-routing srv6 endpoint 
                        end-b6-x-encaps segment-list <seg1> <seg2> <seg3> .... <segn> nexthop 
                        <oif-name> [flavor [psp | usp | usd ]]*/
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
                                    }
                                }
                            }                    
                        }                
                    }

                }
                /* . . . source-packet-routing srv6 locator <loc-name> <ipv6-address> <prefix-len> */
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
                            {
                                static param_t algo;
                                init_param(&algo, CMD, "algorithm", NULL, NULL, INVALID, NULL, "Configure Flexible Algorithm");
                                libcli_register_param(&prefix_len, &algo);
                                {
                                    static param_t value;
                                    init_param(&value, LEAF, NULL, srv6_locator_handler, NULL, INT, "algorithm", "Flex Algo [0-128]");
                                    libcli_register_param(&algo, &value);
                                    libcli_set_param_cmd_code(&value, IPV6_SRV6_LOCATOR_CONFIG_ALGORITHM);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

static int
srv6_ping6_handler(int cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable)
{

    int i = 0;
    node_t *node;
    c_string node_name;
    c_string ipv6_addr_str[48];
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "segment"))
            ipv6_addr_str[i++] = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    srh_hdr_t *srh_hdr = NULL;
    pkt_block_t *pkt_block = NULL;

    /* Encode SRH header only when # of segment is > 1*/

    if (i > 1) {

        pkt_size_t srh_hdr_size = sizeof (srh_hdr_t ) + (i * 16);
        pkt_block = pkt_block_get_new_pkt_buffer (srh_hdr_size);
        pkt_block_set_starting_hdr_type (pkt_block, SRH_HDR);
        srh_hdr = (srh_hdr_t *)pkt_block_get_pkt(pkt_block, NULL);

        srh_hdr->nexthdr = ICMP6_PROTO;
        srh_hdr->hdrlen = srh_hdr_size;
        srh_hdr->type = 4;
        srh_hdr->segments_left = i -1;
        srh_hdr->first_segment = 0;
        srh_hdr->flags = 0;
        srh_hdr->tag = 0;

        for (int j = 0; j < i; j++)  
            inet_pton(AF_INET6, (const char *)ipv6_addr_str[j], srh_hdr->segments[i - j - 1]);
    }

    ipv6_addr_t dest_addr;
    inet_pton6 ((char *)ipv6_addr_str[0], &dest_addr);

    cp2dp_send_ip6_data (node, pkt_block, dest_addr, srh_hdr ? PROTO_SRH:ICMP6_PROTO );

    if (pkt_block) pkt_block_dereference (pkt_block);

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

extern int
srv6_show_handler(int cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable);

int
srv6_build_cli_show_tree (param_t *root)
{
        {
            static param_t srv6;
            init_param(&srv6, CMD, "srv6", NULL, NULL, INVALID, NULL, "SRv6 Ping");
            libcli_register_param(root, &srv6);
            {
                static param_t sid;
                init_param(&sid, CMD, "sid", srv6_show_handler, NULL, INVALID, NULL, "SRv6 SIDs");
                libcli_register_param(&srv6, &sid);
                libcli_set_param_cmd_code(&sid,  CMD_CODE_SHOW_SRV6_SIDS );
            }
        }
    return 0;
}

