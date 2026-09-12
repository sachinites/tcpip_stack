// config node <node-name> vrf <vrf-name>
// config node <node-name> vrf <vrf-name> import-rt <ipv4-address> <uint16>
// config node <node-name> vrf <vrf-name> export-rt <ipv4-address> <uint16>

#include "../CLIBuilder/cmdtlv.h"
#include "../CLIBuilder/libcli.h"
#include "../lmm_enums.h"
#include "../router_init.h"
#include "../cmdcodes.h"
#include <errno.h>
#include "vrf.h"
#include "../RTM/rtm_priv_api.h"
#include "../RTM/rtm_nb_integ.h"
#include "../dpal/cp2dp.h"

#define CMD_CODE_CONFIG_VRF_CREATE          1
#define CMD_CODE_CONFIG_VRF_IMPORT_RT   2
#define CMD_CODE_CONFIG_VRF_EXPORT_RT   3
#define CMD_CODE_SHOW_VRF               4

extern graph_t *topo;


void 
display_cbk_all_vrfs(param_t *param, Stack_t *tlv_stack) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (!node) {
        return;
    }

    int i;

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {
        
        if (!node->vrf[i]) continue;
        
        vrf_t *vrf = node->vrf[i];
        printw(" %s\n", vrf->vrf_name);
    }
}

int 
validate_vrf_existence(Stack_t *tlv_stack, unsigned char *leaf_value) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (!node) {
        return LEAF_VALIDATION_FAILED;
    }

    vrf_t *vrf = vrf_get_by_name(node, (char *)leaf_value);

    if (!vrf) {
        return LEAF_VALIDATION_FAILED;
    }

    return LEAF_VALIDATION_SUCCESS;
}

int
show_vrf_handler(int64_t cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    (void)cmdcode;
    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    show_vrfs(node);
    return 0;
}

/* Type-1 RT assigned number is a 16-bit integer. */
static int
rt_type1_assigned_validator_cbk(Stack_t *tlv_stack, unsigned char *value)
{
    char *endptr;
    unsigned long v;

    (void)tlv_stack;

    if (!value || !*value) {
        return LEAF_VALIDATION_FAILED;
    }

    errno = 0;
    v = strtoul((const char *)value, &endptr, 10);
    if (errno || endptr == (const char *)value || *endptr != '\0') {
        return LEAF_VALIDATION_FAILED;
    }
    if (v > 0xFFFFUL) {
        return LEAF_VALIDATION_FAILED;
    }

    return LEAF_VALIDATION_SUCCESS;
}

static int 
vrf_config_handler (int64_t cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    c_string vrf_name = NULL;
    c_string rt_ip = NULL;
    c_string rt_assigned = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

    if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
        node_name = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
        vrf_name = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "import-rt-ip") ||
             parser_match_leaf_id(tlv->leaf_id, "export-rt-ip"))
        rt_ip = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "import-rt-asn") ||
             parser_match_leaf_id(tlv->leaf_id, "export-rt-asn"))
        rt_assigned = tlv->value;
     } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CMD_CODE_CONFIG_VRF_CREATE:
        {
            rd_t rd;

            vrf_t *vrf = vrf_get_by_name(node, (char *)vrf_name);

            switch (enable_or_disable)
            {
                case CONFIG_ENABLE:
                {
                    if (vrf)
                    {
                        cprintf("Error : VRF already exists\n");
                        return -1;
                    }
                    
                    int vrf_id = vrf_alloc_new_vrf_id (node);

                    if (vrf_id < 0) {
                        cprintf ("Error : Max VRF Reached\n");
                        return -1;
                    }

                    vrf_t *vrf = (vrf_t *)XCALLOC2(0, 1, vrf_t);
                    vrf = vrf_init(node, (uint8_t)vrf_id, (char *)vrf_name, vrf);

                    rd.type = 1;
                    rd.rtr_id = NODE_RTR_ID_INT(node);
                    rd.vrf_id = (uint16_t)vrf_id;
                    vrf->rd = rd;

                    /* Generate import/export RT (Type-1: IPv4:uint16) */
                    rt_type1_fill(&vrf->import_rt,
                                  0,
                                  (uint16_t)vrf_id);
                    vrf->export_rt = vrf->import_rt;

                    if (!node_register_vrf(node, vrf))
                    {
                        cprintf("Error : VRF Creation Failed, Max VRF limit reached\n");
                        vrf_delete(vrf, true);
                        return -1;
                    }
                    cp2dp_vrf_create(node, (char *)vrf_name, vrf->vrf_id);
                    rtm_install_xconnect_vpnv4_route (vrf, true);
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV4, vrf->vrf_id, true);
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV6, vrf->vrf_id, true);
                }
                break;
                case CONFIG_DISABLE:
                {
                    //cp2dp_vpnv4_steering_interface_delete(node);
                    //cp2dp_vrf_delete(node, vrf->vrf_id);
                }
                break;
            }
        }
        break;
        case CMD_CODE_CONFIG_VRF_IMPORT_RT:
        {
            vrf_t *vrf = vrf_get_by_name (node, (char *)vrf_name);
            rt_t new_import_rt;
            
            if (!vrf) {
                cprintf("Error : VRF %s not found\n", vrf_name);
                return -1;
            }

            if (vrf == node->vrf[0]) {
                cprintf ("Error : Operation not allowed on Default vrf\n");
                return -1;
            }

            if (!rt_ip || !rt_assigned) {
                cprintf("Error : Type-1 import-rt requires "
                        "<ipv4-address> <uint16>\n");
                return -1;
            }

            rt_type1_fill(&new_import_rt,
                          tcp_ip_convert_ip_p_to_n((char *)rt_ip),
                          (uint16_t)strtoul((const char *)rt_assigned,
                                            NULL, 10));

            switch (enable_or_disable) {
                
                case CONFIG_ENABLE:
                {
                    /* Check if import RT has changed */
                    if (vrf->import_rt.rtr_id == new_import_rt.rtr_id &&
                        vrf->import_rt.vrf_id == new_import_rt.vrf_id &&
                        vrf->import_rt.type == new_import_rt.type) {
                        return 0;
                    }
                    
                    /* Import RT has changed - update it */
                    vrf->import_rt = new_import_rt;
                    
                    /* Flush existing BGP VPN routes from VRF RIBs */
                    cp_rtm_uninstall_routes_by_proto(vrf->inet0, RTM_PROTO_BGP, RTM_PROTO_BGP_VPN, 0);
                    cp_rtm_uninstall_routes_by_proto(vrf->inet6, RTM_PROTO_BGP, RTM_PROTO_BGP_VPN, 0);
                    
                    /* Re-import routes with new import RT */
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV4, vrf->vrf_id, true);
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV6, vrf->vrf_id, true);
                }
                break;
                
                case CONFIG_DISABLE:
                {
                    /* Check if import RT was configured */
                    if (vrf->import_rt.rtr_id == 0 && vrf->import_rt.vrf_id == 0) {
                        return 0;
                    }

                    if (new_import_rt.rtr_id != vrf->import_rt.rtr_id ||
                        new_import_rt.vrf_id != vrf->import_rt.vrf_id) {
                        cprintf ("Error : Mis-matched Route Import value specified\n");
                        return -1;
                    }
                    
                    /* Clear the import RT (restore default Type-1) */
                    rt_type1_fill(&vrf->import_rt,
                                  NODE_RTR_ID_INT(node),
                                  vrf->vrf_id);
                    
                    /* Flush existing BGP VPN routes from VRF RIBs */
                    cp_rtm_uninstall_routes_by_proto(vrf->inet0, RTM_PROTO_BGP, RTM_PROTO_BGP_VPN, 0);
                    cp_rtm_uninstall_routes_by_proto(vrf->inet6, RTM_PROTO_BGP, RTM_PROTO_BGP_VPN, 0);
                    
                    /* Re-import routes with restored import RT */
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV4, vrf->vrf_id, true);
                    rtm_copy_l3vpn_to_vrf_client_ribs(node, AF_IPV6, vrf->vrf_id, true);
                }
                break;
                
                default:
                    ;
            }
        }
        break;
        case CMD_CODE_CONFIG_VRF_EXPORT_RT:
        {
            vrf_t *vrf = vrf_get_by_name (node, (char *)vrf_name);
            rt_t new_export_rt;
            
            if (!vrf) {
                cprintf("Error : VRF %s not found\n", vrf_name);
                return -1;
            }

            if (vrf == node->vrf[0]) {
                cprintf ("Error : Operation not allowed on Default vrf\n");
                return -1;
            }

            if (!rt_ip || !rt_assigned) {
                cprintf("Error : Type-1 export-rt requires "
                        "<ipv4-address> <uint16>\n");
                return -1;
            }

            rt_type1_fill(&new_export_rt,
                          tcp_ip_convert_ip_p_to_n((c_string)rt_ip),
                          (uint16_t)strtoul((const char *)rt_assigned,
                                            NULL, 10));

            switch (enable_or_disable) {
                
                case CONFIG_ENABLE:
                {
                    /* Check if export RT has changed */
                    if (vrf->export_rt.rtr_id == new_export_rt.rtr_id &&
                        vrf->export_rt.vrf_id == new_export_rt.vrf_id &&
                        vrf->export_rt.type == new_export_rt.type) {
                        return 0;
                    }
                    
                    /* Export RT has changed - update it */
                    vrf->export_rt = new_export_rt;
                    
                    #if 0
                        ToDo :
                        Pull Soln : Ask BGP to flush all routes with this RD value, and re-export again
                        since export RT of this VRF is changed
                        Push Soln : Send Delete notif to BGP for all routes in this VRF with old RD as a key
                        then push all routes again with new RD value.
                    #endif
                }
                break;
                
                case CONFIG_DISABLE:
                {
                    if (vrf->export_rt.rtr_id == 0 && vrf->export_rt.vrf_id == 0) {
                        return 0;
                    }

                    if (new_export_rt.rtr_id != vrf->export_rt.rtr_id ||
                        new_export_rt.vrf_id != vrf->export_rt.vrf_id) {
                        cprintf ("Error : Mis-matched Route Export value specified\n");
                        return -1;
                    }
                    
                    /* Clear the export RT (restore default Type-1) */
                    rt_type1_fill(&vrf->export_rt,
                                  NODE_RTR_ID_INT(node),
                                  vrf->vrf_id);
                
                    #if 0
                        ToDo : 
                        Pull Soln : Ask BGP to flush all routes with this RD value, and re-export again 
                        since export RT of this VRF is changed
                        Push Soln : Send Delete notif to BGP for all routes in this VRF with old RD as a key 
                        then push all routes again with new RD value.
                    #endif 
                }
                break;
                
                default:
                    ;
            }
        }
        break;
        default: ;
    }

    return 0;
}

param_t *
vrf_build_config_tree (param_t *node_name) 
{
    param_t *vrf_param_ptr = NULL;

    {
        static param_t vrf;
        init_param(&vrf, CMD, "vrf", NULL, NULL, INVALID, NULL, "vrf configuration");
        libcli_register_param(node_name, &vrf);
        {
            static param_t vrf_name;
            init_param(&vrf_name, LEAF, NULL, vrf_config_handler, 0, STRING, "vrf-name", "vrf configuration");
            libcli_register_param(&vrf, &vrf_name);
            libcli_register_display_callback(&vrf_name, display_cbk_all_vrfs);
            libcli_set_param_cmd_code (&vrf_name, CMD_CODE_CONFIG_VRF_CREATE);
            vrf_param_ptr = &vrf_name;

            {
                /* config node <node-name> vrf <vrf-name> import-rt
                 *   <ipv4-address> <uint16> */
                static param_t import_rt;
                init_param(&import_rt, CMD, "import-rt", NULL, NULL, INVALID, NULL,
                           "Import Route-Target (Type-1)");
                libcli_register_param(&vrf_name, &import_rt);
                {
                    static param_t import_rt_ip;
                    init_param(&import_rt_ip, LEAF, NULL, 0, 0, IPV4,
                               "import-rt-ip",
                               "Type-1 RT administrator (IPv4 address)");
                    libcli_register_param(&import_rt, &import_rt_ip);
                    {
                        static param_t import_rt_asn;
                        init_param(&import_rt_asn, LEAF, NULL,
                                   vrf_config_handler,
                                   rt_type1_assigned_validator_cbk, INT,
                                   "import-rt-asn",
                                   "Type-1 RT assigned number (0-65535)");
                        libcli_register_param(&import_rt_ip, &import_rt_asn);
                        libcli_set_param_cmd_code(&import_rt_asn,
                                                  CMD_CODE_CONFIG_VRF_IMPORT_RT);
                    }
                }
            }

            {
                /* config node <node-name> vrf <vrf-name> export-rt
                 *   <ipv4-address> <uint16> */
                static param_t export_rt;
                init_param(&export_rt, CMD, "export-rt", NULL, NULL, INVALID, NULL,
                           "Export Route-Target (Type-1)");
                libcli_register_param(&vrf_name, &export_rt);
                {
                    static param_t export_rt_ip;
                    init_param(&export_rt_ip, LEAF, NULL, 0, 0, IPV4,
                               "export-rt-ip",
                               "Type-1 RT administrator (IPv4 address)");
                    libcli_register_param(&export_rt, &export_rt_ip);
                    {
                        static param_t export_rt_asn;
                        init_param(&export_rt_asn, LEAF, NULL,
                                   vrf_config_handler,
                                   rt_type1_assigned_validator_cbk, INT,
                                   "export-rt-asn",
                                   "Type-1 RT assigned number (0-65535)");
                        libcli_register_param(&export_rt_ip, &export_rt_asn);
                        libcli_set_param_cmd_code(&export_rt_asn,
                                                  CMD_CODE_CONFIG_VRF_EXPORT_RT);
                    }
                }
            }
        }
    }
    return vrf_param_ptr;
}
