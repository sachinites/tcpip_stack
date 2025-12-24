// config node <node-name> vrf vrf-name rd <rd-value> 
// config node <node-name> vrf vrf-name import-rt <rt-value>
// config node <node-name> vrf vrf-name export-rt <rt-value>

#include "../CLIBuilder/cmdtlv.h"
#include "../CLIBuilder/libcli.h"
#include "../graph.h"
#include <errno.h>
#include "vrf.h"

#define CMD_CODE_CONFIG_VRF_RD          1
#define CMD_CODE_CONFIG_VRF_IMPORT_RT   2
#define CMD_CODE_CONFIG_VRF_EXPORT_RT   3

extern graph_t *topo;

static int
validate_2B_4B_format(const char *str) {

    char *colon;
    char *endptr;
    unsigned long v1, v2;

    if (!str || !*str)
        return LEAF_VALIDATION_FAILED;

    /* Exactly one ':' */
    colon = (char *)strchr(str, ':');
    if (!colon || strchr(colon + 1, ':'))
        return LEAF_VALIDATION_FAILED;

    /* Validate first part (2B) */
    errno = 0;
    v1 = strtoul(str, &endptr, 10);
    if (errno || endptr != colon)
        return LEAF_VALIDATION_FAILED;

    if (v1 > 0xFFFF)
        return LEAF_VALIDATION_FAILED;

    /* Validate second part (4B) */
    errno = 0;
    v2 = strtoul(colon + 1, &endptr, 10);
    if (errno || *endptr != '\0')
        return LEAF_VALIDATION_FAILED;

    if (v2 > 0xFFFFFFFFUL)
        return LEAF_VALIDATION_FAILED;

    return LEAF_VALIDATION_SUCCESS;
}

static int
rd_validator_cbk (Stack_t *tlv_stack, unsigned char *value) {

    return validate_2B_4B_format((const char *)value);
}

static int
rt_target_validator_cbk(Stack_t *tlv_stack, unsigned char *value) {

    return validate_2B_4B_format((const char *)value);
}

static int 
vrf_config_handler (int cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable) {

    char temp_str[64];
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    c_string vrf_name = NULL;
    c_string import_rt = NULL;
    c_string export_rt = NULL;
    c_string rte_dist = NULL;


    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

    if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
        node_name = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
        vrf_name = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "import-rt"))
        import_rt = tlv->value;
    else if (parser_match_leaf_id(tlv->leaf_id, "export-rt"))
        export_rt = tlv->value;  
    else if (parser_match_leaf_id(tlv->leaf_id, "rte-distinguisher"))
        rte_dist = tlv->value;                           
     } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CMD_CODE_CONFIG_VRF_RD:
        {
            rd_t rd;
            char *endptr;
            char *colon;

            vrf_t *vrf = vrf_get_by_name (node, (char *)vrf_name);

            if (vrf) {
                cprintf ("Error : VRF already exists\n");
                return -1;
            }

            vrf = vrf_init (node, node_get_sequence_no(node), (char *)vrf_name);

            strncpy (temp_str, (const char *)rte_dist, sizeof (temp_str) - 1);
            colon = (char *)strchr(temp_str, ':');
            unsigned long v1 = strtoul(temp_str, &endptr, 10);
            unsigned long v2 = strtoul(colon + 1, &endptr, 10);
            rd.asn = (uint16_t)v1;
            rd.number = (uint32_t)v2;
            vrf->rd = rd;

            if (!node_register_vrf (node, vrf)) {
                cprintf ("Error : VRF Creation Failed, Max VRF limit reached\n");
                vrf_delete(vrf);
                return -1;
            }
        }
        break;
        case CMD_CODE_CONFIG_VRF_IMPORT_RT:
        break;
        case CMD_CODE_CONFIG_VRF_EXPORT_RT:
        break;
        default: ;
    }

    return 0;
}

int
vrf_build_config_tree (param_t *node_name) 
{
    {
        static param_t vrf;
        init_param(&vrf, CMD, "vrf", NULL, NULL, INVALID, NULL, "vrf configuration");
        libcli_register_param(node_name, &vrf);
        {
            static param_t vrf_name;
            init_param(&vrf_name, LEAF, NULL, NULL, NULL, STRING, "vrf-name", "vrf configuration");
            libcli_register_param(&vrf, &vrf_name);
            {
                static param_t rd;
                init_param(&rd, CMD, "route-distinguisher", NULL, NULL, INVALID, NULL, "Route Distinguisher");
                libcli_register_param(&vrf_name, &rd);
                {
                    //config node <node-name> vrf vrf-name rd <rd-value> 
                    static param_t rd_value;
                    init_param(&rd_value, LEAF, NULL, vrf_config_handler, rd_validator_cbk, STRING, "rte-distinguisher", "RD in : <2B:4B> fmt");
                    libcli_register_param(&rd, &rd_value);
                    libcli_set_param_cmd_code (&rd_value, CMD_CODE_CONFIG_VRF_RD);
                }                
            }
            {
                //config node <node-name> vrf vrf-name import-rt . . .
                static param_t import_rt;
                init_param(&import_rt, CMD, "import-rt", NULL, NULL, INVALID, NULL, "Import Route-Target");
                libcli_register_param(&vrf_name, &import_rt);
                {
                    //config node <node-name> vrf vrf-name import-rt <rt-value>
                    static param_t import_rt_val;
                    init_param(&import_rt_val, LEAF, NULL, vrf_config_handler, rt_target_validator_cbk, STRING, "import-rt", "RT value in : <2B:4B> fmt");
                    libcli_register_param(&import_rt, &import_rt_val);
                    libcli_set_param_cmd_code (&import_rt_val, CMD_CODE_CONFIG_VRF_IMPORT_RT);
                }  
            }

            {
                //config node <node-name> vrf vrf-name export-rt . . .
                static param_t export_rt;
                init_param(&export_rt, CMD, "export-rt", NULL, NULL, INVALID, NULL, "Export Route-Target");
                libcli_register_param(&vrf_name, &export_rt);
                {
                    //config node <node-name> vrf vrf-name export-rt <rt-value>
                    static param_t export_rt_val;
                    init_param(&export_rt_val, LEAF, NULL, vrf_config_handler, rt_target_validator_cbk, STRING, "export-rt", "RT value in : <2B:4B> fmt");
                    libcli_register_param(&export_rt, &export_rt_val);
                    libcli_set_param_cmd_code (&export_rt_val, CMD_CODE_CONFIG_VRF_EXPORT_RT);
                }  
            }
        }
    }
    return 0;
}