#include <stdio.h>
#include <string.h>

#include "../../libs/Tracer/tracer.h"

#include "bgp_rib_vpnv4.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

#include "../bgp_route.h"
#include "../bgp_rtr.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../RTM/rtm.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_error.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../RTM/rtm_proto.h"
#include "../../router_init.h"
#include "../bgp_enums.h"

static void
format_ipv4(uint32_t addr, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%u.%u.%u.%u",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 8) & 0xff,
             addr & 0xff);
}

static uint8_t
ipv4_prefix_byte_count(uint8_t prefix_len)
{
    return (uint8_t)((prefix_len + 7) / 8);
}

static void
encode_rd_type1(const rd_t *rd, uint8_t out[8])
{
    out[0] = 0x00;
    out[1] = 0x01;
    out[2] = (uint8_t)((rd->rtr_id >> 24) & 0xff);
    out[3] = (uint8_t)((rd->rtr_id >> 16) & 0xff);
    out[4] = (uint8_t)((rd->rtr_id >> 8) & 0xff);
    out[5] = (uint8_t)(rd->rtr_id & 0xff);
    out[6] = (uint8_t)((rd->vrf_id >> 8) & 0xff);
    out[7] = (uint8_t)(rd->vrf_id & 0xff);
}

static bgp_rib_err_t
decode_rd_wire(const uint8_t in[8], rd_t *rd_out)
{
    uint16_t rd_type = (uint16_t)((in[0] << 8) | in[1]);

    memset(rd_out, 0, sizeof(*rd_out));
    rd_out->type = rd_type;

    switch (rd_type) {
    case 0x0000: /* 2-octet ASN : 4-octet assigned */
        rd_out->rtr_id = (uint32_t)((in[2] << 8) | in[3]);
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    case 0x0001: /* IPv4 : 2-octet assigned */
        rd_out->rtr_id = ((uint32_t)in[2] << 24) |
                         ((uint32_t)in[3] << 16) |
                         ((uint32_t)in[4] << 8) |
                         (uint32_t)in[5];
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    case 0x0002: /* 4-octet ASN : 2-octet assigned */
        rd_out->rtr_id = ((uint32_t)in[2] << 24) |
                         ((uint32_t)in[3] << 16) |
                         ((uint32_t)in[4] << 8) |
                         (uint32_t)in[5];
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    default:
        return BGP_RIB_ERR_DECODE;
    }
}

bgp_rib_err_t
bgp_vpnv4_nlri_encode(const bgp_vpnv4_nlri_t *nlri,
                      bgp_nlri_key_t *key_out)
{
    uint8_t prefix_bytes;
    uint16_t offset;

    if (!nlri || !key_out || nlri->prefix_len > 32) {
        return BGP_RIB_ERR_NULL;
    }

    prefix_bytes = ipv4_prefix_byte_count(nlri->prefix_len);
    offset = 0;

    encode_rd_type1(&nlri->rd, &key_out->wire[offset]);
    offset += 8;

    key_out->wire[offset++] = nlri->prefix_len;

    {
        uint32_t v = nlri->prefix;
        uint8_t i;

        for (i = 0; i < prefix_bytes; i++) {
            key_out->wire[offset++] =
                (uint8_t)((v >> (24 - (i * 8))) & 0xff);
        }
    }

    if (nlri->label_present) {
        /* RFC 8277: 20-bit label in high-order bits of 3 octets; BoS in LSB. */
        uint32_t entry = ((nlri->label & 0xfffff) << 4) | 0x1;

        key_out->wire[offset++] = (uint8_t)((entry >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((entry >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)(entry & 0xff);
    }

    key_out->wire_len = offset;
    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_vpnv4_nlri_decode(const bgp_nlri_key_t *key,
                      bgp_vpnv4_nlri_t *nlri_out)
{
    uint8_t prefix_bytes;
    uint16_t offset = 0;
    uint8_t i;

    if (!key || !nlri_out || key->wire_len < 9) {
        return BGP_RIB_ERR_NULL;
    }

    memset(nlri_out, 0, sizeof(*nlri_out));

    if (decode_rd_wire(&key->wire[offset], &nlri_out->rd) != BGP_RIB_OK) {
        return BGP_RIB_ERR_DECODE;
    }
    offset += 8;

    nlri_out->prefix_len = key->wire[offset++];
    if (nlri_out->prefix_len > 32) {
        return BGP_RIB_ERR_DECODE;
    }

    prefix_bytes = ipv4_prefix_byte_count(nlri_out->prefix_len);
    if (key->wire_len < offset + prefix_bytes) {
        return BGP_RIB_ERR_DECODE;
    }

    for (i = 0; i < prefix_bytes; i++) {
        nlri_out->prefix =
            (nlri_out->prefix << 8) | key->wire[offset + i];
    }
    nlri_out->prefix <<= (32 - nlri_out->prefix_len);
    offset += prefix_bytes;

    if (key->wire_len >= offset + 3) {
        nlri_out->label =
            ((uint32_t)key->wire[offset] << 12) |
            ((uint32_t)key->wire[offset + 1] << 4) |
            ((uint32_t)key->wire[offset + 2] >> 4);
        nlri_out->label_present = true;
    }

    return BGP_RIB_OK;
}

int
bgp_vpnv4_nlri_format_bracket(const bgp_nlri_key_t *key,
                              char *buf,
                              size_t buflen)
{
    char rd_str[48];
    char prefix_str[32];
    uint8_t prefix_len;
    uint8_t prefix_bytes;
    uint16_t offset;
    uint32_t prefix = 0;
    uint8_t i;

    if (!key || !buf || buflen == 0 || key->wire_len < 9) {
        return -1;
    }

    /* RD may be type 0/1/2 from GoBGP; do not require type-1-only decode. */
    if (bgp_rd_wire_to_str(&key->wire[0], rd_str, sizeof(rd_str)) != 0) {
        return -1;
    }

    offset = 8;
    prefix_len = key->wire[offset++];
    if (prefix_len > 32) {
        return -1;
    }

    prefix_bytes = ipv4_prefix_byte_count(prefix_len);
    if (key->wire_len < offset + prefix_bytes) {
        return -1;
    }

    for (i = 0; i < prefix_bytes; i++) {
        prefix = (prefix << 8) | key->wire[offset + i];
    }
    if (prefix_len < 32) {
        prefix <<= (32 - prefix_len);
    }

    format_ipv4(prefix, prefix_str, sizeof(prefix_str));
    {
        size_t used = strlen(prefix_str);
        snprintf(prefix_str + used, sizeof(prefix_str) - used,
                 "/%u", prefix_len);
    }

    /*
     * Display length = RD (64 bits) + IPv4 prefix length.
     * Do not use raw wire_len (includes prefix-len byte and MPLS label).
     * Example: host route → 64 + 32 = 96.
     */
    snprintf(buf, buflen, "[%s][%s]/%u",
             rd_str, prefix_str, (unsigned)(64 + prefix_len));
    return 0;
}

int
bgp_vpnv4_nlri_format_compact(const bgp_nlri_key_t *key,
                              const bgp_rib_attrs_t *attrs,
                              char *buf,
                              size_t buflen)
{
    bgp_vpnv4_nlri_t nlri;
    char rd_str[32];
    char prefix_str[32];

    if (!key || !buf || buflen == 0) {
        return -1;
    }

    if (bgp_vpnv4_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return -1;
    }

    bgp_rd_wire_to_str(&key->wire[0], rd_str, sizeof(rd_str));
    format_ipv4(nlri.prefix, prefix_str, sizeof(prefix_str));
    {
        size_t used = strlen(prefix_str);
        snprintf(prefix_str + used, sizeof(prefix_str) - used,
                 "/%u", nlri.prefix_len);
    }

    if (nlri.label_present) {
        snprintf(buf, buflen,
                 "rd=%s prefix=%s label=%u nlri_len=%u",
                 rd_str, prefix_str, nlri.label,
                 bgp_nlri_key_bit_length(key));
    } else {
        snprintf(buf, buflen,
                 "rd=%s prefix=%s nlri_len=%u",
                 rd_str, prefix_str, bgp_nlri_key_bit_length(key));
    }

    if (attrs && attrs->nexthop[0] != '\0') {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
        used = strlen(buf);
        if (attrs->med_present && used < buflen) {
            snprintf(buf + used, buflen - used, " med=%u", attrs->med);
        }
    }

    return 0;
}

int
bgp_vpnv4_ipv4_unicast_format_compact(const bgp_nlri_key_t *key,
                                       const bgp_rib_attrs_t *attrs,
                                       char *buf,
                                       size_t buflen)
{
    uint8_t prefix_len;
    uint8_t prefix_bytes;
    uint32_t prefix = 0;
    char prefix_str[32];
    uint8_t i;

    if (!key || key->wire_len < 1 || !buf || buflen == 0) {
        return -1;
    }

    prefix_len = key->wire[0];
    prefix_bytes = ipv4_prefix_byte_count(prefix_len);
    if (key->wire_len < 1 + prefix_bytes) {
        return -1;
    }

    for (i = 0; i < prefix_bytes; i++) {
        prefix = (prefix << 8) | key->wire[1 + i];
    }
    prefix <<= (32 - prefix_len);

    format_ipv4(prefix, prefix_str, sizeof(prefix_str));
    {
        size_t used = strlen(prefix_str);
        snprintf(prefix_str + used, sizeof(prefix_str) - used,
                 "/%u", prefix_len);
    }
    snprintf(buf, buflen, "prefix=%s nlri_len=%u",
             prefix_str, bgp_nlri_key_bit_length(key));

    if (attrs && attrs->nexthop[0] != '\0') {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
    }

    return 0;
}

bgp_rib_err_t
bgp_vpnv4_rib_route_add(bgp_rib_t *rib,
                        const bgp_vpnv4_nlri_t *nlri,
                        const bgp_rib_attrs_t *attrs)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri || !attrs) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_add(rib, &key, attrs);
}

bgp_rib_err_t
bgp_vpnv4_rib_route_delete(bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_delete(rib, &key);
}

const bgp_rib_attrs_t *
bgp_vpnv4_rib_route_lookup(const bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return NULL;
    }

    return bgp_rib_route_lookup(rib, &key);
}

void
bgp_vpnv4_nlri_key_to_cmn_prefix(bgp_nlri_key_t *key,
                                 cmn_prefix_t *cmn_prefix)
{
    bgp_vpnv4_nlri_t nlri;

    if (!cmn_prefix) {
        return;
    }

    memset(cmn_prefix, 0, sizeof(*cmn_prefix));
    if (!key) {
        return;
    }

    if (bgp_vpnv4_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return;
    }

    cmn_prefix_initialize_v4(cmn_prefix, nlri.prefix, nlri.prefix_len);
}

/* Similar to bgp_route_build_vpn_nh_template */
bool
bgp_vpnv4_build_nh_template(bgp_nlri_key_t *key,
                            bgp_rib_attrs_t *attrs,
                            cp_nexthop_template_t *cp_nh_template)
{
    char nh_cidr[72];
    cmn_prefix_t gateway;
    rt_t import_rt;
    bgp_vpnv4_nlri_t nlri;
    rtm_error_t rc;

    memset(cp_nh_template, 0, sizeof(*cp_nh_template));

    if (bgp_vpnv4_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return false;
    }

    if (attrs->nexthop[0] == '\0') {
        return false;
    }

    if (strchr(attrs->nexthop, '/')) {
        strncpy(nh_cidr, attrs->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", attrs->nexthop);
    }

    if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
        gateway.afi != AF_IPV4) {
        return false;
    }

    if (!bgp_route_parse_rt_string(attrs->import_rt, &import_rt)) {
        return false;
    }

    cp_nh_template->is_indirect = true;
    cp_nh_template->is_resolved = false;
    cp_nh_template->proto = RTM_PROTO_BGP;
    cp_nh_template->sub_proto = RTM_SUB_PROTO_BGP_VPN;
    cp_nh_template->action = RTM_NH_ACTION_FORWARD;
    cp_nh_template->metric = attrs->med_present ? attrs->med : 0;
    cp_nh_template->import_rt = import_rt;
    if (nlri.label_present && nlri.label) {
        cp_nh_template->vpn_label = (mpls_label_val_t)nlri.label;
    }
    memcpy(&cp_nh_template->gateway, &gateway, sizeof(gateway));

    rc = rtm_nh_proto_info_create(RTM_PROTO_BGP,
                                  RTM_SUB_PROTO_BGP_VPN,
                                  0,
                                  RTM_DEFAULT_VRF,
                                  &cp_nh_template->rtm_nh_proto);
    if (rc != RTM_SUCCESS) {
        memset(cp_nh_template, 0, sizeof(*cp_nh_template));
    }

    return true;
}

void 
bgp_global_rib_export_vpnv4_route_cb(     
                                   void *ctx,
                                   uint8_t afi,
                                   uint8_t safi,
                                   bgp_nlri_key_t *key,
                                   bgp_rib_attrs_t *attrs,
                                   bool is_add,
                                   uint16_t target_vrf_id)
{
    int i; 
    vrf_t *vrf;
    rtm_error_t rc;
    char nh_str[48];
    char route_str[48];
    rtm_t *vpnv4_cust_rtm;
    cmn_prefix_t cmn_prefix;
    cp_nexthop_template_t cp_nh_template;
    bgp_inst_t *bgp_inst = (bgp_inst_t *)ctx;
    node_t *node = bgp_inst->node;

    /* Now install this route in all customer VRF RIBs whose 
        route target matches */
    
    /* Reject the self advertised routes */
    {
        uint32_t nh_int = ip_pton((c_string)attrs->nexthop);
        if (nh_int == 0 || (nh_int == NODE_RTR_ID_INT(node))) return;
    }

    /* Derieve internal AFI from standardized AFI */
    AFI_T vpnv4_cust_rtm_afi = (afi == AFI_IPV4) ? AF_IPV4 : AF_IPV6;

    bgp_vpnv4_nlri_key_to_cmn_prefix(key, &cmn_prefix);
    rtm_format_prefix(&cmn_prefix, route_str, sizeof (route_str));

    if (!bgp_vpnv4_build_nh_template (key, attrs, &cp_nh_template)) {

        tracer (bgp_inst->tr, DRTM|DERR, 
            "%s : [%s] : Route %s, Failed to build nh_template, %sInstallation Failed\n", 
            BGP_RTM_IM, 
            BGP_VPN_V4_RIB_NAME, 
            route_str, 
            is_add ? "" : "Un");

        tracer (node->cptr, DRTM|DERR, 
            "%s : [%s] : Route %s, Failed to build nh_template, %sInstallation Failed\n", 
            BGP_RTM_IM, 
            BGP_VPN_V4_RIB_NAME, 
            route_str, 
            is_add ? "" : "Un");

        return;
    }

    rtm_format_nexthop(&cp_nh_template.gateway, nh_str, sizeof(nh_str));

    tracer (bgp_inst->tr, DRTM_DET, 
            "%s : [%s] : Route %s, nh_template is successfully build, op=%s\n", 
            BGP_RTM_IM, 
            BGP_VPN_V4_RIB_NAME, 
            route_str, 
            is_add ? "Add" : "Del");   
            
    tracer (node->cptr, DRTM_DET, 
            "%s : [%s] : Route %s, nh_template is successfully build, op=%s\n", 
            BGP_RTM_IM, 
            BGP_VPN_V4_RIB_NAME, 
            route_str, 
            is_add ? "Add" : "Del");  

    if (target_vrf_id == 0) {

        /* Now install the vpnv4 route to all client vpnv4 RIBs */
        for (i = 1; i < MAX_VRF_PER_NODE; i++) {

            if (!node->vrf[i]) continue;

            vrf = node->vrf[i];
            
            vpnv4_cust_rtm = rtm_get(node, vrf->vrf_id, vpnv4_cust_rtm_afi, 0);
            if (!vpnv4_cust_rtm ) continue;

            /* Now match Route target */
            if (vrf->import_rt.rtr_id == cp_nh_template.import_rt.rtr_id &&
                vrf->import_rt.vrf_id == cp_nh_template.import_rt.vrf_id) {
                    
                if (is_add) {
                    rc = cp_rtm_install_route ( vpnv4_cust_rtm,  &cmn_prefix, &cp_nh_template);
                }
                else {
                    rc = cp_rtm_uninstall_route ( vpnv4_cust_rtm,  &cmn_prefix, &cp_nh_template);
                }

                tracer (node->cptr, DRTM_DET, 
                    "RTM[%s] : L3 VPN Route %s, %s %sInstalled in Client, Result : %s\n",
                    vpnv4_cust_rtm->name, route_str, nh_str, 
                    is_add ? "" : "Un",
                    rtm_error_to_string(rc));            
            }
        }
        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    /* (Un)Install the route to/from a particular client rtm which belongs to target_vrf_id*/
    vrf = vrf_get_by_id(node, (uint8_t)target_vrf_id);
    if (!vrf) {
        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    vpnv4_cust_rtm = rtm_get(node, target_vrf_id, vpnv4_cust_rtm_afi, 0);

    if (!vpnv4_cust_rtm) {
        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    if (vrf->import_rt.rtr_id == cp_nh_template.import_rt.rtr_id &&
        vrf->import_rt.vrf_id == cp_nh_template.import_rt.vrf_id)
    {
        if (is_add)
        {
            rc = cp_rtm_install_route(vpnv4_cust_rtm, &cmn_prefix, &cp_nh_template);
        }
        else
        {
            rc = cp_rtm_uninstall_route(vpnv4_cust_rtm, &cmn_prefix, &cp_nh_template);
        }

        tracer(node->cptr, DRTM_DET,
               "RTM[%s] : L3 VPN Route %s, %s %sInstalled in Client, Result : %s\n",
               vpnv4_cust_rtm->name, route_str, nh_str,
               is_add ? "" : "Un",
               rtm_error_to_string(rc));
    }

    rtm_nh_template_free_internals(&cp_nh_template);
}