#include <assert.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_sr.h"
#include "isis_advt.h"
#include "isis_tlv_struct.h"
#include "isis_spf.h"
#include "isis_events.h"
#include "../../libs/Tracer/tracer.h"
#include "../SegmentRouting/SR-MPLS/srgb.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../ted/ted.h"
#include "../../LabelMgr/label_mgr.h"

isis_srmpls_config_t *
isis_sr_mpls_get_config (isis_node_info_t *node_info) {

    if (!node_info) return NULL;

    return node_info->srmpls_config;
}

bool
isis_sr_mpls_is_enabled (isis_node_info_t *node_info) {

    return (isis_sr_mpls_get_config(node_info) != NULL);
}

/* Advertise a stand-alone Router CAPABILITY TLV(242) carrying the
    SR-Algorithm SubTLV(19) + SR-MPLS SR-Capability SubTLV ( SRGB ) */
static void
isis_sr_mpls_advertise_rtr_cap_tlv242 (isis_node_info_t *node_info) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_srmpls_config_t *sr_config = node_info->srmpls_config;

    assert (!sr_config->rtr_cap_adv_data_tlv242);

    advt_data = (isis_adv_data_t *)XCALLOC2(0, 1, isis_adv_data_t);
    sr_config->rtr_cap_adv_data_tlv242 = advt_data;

    advt_data->tlv_no = ISIS_TLV_RTR_CAP;
    advt_data->flags = 0;
    advt_data->fragment = NULL;
    advt_data->src.holder = &sr_config->rtr_cap_adv_data_tlv242;
    init_glthread(&advt_data->glue);

    advt_data->u.rtr_cap.rtr_cap.rtr_id = NODE_LO_ADDR_INT(node_info->vrf->node);
    advt_data->u.rtr_cap.rtr_cap.flags = 0;

    /* SR-Algorithm SubTLV(19) - Generic to Segment Routing, shared numbering
        with SRv6 ( see isis_srv6.cpp ) */
    advt_data->u.rtr_cap.is_rtr_cap_algo_subtlv19_present = true;
    advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.type = ISIS_TLV_RTR_CAP_ALGO_SUBTLV;
    advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.length = 16;
    advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.algorithms[0] = SPF_ALOGORITHM;
    advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.algorithms[1] = SPF_STRICT_ALOGORITHM;

    /* SR-MPLS SR-Capability SubTLV : Advertise the SRGB owned by this router */
    advt_data->u.rtr_cap.is_rtr_cap_sr_cap_subtlv_present = true;
    advt_data->u.rtr_cap.rtr_cap_sr_cap_subtlv.type = ISIS_TLV_RTR_CAP_SR_CAP_SUBTLV;
    advt_data->u.rtr_cap.rtr_cap_sr_cap_subtlv.length =
        sizeof (isis_rtr_cap_sr_cap_subtlv_t) - TLV_OVERHEAD_SIZE;
    advt_data->u.rtr_cap.rtr_cap_sr_cap_subtlv.flags = SR_CAP_SUBTLV_FLAG_I;
    advt_data->u.rtr_cap.rtr_cap_sr_cap_subtlv.srgb_base = srgb_get_base_label(sr_config->srgb);
    advt_data->u.rtr_cap.rtr_cap_sr_cap_subtlv.srgb_range = srgb_get_range_size(sr_config->srgb);

    /* Calculate the size of the TLV */
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    /* Advertise the TLV */
    isis_advertise_tlv(node_info, 0, advt_data, &advt_info);
}

static void
isis_sr_mpls_withdraw_rtr_cap_tlv242 (isis_node_info_t *node_info) {

    isis_adv_data_t *advt_data;
    isis_srmpls_config_t *sr_config = node_info->srmpls_config;

    advt_data = sr_config->rtr_cap_adv_data_tlv242;
    if (!advt_data) return;

    if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED)) {
        isis_withdraw_tlv_advertisement(node_info, advt_data);
    }
    else if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED)) {
        isis_wait_list_advt_data_remove(node_info, advt_data);
    }

    isis_advt_data_clear_backlinkage(node_info, advt_data);
    isis_free_advt_data(advt_data);
    assert (!sr_config->rtr_cap_adv_data_tlv242);
}

void
isis_sr_mpls_enable (isis_node_info_t *node_info) {

    if (!node_info) return;
    if (node_info->srmpls_config) return;

    node_info->srmpls_config = (isis_srmpls_config_t *)XCALLOC2(0, 1, isis_srmpls_config_t);

    label_mgr_rc_t rc = label_mgr_reserve_range(
            node_info->vrf->node->lbl_mgr,
            label_mgr_make_client(LABEL_CLIENT_ISIS, node_info->vrf->vrf_id),
            (node_info->vrf->vrf_id + 1) * ISIS_SR_DEFAULT_SRGB_BASE,
            ISIS_SR_DEFAULT_SRGB_RANGE);

    assert (rc == LABEL_MGR_OK);

    srgb_error_t rc1 = srgb_create((node_info->vrf->vrf_id + 1) * ISIS_SR_DEFAULT_SRGB_BASE, 
                 ISIS_SR_DEFAULT_SRGB_RANGE, 
                "ISIS-SRGB", &node_info->srmpls_config->srgb);

    assert (rc1 == SRGB_OK);

    srgb_register_client(node_info->srmpls_config->srgb, SRGB_CLIENT_ISIS);   

    isis_sr_mpls_advertise_rtr_cap_tlv242(node_info);

    /* Self TED may not yet reflect TLV(242) from our LSP; seed SRGB now so
     * the next SPF can program inet.3 + mpls.0 without flush-and-bail. */
    isis_sr_mpls_sync_self_ted_srgb(node_info);

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : SR-MPLS Enabled, SRGB [ %u - %u ]\n", ISIS_SR_MPLS,
        srgb_get_base_label(node_info->srmpls_config->srgb),
        srgb_get_end_label(node_info->srmpls_config->srgb));
}

void
isis_sr_mpls_flush_rtm_routes (isis_node_info_t *node_info) {

    rtm_t *rtm_inet3;
    rtm_t *rtm_mpls0;
    vrf_t *vrf;

    if (!node_info || !node_info->vrf) return;

    vrf = node_info->vrf;

    /* inet.3 : SR ingress / tunnel routes */
    rtm_inet3 = cp_rtm_get_route_target_rtm (
                    vrf, AF_IPV4, RTM_PROTO_ISIS, RTM_SUB_PROTO_SR);
    if (rtm_inet3) {
        cp_rtm_uninstall_routes_by_proto (
            rtm_inet3, RTM_PROTO_ISIS, RTM_SUB_PROTO_SR, 0);
    }

    /* mpls.0 : local-label transit (swap/pop) routes */
    rtm_mpls0 = cp_rtm_get_route_target_rtm (
                    vrf, AF_LABEL, RTM_PROTO_ISIS, RTM_SUB_PROTO_SR);
    if (rtm_mpls0) {
        cp_rtm_uninstall_routes_by_proto (
            rtm_mpls0, RTM_PROTO_ISIS, RTM_SUB_PROTO_SR, 0);
    }

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : Flushed ISIS SR routes from inet.3 and mpls.0\n", ISIS_SR_MPLS);
}

void
isis_sr_mpls_disable (isis_node_info_t *node_info) {

    if (!node_info) return;
    if (!node_info->srmpls_config) return;

    /* Drop programmed SR forwarding state immediately; do not wait for SPF */
    isis_sr_mpls_flush_rtm_routes(node_info);

    isis_sr_mpls_withdraw_node_sid(node_info);

    isis_sr_mpls_withdraw_rtr_cap_tlv242(node_info);

    label_mgr_release_range (node_info->vrf->node->lbl_mgr,
        label_mgr_make_client(LABEL_CLIENT_ISIS, node_info->vrf->vrf_id),
        srgb_get_base_label(node_info->srmpls_config->srgb));

    srgb_unregister_client(node_info->srmpls_config->srgb, SRGB_CLIENT_ISIS);
    srgb_destroy(node_info->srmpls_config->srgb);

    XFREE(node_info->srmpls_config);
    node_info->srmpls_config = NULL;

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : SR-MPLS Disabled\n", ISIS_SR_MPLS);
}

/* Push the locally configured SRGB into this router's TED node so SR route
    reinstall can use the new base/range without waiting for self-LSP refresh. */
void
isis_sr_mpls_sync_self_ted_srgb (isis_node_info_t *node_info) {

    ted_node_t *self;
    isis_srmpls_config_t *sr_config;

    if (!node_info || !node_info->ted_db) return;

    sr_config = isis_sr_mpls_get_config(node_info);
    if (!sr_config || !sr_config->srgb) return;

    self = ted_lookup_node(node_info->ted_db,
                           NODE_LO_ADDR_INT(node_info->vrf->node), 0);
    if (!self) return;

    self->has_srgb = true;
    self->srgb_base = srgb_get_base_label(sr_config->srgb);
    self->srgb_range = srgb_get_range_size(sr_config->srgb);
}

int
isis_sr_mpls_set_srgb (isis_node_info_t *node_info, 
                                    uint32_t srgb_base, uint32_t srgb_range) {

    srgb_error_t rc;
    isis_srmpls_config_t *sr_config = isis_sr_mpls_get_config(node_info);

    if (!sr_config) {
        cprintf("Error : Enable SR-MPLS first\n");
        return -1;
    }

    rc = srgb_validate_range(srgb_base, srgb_range);
    if (rc != SRGB_OK) {
        cprintf("Error : %s\n", srgb_error_to_string(rc));
        return -1;
    }

    if (srgb_get_base_label(sr_config->srgb) == srgb_base &&
        srgb_get_range_size(sr_config->srgb) == srgb_range) {
        return 0;
    }

    /* Old local labels (srgb_base + sid_index) are invalid under the new
        range — drop programmed SR state before reconfiguring. */
    isis_sr_mpls_flush_rtm_routes(node_info);

    /* Reconfiguring the SRGB wipes all label allocations tracked by it, so
        save/re-apply the Node-SID ( if any ) around the reconfiguration */
    bool had_node_sid = sr_config->node_sid_configured;
    uint32_t saved_index = sr_config->node_sid_index;
    uint8_t saved_flags = sr_config->node_sid_flags;

    if (had_node_sid) {
        isis_sr_mpls_withdraw_node_sid(node_info);
    }

    isis_sr_mpls_withdraw_rtr_cap_tlv242(node_info);
    srgb_reconfigure(sr_config->srgb, srgb_base, srgb_range);
    isis_sr_mpls_advertise_rtr_cap_tlv242(node_info);

    if (had_node_sid) {
        if (saved_index < srgb_range) {
            isis_sr_mpls_advertise_node_sid(node_info, saved_index, saved_flags);
        } else {
            cprintf("Warning : Node-SID Index %u no longer fits in the new "
                    "SRGB Range [0 - %u], Node-SID removed\n",
                    saved_index, srgb_range - 1);
        }
    }

    /* Keep local TED in sync, then SPF reinstalls inet.3 + mpls.0 routes
        against the new SRGB (install path does flush+reinstall). */
    isis_sr_mpls_sync_self_ted_srgb(node_info);
    isis_schedule_spf_job(node_info, isis_event_admin_config_changed);

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : SRGB Updated to [ %u - %u ], SR routes flushed and SPF scheduled\n",
        ISIS_SR_MPLS,
        srgb_get_base_label(sr_config->srgb), srgb_get_end_label(sr_config->srgb));

    return 0;
}

int
isis_sr_mpls_reset_srgb (isis_node_info_t *node_info) {

    isis_srmpls_config_t *sr_config = isis_sr_mpls_get_config(node_info);

    if (!sr_config) {
        cprintf("Error : Enable SR-MPLS first\n");
        return -1;
    }

    /* SRGB is mandatory while SR-MPLS is enabled — "no srgb" restores defaults */
    cprintf("SRGB cannot be deleted; resetting to default [%u - %u]\n",
            ISIS_SR_DEFAULT_SRGB_BASE,
            ISIS_SR_DEFAULT_SRGB_BASE + ISIS_SR_DEFAULT_SRGB_RANGE - 1);

    return isis_sr_mpls_set_srgb(node_info,
                                 ISIS_SR_DEFAULT_SRGB_BASE,
                                 ISIS_SR_DEFAULT_SRGB_RANGE);
}

int
isis_sr_mpls_advertise_node_sid (isis_node_info_t *node_info, 
                                                uint32_t sid_index, uint8_t flags) {

    srgb_error_t rc;
    uint32_t label = 0;
    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_srmpls_config_t *sr_config = isis_sr_mpls_get_config(node_info);

    if (!sr_config) {
        cprintf("Error : Enable SR-MPLS first\n");
        return -1;
    }

    /* Re-configuring the Node SID - withdraw the old one first */
    if (sr_config->node_sid_configured) {
        isis_sr_mpls_withdraw_node_sid(node_info);
    }

    /* Reserve the label for this index out of the local SRGB */
    rc = srgb_alloc_label_by_index(sr_config->srgb, sid_index, 
                                    SRGB_CLIENT_ISIS, NULL, &label);
    if (rc != SRGB_OK) {
        cprintf("Error : SID-Index %u : %s\n", sid_index, srgb_error_to_string(rc));
        return -1;
    }

    sr_config->node_sid_configured = true;
    sr_config->node_sid_index = sid_index;
    sr_config->node_sid_label = label;
    sr_config->node_sid_flags = flags;

    advt_data = (isis_adv_data_t *)XCALLOC2(0, 1, isis_adv_data_t);
    sr_config->node_sid_adv_data = advt_data;

    advt_data->tlv_no = ISIS_TLV_NODE_SID;
    advt_data->flags = 0;
    advt_data->fragment = NULL;
    advt_data->src.holder = &sr_config->node_sid_adv_data;
    init_glthread(&advt_data->glue);

    /* Node-SID is bound to this router's Loopback / Router-Id. Only the
        SID Index is advertised on the wire ( per RFC 8667 ); each router
        computes the actual label locally as ( its own SRGB Base + Index ) */
    advt_data->u.node_sid.prefix = NODE_LO_ADDR_INT(node_info->vrf->node);
    advt_data->u.node_sid.prefix_len = 32;
    advt_data->u.node_sid.sid_index = sid_index;
    advt_data->u.node_sid.flags = flags;

    advt_data->tlv_size = isis_get_adv_data_size(advt_data);

    isis_advertise_tlv(node_info, 0, advt_data, &advt_info);

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : Node-SID Index %u ( Label %u ) advertised\n", ISIS_SR_MPLS,
        sid_index, label);

    return 0;
}

void
isis_sr_mpls_withdraw_node_sid (isis_node_info_t *node_info) {

    isis_adv_data_t *advt_data;
    isis_srmpls_config_t *sr_config = isis_sr_mpls_get_config(node_info);

    if (!sr_config) return;
    if (!sr_config->node_sid_configured) return;

    advt_data = sr_config->node_sid_adv_data;
    assert (advt_data);

    if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED)) {
        isis_withdraw_tlv_advertisement(node_info, advt_data);
    }
    else if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED)) {
        isis_wait_list_advt_data_remove(node_info, advt_data);
    }

    isis_advt_data_clear_backlinkage(node_info, advt_data);
    isis_free_advt_data(advt_data);
    assert (!sr_config->node_sid_adv_data);

    srgb_free_label_by_index(sr_config->srgb, sr_config->node_sid_index, SRGB_CLIENT_ISIS);

    tracer (ISIS_TR(node_info), TR_ISIS_SR_MPLS,
        "%s : Node-SID Index %u withdrawn\n", ISIS_SR_MPLS,
        sr_config->node_sid_index);

    sr_config->node_sid_configured = false;
    sr_config->node_sid_index = 0;
    sr_config->node_sid_label = 0;
    sr_config->node_sid_flags = 0;
}

uint32_t
isis_sr_mpls_show_config (isis_node_info_t *node_info) {

    uint32_t rc = 0;
    isis_srmpls_config_t *sr_config = isis_sr_mpls_get_config(node_info);

    if (!sr_config) {
        rc += cprintf ("SR-MPLS : Disabled\n");
        return rc;
    }

    rc += cprintf ("SR-MPLS : Enabled\n");

    if (sr_config->node_sid_configured) {
        rc += cprintf ("Node-SID : Index %u  ( Label %u )  Flags : 0x%x  %s\n",
                sr_config->node_sid_index,
                sr_config->node_sid_label,
                sr_config->node_sid_flags,
                IS_BIT_SET(sr_config->node_sid_flags, NODE_SID_FLAG_N) ? "[N]" : "");
    }
    else {
        rc += cprintf ("Node-SID : Not Configured\n");
    }

    srgb_show(sr_config->srgb, true);

    return rc;
}
