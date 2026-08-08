#ifndef __ISIS_SR__
#define __ISIS_SR__

/* Very basic / minimal IS-IS Segment Routing ( SR-MPLS ) support :

    1. Advertise SR-MPLS Capability ( SRGB ) + SR-Algorithm via the Router
       CAPABILITY TLV(242) - see ISIS_TLV_RTR_CAP_SR_CAP_SUBTLV.
    2. Advertise this router's Node-SID ( index relative to its own SRGB ),
       bound to its Loopback/Router-Id, via a dedicated Node-SID TLV - see
       ISIS_TLV_NODE_SID.

    This is intentionally minimal : No label pool/allocation, no Adjacency-SID,
    no Prefix-SID for non-local prefixes, no SR-MPLS forwarding/MPLS label
    programming. It only implements the control plane advertisement piece. */

typedef struct isis_node_info_ isis_node_info_t;
typedef struct isis_adv_data_ isis_adv_data_t;
typedef struct srgb_ srgb_t;

/* SR-MPLS Config block, hanging off isis_node_info_t->srmpls_config.
    Label allocation/bookkeeping for the SRGB ( Segment Routing Global Block )
    is delegated to the SRGB library, see
    Layer3/SegmentRouting/SR-MPLS/srgb.h. Default SRGB values ( used when
    SR-MPLS is enabled without an explicit SRGB configuration ) are
    ISIS_SR_DEFAULT_SRGB_BASE/RANGE, see isis_const.h */
typedef struct isis_srmpls_config_ {

    /* SRGB owned by this router, ISIS registers itself as a client of it */
    srgb_t *srgb;

    /* Node SID Config - Index is relative to the SRGB above */
    bool node_sid_configured;
    uint32_t node_sid_index;
    uint32_t node_sid_label;
    uint8_t node_sid_flags;
    char padding[3];

    /* Advt Handles. This is a stand-alone Router CAPABILITY TLV(242) instance,
        independent of the one owned by SRv6 ( see isis_srv6.cpp ), so that
        SRv6 and SR-MPLS can be enabled/disabled independently of each other */
    isis_adv_data_t *rtr_cap_adv_data_tlv242;
    isis_adv_data_t *node_sid_adv_data;

} __attribute__((aligned(8))) isis_srmpls_config_t;

void
isis_sr_mpls_enable (isis_node_info_t *node_info);

void
isis_sr_mpls_disable (isis_node_info_t *node_info);

/* Uninstall all ISIS SR-MPLS routes from inet.3 and mpls.0 */
void
isis_sr_mpls_flush_rtm_routes (isis_node_info_t *node_info);

bool
isis_sr_mpls_is_enabled (isis_node_info_t *node_info);

isis_srmpls_config_t *
isis_sr_mpls_get_config (isis_node_info_t *node_info);

int
isis_sr_mpls_set_srgb (isis_node_info_t *node_info, 
                                    uint32_t srgb_base, uint32_t srgb_range);

/* SRGB cannot be deleted — reset to ISIS default base/range and refresh routes */
int
isis_sr_mpls_reset_srgb (isis_node_info_t *node_info);

int
isis_sr_mpls_advertise_node_sid (isis_node_info_t *node_info, 
                                    uint32_t sid_index, uint8_t flags);

void
isis_sr_mpls_withdraw_node_sid (isis_node_info_t *node_info);

uint32_t
isis_sr_mpls_show_config (isis_node_info_t *node_info);

#endif /* __ISIS_SR__ */
