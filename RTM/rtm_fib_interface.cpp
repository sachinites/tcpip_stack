
#include "../Tracer/tracer.h"
#include "../graph.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"
#include "rtm_presentation.h"
#include "rtm_fib_common.h"
#include "../common/mpls_lstack.h"
#include "../FIB/fib_error.h"
#include "../common/cp2dp.h"

/* Function which created a data plane forwarding info from a nexthop 
    for Indirect nexthop : 
        pnh - Indirect Nexthop
        cnh - Direct Nexthop which resolved pnh

    For Direct Nexthops:
        pnh - Direct Nexthop
        cnh = NULL
*/

/* Prepare fwd_info_out from inh and dnh
    fwd_info_out gets OIF and Nexthop Address from DNH
    DNH may or may not have label stack / segment list
    and INH may or may not have label stack / segment list
    fwd_info_out - mist copy labels / segment list from INH first ( inner labels / seg lst )
    then copy labels/seg list from INH ( outer labels / seg list )

    We will implement this function case by case */
static rtm_error_t
rtm_resolution_create_inh_fwd_info (rtm_t *rtm, 
                                    AFI_T afi,
                                    rtm_nh *inh, rtm_nh *dnh, 
                                    rtm_nh_fwd_info_t *fwd_info_out) {

    mpls_label_val_t label_val;
    mpls_label_t label;

    /* Default Case : When ipv4/6 INH next hop is resolved to ipv4/6 DNH - 
        Normal case when BGP NHs resolves over IGP nexthops */

    // Route is IPv4/IPv6 and NHs do not have segments/labels
    if ((afi == AF_IPV4 || afi == AF_IPV6) && 
        !IS_BIT_SET(inh->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK) &&
        !IS_BIT_SET(dnh->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK) &&
        !IS_BIT_SET(inh->fwd_flags, FIB_NH_FWD_F_IPV6_STCK) &&
        !IS_BIT_SET(dnh->fwd_flags, FIB_NH_FWD_F_IPV6_STCK))
    {
        fwd_info_out->oif = dnh->oif;
        fwd_info_out->nh_addr = dnh->prefix;
        fwd_info_out->fwd_flags = dnh->fwd_flags;
        return RTM_SUCCESS;
    }

    /* L3 VPNv4 case 
    Route is IPv4 and 
    INH is ipv4 with VPN label  and 
    DNH is ipv4 nexthop with label stack  */

    if (afi == AF_IPV4 &&
        IS_BIT_SET(inh->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK) &&
        IS_BIT_SET(inh->fwd_flags, FIB_NH_FWD_F_IPV4) &&
        IS_BIT_SET(dnh->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK) &&
        IS_BIT_SET(dnh->fwd_flags, FIB_NH_FWD_F_IPV4)) 
    {
        fwd_info_out->oif = dnh->oif;
        fwd_info_out->nh_addr = dnh->prefix;
        fwd_info_out->fwd_flags = dnh->fwd_flags;

        /* Copy VPN label from INH (innermost label) */
        label_val = mpls_label_get_value (inh->label_stack->labels[0].label_val);
        mpls_label_init(&label);
        mpls_label_set_value  (&label.label_val, label_val);
        mpls_label_set_stack_bottom(&label.label_val);
        label.op = MPLS_OP_PUSH;
        mpls_lstack_push(&fwd_info_out->u.mpls_fwd.label_stack, label);

        /* Copy labels from DNH (outer labels) */
        int i = 0;

        while (i < (MAX_LBL_DEPTH - 1) &&  // because one label is already copied above
                !mpls_label_is_null(dnh->label_stack->labels[i])) {
            label_val = mpls_label_get_value (dnh->label_stack->labels[i].label_val);
            mpls_label_init(&label);
            mpls_label_set_value  (&label.label_val, label_val);
            label.op = MPLS_OP_PUSH;
            mpls_lstack_push(&fwd_info_out->u.mpls_fwd.label_stack, label);
            i++;
        }

        return RTM_SUCCESS;
    }
    
    return RTM_SUCCESS;
}

static rtm_error_t
rtm_resolution_create_dnh_fwd_info (rtm_t *rtm, 
                                    rtm_nh *pnh, 
                                    rtm_nh_fwd_info_t *fwd_info_out) 
{   
    /* Populate outgoing interface */
    fwd_info_out->oif = pnh->oif;
    
    /* Populate nexthop address */
    fwd_info_out->nh_addr = pnh->prefix;
    
    /* Populate forwarding flags */
    fwd_info_out->fwd_flags = pnh->fwd_flags;

    /* Handle MPLS label stack if present */
    if (pnh->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK)
    {
        memcpy(&fwd_info_out->u.mpls_fwd.label_stack, pnh->label_stack,
               sizeof(mpls_lstack_t));
    }

    /* Handle SRv6 segment list if present */
    if (pnh->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        /* Copy SRv6 end function */
        fwd_info_out->u.v6_fwd.endfn = pnh->endfn;
        /* Copy segment list count */
        fwd_info_out->u.v6_fwd.n_segment_list = pnh->n_segment_list;

        /* Allocate and copy segment list */
        size_t seg_list_size = sizeof(cmn_prefix_t) * pnh->n_segment_list;

        memcpy(&fwd_info_out->u.v6_fwd.v6segment_lst, pnh->v6segment_lst,
               seg_list_size);
    }
    
    return RTM_SUCCESS;
}

static rtm_error_t
rtm_resolution_create_nh_fwd_info(rtm_t *rtm,  AFI_T afi,
        rtm_nh *inh, 
        rtm_nh *dnh, rtm_nh_fwd_info_t *fwd_info_out) {

    /* DNH is deleted , just delete the NH from FIB based on idx*/
    if (!dnh) {
        return RTM_SUCCESS;
    }

    /* if DNH is added */
    if (!inh && dnh) {
        return rtm_resolution_create_dnh_fwd_info (rtm, dnh, fwd_info_out);
    }

    /* If INH is added which is resolved by DNH */
    return rtm_resolution_create_inh_fwd_info (rtm, afi, inh, dnh, fwd_info_out);
}

static bool 
rtm_download_route_to_fib (rtm_t *rtm) {

    // x.inet.3 and x.inet.6 routes are not allowed to download in FIB directly. They are 
    // service routes.
    if ((rtm->afi == AF_IPV4 || rtm->afi == AF_IPV6) &&
            (rtm->rtm_id == 3 || rtm->rtm_id == 6 )) {
                return false;
    }

    return true;
}

void 
rtm_fib_update(rtm_t *rtm, rtm_presentation_data_t *presentation_data) {

    char rt_str[48];
    char nh_str[128];
    rtm_nh_fwd_info_t fwd_info; 

    if (!rtm_download_route_to_fib(rtm)) return;

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Updating FIB : Route %s, NH %s(%u), Operation %s\n",
        rtm->name,
        rtm_format_prefix(&presentation_data->route, rt_str, sizeof(rt_str)),
        presentation_data->operation == RTM_PPT_OP_ADD ? \
        rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
        presentation_data->nh_idx,
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
        presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");

    /* Create Fib route entry */
    if (presentation_data->operation != RTM_PPT_OP_DELETE) {

        memset (&fwd_info, 0, sizeof (fwd_info));

        rtm_error_t rc = rtm_resolution_create_nh_fwd_info (
                rtm,  presentation_data->route.afi,
                presentation_data->inh, 
                presentation_data->nh,
                &fwd_info);

        if (rc != RTM_SUCCESS) {

            tracer (rtm->node->cptr, DERR,
                "RTM[%s] : FIB Update Failed : Could not create FWD info for Route %s, NH %s(%u), Operation %s\n",
                rtm->name,
                rt_str,
                presentation_data->operation == RTM_PPT_OP_ADD ? \
                rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
                presentation_data->nh_idx,
                presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
                presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");
            return;
        }
    }

    /* Update FIB based on operation */
    cp2dp_fib_update (
            rtm->node, 
            rtm->afi, 
            rtm->vrf, 
            &presentation_data->route, 
            presentation_data->nh_idx,
            presentation_data->operation != RTM_PPT_OP_DELETE ? &fwd_info : NULL,
            rtm_to_fib_map_opn(presentation_data->operation));
}

