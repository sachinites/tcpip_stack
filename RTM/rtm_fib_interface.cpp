
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

static rtm_error_t
rtm_resolution_create_dnh_fwd_info (rtm_t *rtm, rtm_nh *pnh, 
                                    rtm_nh_fwd_info_t *fwd_info_out) 
{
    rtm_error_t rc = RTM_SUCCESS;
    
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
    
    return rc;
}

static rtm_error_t
rtm_resolution_create_nh_fwd_info(rtm_t *rtm, 
        rtm_nh *pnh, 
        rtm_nh *cnh, rtm_nh_fwd_info_t *fwd_info_out) {

    memset (fwd_info_out, 0, sizeof (*fwd_info_out));

    if (cnh == NULL) {
        return rtm_resolution_create_dnh_fwd_info (rtm, pnh, fwd_info_out);
    }

    return rtm_resolution_create_dnh_fwd_info (rtm, cnh, fwd_info_out);
}

void 
rtm_fib_update(rtm_t *rtm, rtm_presentation_data_t *presentation_data) {

    char rt_str[48];
    char nh_str[128];
    
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
    rtm_nh_fwd_info_t fwd_info; 
    rtm_error_t rc = rtm_resolution_create_nh_fwd_info (
            rtm, 
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

    /* Update FIB based on operation */
    cp2dp_fib_update (
            rtm->node, 
            rtm->afi, 
            rtm->vrf, 
            &presentation_data->route, 
            presentation_data->nh_idx,
            &fwd_info,
            rtm_to_fib_map_opn(presentation_data->operation));


    tracer (rtm->node->cptr, DERR,
            "RTM[%s] : FIB Update Failed : Could not update FIB for Route %s, "
            "NH %s(%u), Operation %s\n",
            rtm->name,
            rt_str,
            presentation_data->operation == RTM_PPT_OP_ADD ? \
            rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
            presentation_data->nh_idx,
            presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
            presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");
}

