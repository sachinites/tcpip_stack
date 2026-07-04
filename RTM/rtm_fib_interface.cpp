
#include <stdio.h>
#include "../libs/Tracer/tracer.h"
#include "../router_init.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"
#include "rtm_presentation.h"
#include "rtm_fib_common.h"
#include "../libs/common/mpls_lstack.h"
#include "../datapath/FIB/fib_error.h"
#include "../datapath/FIB/fib.h"
#include "../dpal/cp2dp.h"

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
*/

static rtm_error_t
rtm_resolution_create_inh_fwd_info (rtm_t *rtm, 
                                    AFI_T afi,
                                    rtm_nh *inh, rtm_nh *dnh, 
                                    rtm_nh_fwd_info_t *fwd_info_out) {
    int i;
    bool l3_vpn = false;
    mpls_label_t label;
    mpls_label_val_t label_val;
    bool is_mpls_label_stck = false;

    fwd_info_out->oif = dnh->oif;
    fwd_info_out->fwd_flags = inh->fwd_flags;
    fwd_info_out->nh_addr = dnh->prefix;

    /* If INHs resolves over local/connected route , ex, configuring BGP route
        with IGP like nexthop (which is actually very common) */
    if (inh->is_indirect &&
        inh->prefix.afi == AF_IPV4 &&
        dnh->fwd_flags & (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_LOCAL)) {

        assert(fwd_info_out->nh_addr.u.v4_addr == 0);

        cmn_prefix_initialize_v4(&fwd_info_out->nh_addr,
                                 inh->prefix.u.v4_addr, 32);
    }

    mpls_lstack_init (&fwd_info_out->u.mpls_fwd.label_stack);

    if (inh->l3_vpn_label) {
    
        /* Copy VPN label from INH (innermost label) */
        mpls_label_init(&label);
        mpls_label_set_value  (&label.label_val, inh->l3_vpn_label);
        label.op = MPLS_OP_PUSH;
        mpls_lstack_push(&fwd_info_out->u.mpls_fwd.label_stack, label);  
        l3_vpn = true;      
        is_mpls_label_stck = true;
    }

    if (IS_BIT_SET(dnh->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK)) {

        i = 0;
        uint8_t max_label_stk_depth = l3_vpn ? MAX_LBL_DEPTH -1 : MAX_LBL_DEPTH;

        while (i < max_label_stk_depth &&
                !mpls_label_is_null(dnh->label_stack->labels[i])) {
            label_val = mpls_label_get_value (dnh->label_stack->labels[i].label_val);
            mpls_label_init(&label);
            mpls_label_set_value  (&label.label_val, label_val);
            label.op = MPLS_OP_PUSH;
            mpls_lstack_push(&fwd_info_out->u.mpls_fwd.label_stack, label);
            i++;
            is_mpls_label_stck = true;
        }
    }

    /* Set stack bottom*/
    if (is_mpls_label_stck) {

        mpls_label_t *bottom_label = &fwd_info_out->u.mpls_fwd.label_stack.labels[0];
        mpls_label_set_stack_bottom (&bottom_label->label_val);
        mpls_label_t *top_label = mpls_lstack_get_top (&fwd_info_out->u.mpls_fwd.label_stack);
        top_label->op = (afi == AF_MPLS) ? MPLS_OP_SWAP : MPLS_OP_PUSH;
        SET_BIT (fwd_info_out->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK);
    }

    if (inh->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        fwd_info_out->u.v6_fwd.endfn = inh->endfn;
        fwd_info_out->u.v6_fwd.n_segment_list = inh->n_segment_list;
        
        for (uint8_t i = 0; i < inh->n_segment_list; i++) {
            memcpy(fwd_info_out->u.v6_fwd.v6segment_lst[i],
                   inh->v6segment_lst[i].u.v6_addr,
                   sizeof(inh->v6segment_lst[i].u.v6_addr));
        }
    }

    if (inh->fwd_flags & FIB_NH_FWD_F_TUNNEL) {
        fwd_info_out->u.gre_fwd.gre_tunnel_src = inh->gre_tunnel_src;
        fwd_info_out->u.gre_fwd.gre_tunnel_dst = inh->gre_tunnel_dst;
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

        fwd_info_out->u.v6_fwd.endfn = pnh->endfn;
        fwd_info_out->u.v6_fwd.n_segment_list = pnh->n_segment_list;

        /* v6segment_lst stores raw 16-byte addresses; copy only the v6_addr
         * field from each cmn_prefix_t — not the whole struct. */
        for (uint8_t i = 0; i < pnh->n_segment_list; i++) {
            memcpy(fwd_info_out->u.v6_fwd.v6segment_lst[i],
                   pnh->v6segment_lst[i].u.v6_addr,
                   sizeof(pnh->v6segment_lst[i].u.v6_addr));
        }
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

    // 0.inet.3 and 0.inet6.3 routes are not allowed to download in FIB directly. 
    // They are service routes.
    if ((rtm->afi == AF_IPV4 || rtm->afi == AF_IPV6) && 
            (rtm->rtm_id == 3 )) {
        return false;
    }

    return true;
}

/* Get the target fib where the route is being downloaded*/
bool
rtm_get_target_fib (rtm_t *rtm,
                    cmn_prefix_t *route,
                    rtm_nh* inh,
                    rtm_nh* nh,
                    uint8_t *vrf_out, 
                    AFI_T *afi_out) {
    
    /* BGP VPN Route in Customer VRF Rib, eg : red.inet.0*/
    if (inh &&
        inh->proto == RTM_PROTO_BGP && 
        inh->sub_proto == RTM_PROTO_BGP_VPN &&
        inh->rtm->vrf != RTM_DEFAULT_VRF && 
        inh->rtm->rtm_id == 0) {

        vrf_t *vrf = vrf_get_by_id(rtm->node, inh->rtm->vrf);
        if (!vrf) return false;

        fib_t *fib = fib_get(rtm->node->dp_ctx, route->afi, vrf->vrf_id);
        if (!fib) return false;

        *vrf_out = fib->vrf_id;
        *afi_out = fib->afi;

        return true;
    }

    /* ISIS - SR routes */
    if (!inh &&
        (nh->proto == RTM_PROTO_ISIS || nh->proto == RTM_PROTO_OSPF) && 
        nh->sub_proto == RTM_SUB_PROTO_SR) {

        /* SR Transit routes will go in global mpls.0 fib*/
        if (route->afi == AF_MPLS) {
            *vrf_out = RTM_DEFAULT_VRF;
            *afi_out = route->afi;

            return true;
        }

        /* SR ingress routes will go in vrf.inet / vrf.inet6 FIBs 
            handled by default case */
    }
  

    /* Customer VRF routes --> download to corresponding FIB
        - already covered by Defaults case */
        
    /* Defaults*/
    *vrf_out = rtm->vrf;
    *afi_out = rtm->afi;

    return true;
}

void 
rtm_fib_update(rtm_t *rtm, rtm_presentation_data_t *presentation_data) {

    char rt_str[48];
    char nh_str[128];
    rtm_nh_fwd_info_t fwd_info; 

    AFI_T target_fib_afi;
    uint8_t target_fib_vrf_out;

    if (!rtm_download_route_to_fib(rtm)) {
        tracer (rtm->node->cptr, DRTM_DET, 
            "RTM[%s] : Route %s, NH %s(%u) not allowed to downloaded to FIB\n",
            rtm->name, 
            rtm_format_prefix(&presentation_data->route, rt_str, sizeof(rt_str)),
            presentation_data->nh ? rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "",
            presentation_data->nh_idx);
        return;
    }

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Updating FIB : Route %s, NH %s(%u), Operation %s\n",
        rtm->name,
        rtm_format_prefix(&presentation_data->route, rt_str, sizeof(rt_str)),
        presentation_data->operation == RTM_PPT_OP_ADD ? \
        rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
        presentation_data->nh_idx,
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
        presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");

    bool fib_found = false;
    if (presentation_data->operation != RTM_PPT_OP_DELETE) {

        fib_found = rtm_get_target_fib(rtm,
                           &presentation_data->route,
                           presentation_data->inh,
                           presentation_data->nh,
                           &target_fib_vrf_out,
                           &target_fib_afi);

        if (fib_found) {
            presentation_data->nh->target_fib.vrf = target_fib_vrf_out;
            presentation_data->nh->target_fib.afi = target_fib_afi;
        }
    }
    else {

        target_fib_vrf_out = presentation_data->target_fib.vrf;
        target_fib_afi = presentation_data->target_fib.afi;
        fib_found = true;
    }
    
    if (!fib_found) {

        tracer (rtm->node->cptr, DRTM | DERR, 
            "RTM[%s] : FIB location failed for Route %s, NH %s(%u), Operation %s\n",
                rtm->name,
                rt_str,
                presentation_data->operation == RTM_PPT_OP_ADD ? \
                rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
                presentation_data->nh_idx,
                presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
                presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");

        return;
    }

    /* Create Fib route entry */
    if (presentation_data->operation != RTM_PPT_OP_DELETE) {

        memset (&fwd_info, 0, sizeof (fwd_info));

        rtm_error_t rc =  rtm_resolution_create_nh_fwd_info (
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

    tracer (rtm->node->cptr, DRTM, "RTM[%s] : route=%s op=%s nh_idx=%u vrf=%u afi=%u -> cp2dp_fib_update\n",
            rtm->name, rt_str,
            presentation_data->operation == RTM_PPT_OP_ADD ? "ADD" :
            presentation_data->operation == RTM_PPT_OP_UPDATE ? "UPD" : "DEL",
            presentation_data->nh_idx, (unsigned)target_fib_vrf_out, (unsigned)target_fib_afi);

    /* Update FIB based on operation */
    cp2dp_fib_update (
            rtm->node, 
            target_fib_vrf_out,
            target_fib_afi,
            &presentation_data->route, 
            presentation_data->nh_idx,
            presentation_data->inh_idx,
            presentation_data->operation != RTM_PPT_OP_DELETE ? &fwd_info : NULL,
            rtm_to_fib_map_opn(presentation_data->operation));
}

