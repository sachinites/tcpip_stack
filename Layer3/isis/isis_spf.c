#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"
#include "isis_flood.h"
#include "isis_policy.h"
#include "isis_ted.h"
#include "isis_utils.h"
#include "isis_nxthop.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../RTM/rtm_route.h"
#include "../../RTM/rtm_enums.h"
#include "../../Layer3/SegmentRouting/SRv6/cp/srv6_rtm.h"

void
isis_cancel_spf_job(isis_node_info_t *node_info) {

    if (!node_info ||
        !node_info->spf_job_task) return;

    task_cancel_job(EV(node_info->vrf->node),  node_info->spf_job_task);
    node_info->spf_job_task = NULL;
}

static inline void
isis_free_spf_result(isis_spf_result_t *spf_result){

    nh_flush_nexthops(spf_result->nexthops);
    remove_glthread(&spf_result->spf_res_glue);
    XFREE(spf_result);
}

static void
isis_init_node_spf_data(ted_node_t *ted_node, bool delete_spf_result){

    isis_spf_data_t **_spf_data = (isis_spf_data_t **)&ISIS_NODE_SPF_DATA(ted_node);
    isis_spf_data_t *spf_data = *_spf_data;

    if (! spf_data ) {
        spf_data = XCALLOC2(0, 1, isis_spf_data_t);
        init_glthread(&spf_data->spf_result_head);
        spf_data->node = ted_node;
        *_spf_data = spf_data;
    }

    else if(delete_spf_result){

        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

            isis_spf_result_t *res = isis_spf_res_glue_to_spf_result(curr);
            isis_free_spf_result(res);
        } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
        init_glthread(&spf_data->spf_result_head);
    }

    spf_data->spf_metric = ISIS_INFINITE_METRIC;
    remove_glthread(&spf_data->priority_thread_glue);
    nh_flush_nexthops(spf_data->nexthops);
    spf_data->is_spf_processed = false;
}

static int 
isis_spf_comparison_fn(void *data1, void *data2){

    isis_spf_data_t *spf_data_1 = (isis_spf_data_t *)data1;
    isis_spf_data_t *spf_data_2 = (isis_spf_data_t *)data2;

    if(spf_data_1->spf_metric < spf_data_2->spf_metric)
        return CMP_PREFERRED;
    if(spf_data_1->spf_metric > spf_data_2->spf_metric)
        return CMP_NOT_PREFERRED;

#if 0
    if (spf_data1->node->pn_no && !spf_data2->node->pn_no)
        return CMP_PREFERRED;
    if (!spf_data1->node->pn_no && spf_data2->node->pn_no)
        return CMP_NOT_PREFERRED;
#endif

    return CMP_PREF_EQUAL;
}

static isis_spf_result_t *
isis_spf_lookup_spf_result_by_node(ted_node_t *spf_root, ted_node_t *node_info){

    glthread_t *curr;
    isis_spf_result_t *spf_result;
    isis_spf_data_t *curr_spf_data;

    isis_spf_data_t *spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(spf_root);

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

        spf_result = isis_spf_res_glue_to_spf_result(curr);
        if(spf_result->node == node_info)
            return spf_result;
    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);
    return NULL;
}

/* Install Route in RTM */
static void
isis_rt_ipv6_route_add(
    isis_node_info_t *node_info,
    ipv6_addr_t *prefix,
    uint8_t mask,
    ipv6_addr_t *gw_ip,
    Interface *oif,
    uint32_t metric)
{
    node_t *node = node_info->vrf->node;
    rtm_t *rtm = cp_rtm_get_route_target_rtm(
                    node_info->vrf,
                    AF_IPV6,
                    RTM_PROTO_ISIS, 
                    RTM_PROTO_L1_ISIS_INT);

    cmn_prefix_t rtm_prefix, rtm_gateway;
    memset (&rtm_gateway, 0 , sizeof (rtm_gateway));

    cmn_prefix_initialize_v6 (&rtm_prefix, &prefix->addr, mask);
    if (gw_ip) {
        cmn_prefix_initialize_v6 (&rtm_gateway, &gw_ip->addr, 128);
    }

    RTM_NH_ACTION_TYPE_T action = RTM_NH_ACTION_FORWARD;

    switch (oif->iftype) {

        case INTF_TYPE_GRE_TUNNEL:
            action = RTM_NH_ACTION_TUNNEL;
            break;
        default: 
            break;
    }

    cp_rtm_install_route_advanced (
        rtm,
        &rtm_prefix,
        RTM_PROTO_ISIS,
        RTM_PROTO_L1_ISIS_INT,
        0,
        action,
        metric,
        &rtm_gateway,
        oif->GetSharedPtr(), 
        NULL, 0, 0);
}

static void
isis_rt_ipv6_route_del(
    isis_node_info_t *node_info,
    ipv6_addr_t *prefix,
    uint8_t mask,
    ipv6_addr_t *gw_ip,
    Interface *oif,
    uint32_t metric)
{
    node_t *node = node_info->vrf->node;
    rtm_t *rtm = cp_rtm_get_route_target_rtm(
                    node_info->vrf,
                    AF_IPV6,
                    RTM_PROTO_ISIS, 
                    RTM_PROTO_L1_ISIS_INT);

    cmn_prefix_t rtm_prefix, rtm_gateway;
    memset (&rtm_gateway, 0 , sizeof (rtm_gateway));

    cmn_prefix_initialize_v6 (&rtm_prefix, &prefix->addr, mask);

    if (gw_ip) {
        cmn_prefix_initialize_v6(&rtm_gateway, &gw_ip->addr, 128);
    }

    RTM_NH_ACTION_TYPE_T action = RTM_NH_ACTION_FORWARD;

    if (oif) {

        switch (oif->iftype) {

            case INTF_TYPE_GRE_TUNNEL:
                action = RTM_NH_ACTION_TUNNEL;
                break;
            default: 
                break;
        }
    }

    if (gw_ip || oif) {

        cp_rtm_uninstall_route_advanced (
            rtm,
            &rtm_prefix,
            RTM_PROTO_ISIS,
            RTM_PROTO_L1_ISIS_INT,
            0,
            action,
            metric,
            &rtm_gateway,
            oif ? oif->GetSharedPtr() : 0, 
            NULL, 0, 0);
        
            return;
    }

    cp_rtm_uninstall_route_by_proto(rtm, 
            &rtm_prefix, 
            RTM_PROTO_ISIS,
            RTM_PROTO_L1_ISIS_INT);    
}

static int
isis_spf_install_v6routes(isis_node_info_t *node_info, ted_node_t *ted_spf_root){

    rtm_t *rtm_v6;
    rtm_t *rtm_srv6;
    uint32_t count = 0;
    ipv6_addr_t v6_prefix;
    cmn_prefix_t prefix;
    rtm_route *rtm_route;
    char ipv6_addr_str[48];
    ted_v6prefix_t *ted_prefix;
    avltree_node_t *avl_node;
    uint32_t route_isis_metric;
    vrf_t *vrf = node_info->vrf;
    node_t *spf_root = node_info->vrf->node;

    rtm_v6 = cp_rtm_get_route_target_rtm (
                vrf,
                AF_IPV6, RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT);

    rtm_srv6 = cp_rtm_get_route_target_rtm (
                vrf,
                AF_IPV6, RTM_PROTO_ISIS, RTM_SUB_PROTO_SRv6);

    cp_rtm_uninstall_routes_by_proto (rtm_v6, RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, 0);
    cp_rtm_uninstall_routes_by_proto (rtm_srv6, RTM_PROTO_ISIS, RTM_SUB_PROTO_SRv6, 0);

    /* Now iterate over result list and install routes for
     * loopback address of all routers*/
    int i = 0;
    glthread_t *curr;
    isis_spf_result_t *spf_result;
    nexthop_t *nexthop = NULL;

    isis_spf_data_t *spf_data = (isis_spf_data_t *)(ISIS_NODE_SPF_DATA(ted_spf_root));

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr) {    

        spf_result = isis_spf_res_glue_to_spf_result(curr);
        
        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, 
            "%s : Dest %s  : Computing ipv6 Routes Begin\n", ISIS_ROUTE,
                spf_result->node->node_name);

        if (spf_result->node->pn_no) continue;

        /* Install all v6 prefixes */
        ITERATE_AVL_TREE_BEGIN(spf_result->node->v6prefix_tree_root, avl_node) {

            ted_prefix = avltree_container_of(avl_node, ted_v6prefix_t, avl_glue);
            memcpy (v6_prefix.addr, ted_prefix->prefix, 16);

            cmn_prefix_initialize_v6(&prefix, &v6_prefix.addr, ted_prefix->mask);

            rtm_route = rtm_route_lookup(rtm_v6, &prefix);

            tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Considering Route %s/%d\n", 
                    ISIS_ROUTE,
                    spf_result->node->node_name,
                    inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

            /* Case 0 : If directly connected route, skip */
            if (rtm_route && 
                rtm_route_is_resolved(rtm_route) &&
                rtm_route_is_local (rtm_route)) {

                tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, 
                    "%s : Dest %s  : Route %s/%d is Local, skipped\n",
                    ISIS_ROUTE, spf_result->node->node_name, 
                    inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

                continue;
            }

            /* Case 1 : No L3 route present in RIB by ISIS */
            if (!rtm_route || !rtm_route_is_path_present (
                    rtm_route, RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, &route_isis_metric)) {

                for (i = 0; i < MAX_NXT_HOPS; i++){
                    
                    nexthop = spf_result->nexthops[i];
                    if (!nexthop) continue;

                    tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Add %s/%d\n", 
                            ISIS_ROUTE,
                            spf_result->node->node_name,
                            inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

                    isis_rt_ipv6_route_add(node_info,
                                           &v6_prefix,
                                           ted_prefix->mask,
                                           0,
                                           node_get_intf_by_ifindex(spf_root, nexthop->ifindex),
                                           spf_result->spf_metric + ted_prefix->metric);

                    count++;
                }

                continue;
            }

            /* Case 2 : Better route already present in RIB */
            if (route_isis_metric < 
                    (spf_result->spf_metric + ted_prefix->metric)) {

                continue;
            }

            /* Case 3 : IF new route is a better route, then replace the route in routing table*/
            if (route_isis_metric > 
                    (spf_result->spf_metric + ted_prefix->metric)) {

                tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Delete %s/%d\n", 
                            ISIS_ROUTE, spf_result->node->node_name,
                            inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

                isis_rt_ipv6_route_del (node_info,
                         &v6_prefix, ted_prefix->mask,  0, 0, 0);

                for (i = 0; i < MAX_NXT_HOPS; i++){

                    nexthop = spf_result->nexthops[i];
                    if (!nexthop) continue;

                    tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Replaced %s/%d\n", 
                            ISIS_ROUTE, spf_result->node->node_name,
                            inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

                    isis_rt_ipv6_route_add(node_info,
                                           &v6_prefix,
                                           ted_prefix->mask,
                                           0,
                                           node_get_intf_by_ifindex(spf_root, nexthop->ifindex),
                                           spf_result->spf_metric + ted_prefix->metric);

                    count++;
                }
                continue;
            }

            /* Case 4: ECMP case, merge the nexthops */
            for (i = 0; i < MAX_NXT_HOPS; i++) {

                nexthop = spf_result->nexthops[i];
                if (!nexthop) continue;

                tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : ECMP Route Add %s/%d\n", 
                            ISIS_ROUTE, spf_result->node->node_name,
                            inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

                isis_rt_ipv6_route_add(node_info,
                                       &v6_prefix,
                                       ted_prefix->mask,
                                       0,
                                       node_get_intf_by_ifindex(spf_root, nexthop->ifindex),
                                       spf_result->spf_metric + ted_prefix->metric);

                count++;
            }

        } ITERATE_AVL_TREE_END;

        /* Install all srv6 prefix sids */
        ITERATE_AVL_TREE_BEGIN(spf_result->node->srv6prefixsid_tree_root, avl_node) {

            ted_prefix = avltree_container_of(avl_node, ted_v6prefix_t, avl_glue);
            memcpy (v6_prefix.addr, ted_prefix->prefix, 16);

            tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : SRv6 Prefix sid Route Add %s/%d\n", 
                    ISIS_ROUTE,
                    spf_result->node->node_name,
                    inet_ntop6 (&v6_prefix, ipv6_addr_str), ted_prefix->mask);

            for (i = 0; i < MAX_NXT_HOPS; i++){

                nexthop = spf_result->nexthops[i];
                if (!nexthop) continue;

                srv6_rtm_route_install (vrf,
                                        &v6_prefix, 
                                        ted_prefix->mask, 
                                        FIB_NH_FWD_F_FORWARD,
                                        0, 
                                        node_get_intf_by_ifindex (spf_root, nexthop->ifindex),
                                        NULL, spf_result->spf_metric + ted_prefix->metric, 
                                        ted_prefix->endfn, 
                                        RTM_PROTO_ISIS, true);

                count++;
            }

        } ITERATE_AVL_TREE_END;

    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);

    return count;
}

/* Install Route in RTM */
static void
isis_rt_ipv4_route_add(
    isis_node_info_t *node_info,
    uint32_t prefix,
    uint8_t mask,
    uint32_t gw_ip,
    Interface *oif,
    uint32_t metric)
{

    char prefix_str[48];
    char gateway_str[48];
    rtm_t *rtm = cp_rtm_get_route_target_rtm(
                    node_info->vrf,
                    AF_IPV4,
                    RTM_PROTO_ISIS, 
                    RTM_PROTO_L1_ISIS_INT);

    cmn_prefix_t rtm_prefix, rtm_gateway;

    cmn_prefix_initialize_v4 (&rtm_prefix, prefix, mask);
    cmn_prefix_initialize_v4 (&rtm_gateway, gw_ip, 32);
    RTM_NH_ACTION_TYPE_T action = RTM_NH_ACTION_FORWARD;

    switch (oif->iftype) {

        case INTF_TYPE_GRE_TUNNEL:
        {
            action = RTM_NH_ACTION_TUNNEL;
            /* Overwrite gateway to tunnel Destination Address */
            GRETunnelInterface *gre_intf = dynamic_cast<GRETunnelInterface *>(oif);
            cmn_prefix_initialize_v4 (&rtm_gateway, gre_intf->tunnel_dst_ip, 32);
        }
        break;
        default:
            break;
    }

    tracer (ISIS_TR(node_info), TR_ISIS_ROUTE,
        "%s : RTM Install  vrf=%s route=%s nexthop=%s oif=%s metric=%u "
        "action=%s proto=%s/%s\n",
        ISIS_ROUTE,
        node_info->vrf->vrf_name,
        cmn_prefix_to_string(&rtm_prefix, &prefix_str),
        cmn_prefix_to_string(&rtm_gateway, &gateway_str),
        oif ? oif->if_name.c_str() : "-",
        metric,
        rtm_nh_action_to_string(action),
        rtm_proto_to_string(RTM_PROTO_ISIS),
        rtm_sub_proto_to_string(RTM_PROTO_L1_ISIS_INT));

    cp_rtm_install_route_advanced (
        rtm,
        &rtm_prefix,
        RTM_PROTO_ISIS,
        RTM_PROTO_L1_ISIS_INT,
        0,
        action,
        metric,
        &rtm_gateway,
        oif->GetSharedPtr(), 
        NULL, 0, 0);
}

static void
isis_rt_ipv4_route_del(
    isis_node_info_t *node_info,
    uint32_t prefix,
    uint8_t mask,
    uint32_t gw_ip,
    Interface *oif,
    uint32_t metric)
{

    char prefix_str[48];
    char gateway_str[48];
    rtm_t *rtm = node_info->vrf->inet0;
    cmn_prefix_t rtm_prefix, rtm_gateway;

    cmn_prefix_initialize_v4 (&rtm_prefix, prefix, mask);

    RTM_NH_ACTION_TYPE_T action = RTM_NH_ACTION_FORWARD;

    if (oif) {

        switch (oif->iftype) {

            case INTF_TYPE_GRE_TUNNEL:
                action = RTM_NH_ACTION_TUNNEL;
                break;
            default: 
                break;
        }
    }

    if (gw_ip || oif) {

        cmn_prefix_initialize_v4 (&rtm_gateway, gw_ip, 32);

        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE,
            "%s : RTM Uninstall  vrf=%s route=%s nexthop=%s oif=%s metric=%u "
            "action=%s proto=%s/%s\n",
            ISIS_ROUTE,
            node_info->vrf->vrf_name,
            cmn_prefix_to_string(&rtm_prefix, &prefix_str),
            gw_ip ? cmn_prefix_to_string(&rtm_gateway, &gateway_str) : "-",
            oif ? oif->if_name.c_str() : "-",
            metric,
            rtm_nh_action_to_string(action),
            rtm_proto_to_string(RTM_PROTO_ISIS),
            rtm_sub_proto_to_string(RTM_PROTO_L1_ISIS_INT));

        cp_rtm_uninstall_route_advanced (
            rtm,
            &rtm_prefix,
            RTM_PROTO_ISIS,
            RTM_PROTO_L1_ISIS_INT,
            0,
            action,
            metric,
            &rtm_gateway,
            oif ? oif->GetSharedPtr():0,
            NULL, 0, 0);
        return;
    }

    tracer (ISIS_TR(node_info), TR_ISIS_ROUTE,
        "%s : RTM Uninstall All NHs  vrf=%s route=%s proto=%s/%s\n",
        ISIS_ROUTE,
        node_info->vrf->vrf_name,
        cmn_prefix_to_string(&rtm_prefix, &prefix_str),
        rtm_proto_to_string(RTM_PROTO_ISIS),
        rtm_sub_proto_to_string(RTM_PROTO_L1_ISIS_INT));

    cp_rtm_uninstall_route_by_proto(rtm, 
            &rtm_prefix, 
            RTM_PROTO_ISIS,
            RTM_PROTO_L1_ISIS_INT);
}

static int
isis_spf_install_routes(isis_node_info_t *node_info, ted_node_t *ted_spf_root){

    rtm_t *rtm;
    rtm_nh *nh;
    cmn_prefix_t prefix;
    rtm_route *rtm_route;
    char ip_addr[IPV4_ADDR_LEN_STR];
    ted_prefix_t *ted_prefix;
    avltree_node_t *avl_node;
    uint32_t prefix32bit, mask32bit;

    rtm = node_info->vrf->inet0;

    cp_rtm_uninstall_routes_by_proto (rtm, RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, 0);

    /* Now iterate over result list and install routes for
     * loopback address of all routers*/

    int i = 0;
    int count = 0; /*no of routes installed*/
    glthread_t *curr;
    uint32_t route_isis_metric;
    nexthop_t *nexthop = NULL;
    isis_spf_result_t *spf_result;
    
    isis_spf_data_t *spf_data = (isis_spf_data_t *)(ISIS_NODE_SPF_DATA(ted_spf_root));

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr){

        spf_result = isis_spf_res_glue_to_spf_result(curr);
        
        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Computing Routes Begin\n", 
                        ISIS_ROUTE,
                        spf_result->node->node_name);

        if (spf_result->node->pn_no) continue;

#if 0
        /* Router ID */
        if (isis_evaluate_policy(spf_root,
                                 node_info->import_policy,
                                 spf_result->node->rtr_id, 32) == PFX_LST_DENY) {

            goto Exported_Prefixes;
        }

        for (i = 0; i < MAX_NXT_HOPS; i++){

            nexthop = spf_result->nexthops[i];

            if (!nexthop) continue;

            tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Add %s/%d\n", 
                        ISIS_ROUTE,
                        spf_result->node->node_name,
                        tcp_ip_covert_ip_n_to_p(spf_result->node->rtr_id, ip_addr), 32);          

            /* New RTM Route Install */
            isis_rt_ipv4_route_add (spf_root,  spf_result->node->rtr_id, 32,
                        tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                        nexthop->oif.get(),
                        spf_result->spf_metric);   

            count++;
        }
#endif 

        Exported_Prefixes:

            /* Exported Prefixes */
            
             ITERATE_AVL_TREE_BEGIN(spf_result->node->prefix_tree_root, avl_node){

                    ted_prefix = avltree_container_of(avl_node, ted_prefix_t, avl_glue);
                    
                    if (isis_evaluate_policy(node_info,
                                                    node_info->import_policy,
                                                    ted_prefix->prefix, ted_prefix->mask) == PFX_LST_DENY){
                        continue;
                    }

                    mask32bit = tcp_ip_convert_dmask_to_bin_mask (ted_prefix->mask);
                    prefix32bit = ted_prefix->prefix & mask32bit;
                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr);

                    cmn_prefix_initialize_v4(&prefix, prefix32bit, ted_prefix->mask);

                    rtm_route = rtm_route_lookup(rtm, &prefix);
                    
                    tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Considering Route %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    ip_addr, ted_prefix->mask); 

                    /*Case 0 : If directly connected route, skip */
                    if (rtm_route && 
                        rtm_route_is_resolved(rtm_route) &&
                        rtm_route_is_local (rtm_route)) {

                        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, 
                            "%s : Dest %s  : Route %s/%d is Local, skipped",
                            ISIS_ROUTE, spf_result->node->node_name, ip_addr, ted_prefix->mask);

                        continue;
                    }

                    /* Case 1 : No L3 route present in RIB by ISIS */
                    if (!rtm_route || !rtm_route_is_path_present (
                            rtm_route, RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, &route_isis_metric)) {

                        for (i = 0; i < MAX_NXT_HOPS; i++){
                            
                            nexthop = spf_result->nexthops[i];
                            if (!nexthop) continue;

                            tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Add %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    ip_addr, ted_prefix->mask);     

                            /* New RTM Route Install */
                            isis_rt_ipv4_route_add (node_info, 
                                prefix32bit, ted_prefix->mask,
                                tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                nexthop->oif.get(),
                                spf_result->spf_metric + ted_prefix->metric);  

                             count++;
                        }

                        continue;
                    }
                    
                    /* Case 2 : Better route already present in RIB */
                    if (route_isis_metric < 
                            (spf_result->spf_metric + ted_prefix->metric)) {

                        continue;
                    }

                    /* Case 3 : IF new route is a better route, then replace the route in routing table*/
                    if (route_isis_metric > 
                            (spf_result->spf_metric + ted_prefix->metric)) {

                        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Delete %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask); 

                        isis_rt_ipv4_route_del (node_info,
                                 prefix32bit, ted_prefix->mask,  0, 0, 0);

                        for (i = 0; i < MAX_NXT_HOPS; i++){

                            nexthop = spf_result->nexthops[i];
                            if (!nexthop) continue;

                            tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : Route Replaced %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    ip_addr, ted_prefix->mask);         

                            /* New RTM Route Install */
                            isis_rt_ipv4_route_add (node_info,
                                prefix32bit, ted_prefix->mask, 
                                tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                nexthop->oif.get(),
                                spf_result->spf_metric + ted_prefix->metric);  

                             count++;
                        }
                        continue;
                    }

                    /* Case 4: ECMP case, merge the nexthops */
                    for (i = 0; i < MAX_NXT_HOPS; i++) {

                        nexthop = spf_result->nexthops[i];
                        if (!nexthop) continue;

                        tracer (ISIS_TR(node_info), TR_ISIS_ROUTE, "%s : Dest %s  : ECMP Route Add %s/%d\n", 
                                    ISIS_ROUTE, spf_result->node->node_name,
                                    tcp_ip_covert_ip_n_to_p(prefix32bit, ip_addr), ted_prefix->mask);      

                            /* New RTM Route Install */
                            isis_rt_ipv4_route_add (node_info,
                                prefix32bit, ted_prefix->mask,
                                tcp_ip_convert_ip_p_to_n(nexthop->gw_ip),
                                nexthop->oif.get(),
                                spf_result->spf_metric + ted_prefix->metric);  

                         count++;
                    }
             } ITERATE_AVL_TREE_END;

    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);

    return count;
}

static void
isis_initialize_direct_nbrs (isis_node_info_t *node_info, ted_node_t *ted_spf_root){

    /*Initialize direct nbrs*/
    char ip_addr[IPV4_ADDR_LEN_STR];
    ted_intf_t *oif, *oif2;
    ted_node_t *nbr = NULL;
    nexthop_t *nexthop = NULL;
    unsigned char log_buf[256];
    isis_spf_data_t *nbr_spf_data;
    ted_node_t *nbr_of_pn = NULL;
    uint32_t nxt_hop_ip , nxt_hop_ip2;
    node_t *spf_root = node_info->vrf->node;

    tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
        "%s : ISIS initializing direct nbrs\n", ISIS_SPF);
    
    ITERATE_TED_NODE_NBRS_BEGIN(ted_spf_root, nbr, oif, nxt_hop_ip){

        /*No need to process any nbr which is not conneted via
         * Bi-Directional L3 link. */
        if (!ted_is_link_bidirectional(oif->link)) {

                tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
                    "%s : nbr %s is not birectional, skipping it\n", ISIS_SPF, nbr->node_name);
            continue;
        }

        /* Case 1 : When root and nbr both are non PNs*/
        if (!ted_spf_root->pn_no && !nbr->pn_no)
        {
                    /*Step 2.1 : Begin*/
                    nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr);
                    /*Populate nexthop array of directly connected nbrs of spf_root*/
                    if (oif->cost < nbr_spf_data->spf_metric)
                    {
                         tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : Nbr Node %s nexthops flushed :  %s\n",
                            ISIS_SPF, nbr->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                         nh_flush_nexthops(nbr_spf_data->nexthops);
                         nexthop = nh_create_new_nexthop(nbr->node_name,
                                                         oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr), IP_PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex)->GetSharedPtr();
                         nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
                         nbr_spf_data->spf_metric = oif->cost;
                         nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf));
                         tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : Nbr Node %s nexthops learned :  %s\n",
                            ISIS_SPF, nbr->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                    }
                    /*Step 2.1 : End*/

                    /*Step 2.2 : Begin*/
                    /*Cover the ECMP case*/
                    else if (oif->cost == nbr_spf_data->spf_metric)
                    {
                         nexthop = nh_create_new_nexthop(nbr->node_name,
                                                         oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip, ip_addr),
                                                         IP_PROTO_ISIS);
                         
                         if (nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop)) {

                            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex)->GetSharedPtr();
                            tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : Nbr Node %s nexthops learned :  %s\n",
                                ISIS_SPF, nbr->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                         }
                         else {
                            
                            tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : Nbr Node %s nexthops not learned :  %s, ECMP limit reached\n",
                                ISIS_SPF, nbr->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));
                            delete (nexthop);
                         }
                    }
        }

        /*Case 2 : When root is PN and Nbr is not PN*/
        else if (ted_spf_root->pn_no && !nbr->pn_no) {
            /* We never run SPF on PN as spf root*/
            assert(0);
        }

        /*Case 3 : When root and nbr both are PNs*/
        else if (ted_spf_root->pn_no && nbr->pn_no) {
            /* IGP topology never have 2 PNs adjacent to each other*/
            assert(0);
        }

        /* Case 4 : When root is non-PN and nbr is PN. */
        else if (!ted_spf_root->pn_no && nbr->pn_no) {

              uint32_t root_to_pn_cost = oif->cost;
              ted_intf_t *root_to_pn_oif = oif;
              nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr);
              nbr_spf_data->spf_metric = root_to_pn_cost;

              ITERATE_TED_NODE_NBRS_BEGIN(nbr, nbr_of_pn, oif2, nxt_hop_ip2){

                     tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : Initializing PN's %s direct nbr %s\n", 
                        ISIS_SPF, nbr->node_name, nbr_of_pn->node_name);
                        
                     if (!ted_is_link_bidirectional(oif2->link)){ 
                        tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
                            "%s : PN's %s direct nbr %s is not birectional, skipping it\n", ISIS_SPF,  
                            nbr->node_name, nbr_of_pn->node_name);
                        continue;
                     }

                    if (nbr_of_pn == ted_spf_root) {
                        tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
                            "%s : PN's %s direct nbr %s is self root, skipping it\n", ISIS_SPF,  
                            nbr->node_name, nbr_of_pn->node_name);
                        continue;
                    }

                    /*Step 2.1 : Begin*/
                    nbr_spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(nbr_of_pn);
                    /*Populate nexthop array of directly connected nbrs of spf_root*/
                    if ( (root_to_pn_cost + oif2-> cost ) < nbr_spf_data->spf_metric)
                    {
                         tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops flushed :  %s\n",
                            ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));                        
                         nh_flush_nexthops(nbr_spf_data->nexthops);
                         nexthop = nh_create_new_nexthop(nbr_of_pn->node_name,
                                                        root_to_pn_oif->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip2, ip_addr), IP_PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, root_to_pn_oif->ifindex)->GetSharedPtr();
                         nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop);
                         tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s\n",
                            ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                            nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));                          
                         nbr_spf_data->spf_metric = root_to_pn_cost + oif2->cost;
                    }
                    /*Step 2.1 : End*/

                    /*Step 2.2 : Begin*/
                    /*Cover the ECMP case*/
                    else if ((root_to_pn_cost + oif2-> cost )== nbr_spf_data->spf_metric)
                    {
                         nexthop = nh_create_new_nexthop(nbr_of_pn->node_name,
                                                         oif2->ifindex,
                                                         tcp_ip_covert_ip_n_to_p(nxt_hop_ip2, ip_addr),
                                                         IP_PROTO_ISIS);
                         nexthop->oif = node_get_intf_by_ifindex(spf_root, root_to_pn_oif->ifindex)->GetSharedPtr();

                         if (nh_insert_new_nexthop_nh_array(nbr_spf_data->nexthops, nexthop)) {

                            nexthop->oif = node_get_intf_by_ifindex(spf_root, oif->ifindex)->GetSharedPtr();
                            tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s\n",
                                ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf)));  
                         }
                         else {
                            
                            tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s : PN's %s direct nbr %s nexthops learned :  %s, ECMP limit reached\n",
                                ISIS_SPF, nbr->node_name, nbr_of_pn->node_name,
                                nh_nexthops_str(nbr_spf_data->nexthops, log_buf, sizeof(log_buf))); 
                            delete (nexthop);
                         }                 
                    }

             } ITERATE_TED_NODE_NBRS_END(nbr, nbr_of_pn, oif2, nxt_hop_ip2);
        }

        /*Step 2.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(ted_spf_root, nbr, oif, nxt_hop_ip);
}

static void
isis_spf_record_result(tracer_t *tr,
                       ted_node_t *spf_root,
                       ted_node_t *processed_node)
{ /*Dequeued Node*/

    unsigned char log_buff[256];
    isis_spf_data_t *spf_root_spf_data;
    isis_spf_data_t *processed_node_spf_data;

    spf_root_spf_data = ISIS_NODE_SPF_DATA(spf_root);
    processed_node_spf_data = ISIS_NODE_SPF_DATA(processed_node);

    /*Step 5 : Begin*/
    /* We are here because the node taken off the PQ is some node in Graph
     * to which shortest path has been calculated. We are done with this node
     * hence record the spf result in spf_root's local data structure*/

    /*Record result*/
    /*This result must not be present already but due to transient TEDs, anything
        could happen, hence do not assert, just return*/
    assert (!isis_spf_lookup_spf_result_by_node(spf_root, processed_node) );

    isis_spf_result_t *spf_result = XCALLOC2(0, 1, isis_spf_result_t);
    /*We record three things as a part of spf result for a node in 
     * topology : 
     * 1. The node itself
     * 2. the shortest path cost to reach the node
     * 3. The set of nexthops for this node*/
    spf_result->node = processed_node;
    spf_result->spf_metric = processed_node_spf_data->spf_metric;
    nh_union_nexthops_arrays(
            processed_node_spf_data->nexthops,
            spf_result->nexthops);

    tracer (tr, TR_ISIS_SPF,
        "%s : Result Recorded for node %s, "
            "Next hops : %s, spf_metric = %u\n", ISIS_SPF,
            processed_node->node_name,
            nh_nexthops_str(spf_result->nexthops, log_buff, sizeof(log_buff)),
            spf_result->spf_metric);

    /*Add the result Data structure for node which has been processed
     * to the spf result table (= linked list) in spf root*/
    init_glthread(&spf_result->spf_res_glue);
    glthread_add_next(&spf_root_spf_data->spf_result_head,
                                   &spf_result->spf_res_glue);

    /*Step 5 : End*/
}

static void
isis_spf_explore_nbrs(tracer_t *tr,
                                    ted_node_t *spf_root,           /*Only used for logging*/
                                    ted_node_t *curr_node,        /*Current Node being explored*/
                                    glthread_t *priority_lst){

    ted_intf_t *oif;
    ted_node_t *nbr;
    uint32_t nxt_hop_ip;
    unsigned char log_buf[256];

    isis_spf_data_t *curr_node_spf_data = ISIS_NODE_SPF_DATA(curr_node);
    isis_spf_data_t *nbr_node_spf_data;

    tracer (tr, TR_ISIS_SPF,
        "%s : Nbr Exploration Start for Node : %s\n", ISIS_SPF, curr_node->node_name);

    /*Step 6 : Begin*/
    /*Now Process the nbrs of the processed node, and evaluate if we have
     * reached them via shortest path cost.*/

    if (IS_BIT_SET( curr_node->flags, ISIS_LSP_PKT_F_OVERLOAD_BIT) &&
            spf_root != curr_node) {
        tracer (tr, TR_ISIS_SPF,
            "%s : Nbr Exploration Node : %s aborted, reason : Overloaded\n", 
            ISIS_SPF, curr_node->node_name);
        return;
    }

    ITERATE_TED_NODE_NBRS_BEGIN(curr_node, nbr, oif, nxt_hop_ip){
        
        tracer (tr, TR_ISIS_SPF,
            "%s : For Node %s , Processing nbr %s\n", ISIS_SPF,
                curr_node->node_name, 
                nbr->node_name);

        if(!ted_is_link_bidirectional(oif->link)) continue;

        nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);

        if (nbr_node_spf_data->is_spf_processed) {
            tracer (tr, TR_ISIS_SPF,
                "%s : Nbr node %s skipped, already processed\n", ISIS_SPF,
                 nbr_node_spf_data->node->node_name);
            continue;
        }

         tracer (tr, TR_ISIS_SPF,
            "%s : Testing Inequality : " 
                " spf_metric(%s, %u) + link cost(%u) < spf_metric(%s, %u)\n", ISIS_SPF,
                curr_node->node_name, 
                curr_node_spf_data->spf_metric, 
                oif->cost, nbr->node_name,
                nbr_node_spf_data->spf_metric);

        /*Step 6.1 : Begin*/
        /* We have just found that a nbr node is reachable via even better 
         * shortest path cost. Simply adjust the nbr's node's position in PQ
         * by removing (if present) and adding it back to PQ*/
        if (curr_node_spf_data->spf_metric + oif->cost < 
                nbr_node_spf_data->spf_metric) {

            tracer (tr, TR_ISIS_SPF,
                "%s : For Node %s , Primary Nexthops Flushed\n", ISIS_SPF,
                   nbr->node_name);

            /*Remove the obsolete Nexthops */
            nh_flush_nexthops(nbr_node_spf_data->nexthops);
            /*copy the new set of nexthops from predecessor node 
             * from which shortest path to nbr node is just explored*/
            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);
            /*Update shortest path cost of nbr node*/
            nbr_node_spf_data->spf_metric = curr_node_spf_data->spf_metric + oif->cost;

            tracer (tr, TR_ISIS_SPF,
                "%s : Primary Nexthops Copied "
                "from Node %s to Node %s, Next hops : %s\n", ISIS_SPF,
                    curr_node->node_name, 
                    nbr->node_name,
                    nh_nexthops_str(nbr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));

            /*If the nbr node is already present in PQ, remove it from PQ and it 
             * back so that it takes correct position in PQ as per new spf metric*/
            if(!IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                tracer (tr, TR_ISIS_SPF,
                    "%s : Node %s Already On priority Queue\n", ISIS_SPF,  nbr->node_name);
               
                remove_glthread(&nbr_node_spf_data->priority_thread_glue);
            }

             tracer (tr, TR_ISIS_SPF,
                "%s : Node %s inserted into priority Queue "
                        "with spf_metric = %u\n", ISIS_SPF,
                         nbr->node_name, nbr_node_spf_data->spf_metric);

            glthread_priority_insert(priority_lst, 
                    &nbr_node_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);
            /*Step 6.1 : End*/
        }
        /*Step 6.2 : Begin*/
        /*Cover the ECMP case. We have just explored an ECMP path to nbr node.
         * So, instead of replacing the obsolete nexthops of nbr node, We will
         * do union of old and new nexthops since both nexthops are valid. 
         * Remove Duplicates however*/
        else if(curr_node_spf_data->spf_metric + oif->cost == 
                    nbr_node_spf_data->spf_metric){

            tracer (tr, TR_ISIS_SPF,
                "%s : Primary Nexthops Union of Current Node"
                " %s(%s) with Nbr Node ", ISIS_SPF,
                curr_node->node_name, 
                nh_nexthops_str(curr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));
            tracer_disable_hdr_print (tr);
            tracer (tr, TR_ISIS_SPF,
                "%s(%s)\n",  nbr->node_name, 
                nh_nexthops_str(nbr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));

            nh_union_nexthops_arrays(curr_node_spf_data->nexthops,
                    nbr_node_spf_data->nexthops);

            /*If the nbr node is already present in PQ, remove it from PQ and it 
             * back so that it takes correct position in PQ as per new spf metric. This Code
                is required for topologies containing VLANs/PNs. Remove below step and
                build_dualswitch_topo( ) will fail to compute routes*/
            if(!IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                tracer (tr, TR_ISIS_SPF,
                    "%s : Node %s Already On priority Queue, removing it from PQ\n",
                     ISIS_SPF, nbr->node_name);
                remove_glthread(&nbr_node_spf_data->priority_thread_glue);
            }

            tracer (tr, TR_ISIS_SPF,
                "%s : Node %s inserted into priority Queue "
                        "with spf_metric = %u\n", ISIS_SPF,
                         nbr->node_name, nbr_node_spf_data->spf_metric);

            glthread_priority_insert(priority_lst, 
                    &nbr_node_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);

        }
        /*Step 6.2 : End*/
    } ITERATE_TED_NODE_NBRS_END(curr_node, nbr, oif, nxt_hop_ip);
        
     tracer (tr, TR_ISIS_SPF,
        "%s : Node %s has been processed, nexthops %s\n", ISIS_SPF,
           curr_node->node_name, 
            nh_nexthops_str(curr_node_spf_data->nexthops, log_buf, sizeof(log_buf)));
    /* We are done processing the curr_node, remove its nexthops to lower the
     * ref count*/
    nh_flush_nexthops(curr_node_spf_data->nexthops); 
    /*Step 6 : End*/
}

static void
 isis_initialize_topology_for_spf_run (ted_node_t *spf_root) {

     glthread_t *curr;
     ted_node_t *nbr;
     ted_intf_t *oif;
     uint32_t nxt_hop_ip;

     isis_spf_data_t *spf_data = ISIS_NODE_SPF_DATA(spf_root);
     isis_spf_data_t *curr_spf_data;

    glthread_t priority_lst;
    init_glthread(&priority_lst); 

    glthread_priority_insert(&priority_lst, 
            &spf_data->priority_thread_glue,
            isis_spf_comparison_fn, 
            isis_spf_data_offset_from_priority_thread_glue);

    while(!IS_GLTHREAD_LIST_EMPTY(&priority_lst)){

        curr = dequeue_glthread_first(&priority_lst);
        spf_data = isis_priority_thread_glue_to_spf_data(curr);

        if (spf_data->node == spf_root) {
             isis_init_node_spf_data(spf_root, true);
             spf_data = ISIS_NODE_SPF_DATA(spf_root);
             spf_data->spf_metric = 0;
        }
        else {
            isis_init_node_spf_data(spf_data->node, false);
        }

        ITERATE_TED_NODE_NBRS_BEGIN(spf_data->node, nbr, oif, nxt_hop_ip){

            curr_spf_data = ISIS_NODE_SPF_DATA(nbr);
            if ( curr_spf_data &&
                  (curr_spf_data->spf_metric == ISIS_INFINITE_METRIC ||
                 curr_spf_data->node == spf_root)){
                continue;
            }
           
            isis_init_node_spf_data(nbr, false);
            curr_spf_data = ISIS_NODE_SPF_DATA(nbr);

           glthread_priority_insert(&priority_lst, 
                    &curr_spf_data->priority_thread_glue,
                    isis_spf_comparison_fn, 
                    isis_spf_data_offset_from_priority_thread_glue);
            
        } ITERATE_TED_NODE_NBRS_END(spf_data->node, nbr, oif, nxt_hop_ip);
    }
 }

void
isis_compute_spf (isis_node_info_t *node_info);

void
isis_compute_spf (isis_node_info_t *node_info){

    ted_intf_t *oif;
    glthread_t *curr;
    uint32_t nxt_hop_ip;
    ted_node_t *nbr;
    ted_node_t *ted_spf_root;
    isis_spf_data_t *curr_spf_data;
    isis_spf_data_t *spf_root_spf_data = NULL;
    isis_spf_data_t *nbr_node_spf_data = NULL;
    node_t *spf_root = node_info->vrf->node;

    ted_spf_root = ted_lookup_node(
                        node_info->ted_db,
                        tcp_ip_convert_ip_p_to_n (NODE_RTRID_ADDR(spf_root)), 0);

    if (!ted_spf_root) return;

    tracer (ISIS_TR(node_info), TR_ISIS_SPF,  "%s : Running Spf\n", ISIS_SPF);

    /*Step 1 : Begin*/
    /* Clear old spf Result list from spf_root, and clear
     * any nexthop data if any*/
    isis_init_node_spf_data(ted_spf_root, true);
    spf_root_spf_data = ISIS_NODE_SPF_DATA(ted_spf_root);
    spf_root_spf_data->spf_metric = 0;

    /* Iterate all Routers in the graph and initialize the required fields
     * i.e. init cost to INFINITE, remove any spf nexthop data if any
     * left from prev spf run
     * */
    isis_initialize_topology_for_spf_run (ted_spf_root);
    /*Step 1 : End*/
   
    isis_initialize_direct_nbrs(node_info, ted_spf_root);

    /*Step 3 : Begin*/
    /* Initialize the Priority Queue. You can implement the PQ as a 
     * Min-Heap which would give best performance, but we have chosen
     * a linked list as Priority Queue*/
    glthread_t priority_lst;
    init_glthread(&priority_lst); 
    /*Insert spf_root as the only node into PQ to begin with*/
    glthread_priority_insert(&priority_lst, 
            &spf_root_spf_data->priority_thread_glue,
            isis_spf_comparison_fn, 
            isis_spf_data_offset_from_priority_thread_glue);
    /*Step 3 : End*/

    /*Iterate until the PQ go empty. Currently it has only spf_root*/
    while(!IS_GLTHREAD_LIST_EMPTY(&priority_lst)){

        /*Step 4 : Begin*/
        curr = dequeue_glthread_first(&priority_lst);
        curr_spf_data = isis_priority_thread_glue_to_spf_data(curr);
        curr_spf_data->is_spf_processed = true;

        tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
            "%s : Node %s taken out of priority queue\n", ISIS_SPF, curr_spf_data->node->node_name);

        /* if the current node that is removed from PQ is spf root itself. 
         * Then No need to rcord the result. Process nbrs and put them in PQ*/
        if(curr_spf_data->node == ted_spf_root){

            ITERATE_TED_NODE_NBRS_BEGIN(curr_spf_data->node, nbr, oif, nxt_hop_ip){

               if(!ted_is_link_bidirectional(oif->link)) continue;
                                
                nbr_node_spf_data = ISIS_NODE_SPF_DATA(nbr);
                if(IS_GLTHREAD_LIST_EMPTY(&nbr_node_spf_data->priority_thread_glue)){

                    tracer (ISIS_TR(node_info), TR_ISIS_SPF,
                        "%s : Processing Direct Nbr %s\n", ISIS_SPF, nbr->node_name);

                    glthread_priority_insert(&priority_lst, 
                            &nbr_node_spf_data->priority_thread_glue,
                            isis_spf_comparison_fn, 
                            isis_spf_data_offset_from_priority_thread_glue);

                    tracer (ISIS_TR(node_info), TR_ISIS_SPF,
                        "%s : Direct Nbr %s added to priority Queue\n", ISIS_SPF, nbr->node_name);
                }
            } ITERATE_TED_NODE_NBRS_END(curr_spf_data->node, nbr, oif, nxt_hop_ip);

            tracer (ISIS_TR(node_info), TR_ISIS_SPF,
                "%s : Root %s Processing Finished\n", 
                    ISIS_SPF, curr_spf_data->node->node_name);

            continue;
        }
        /*Step 4 : End*/

        /*Step 5  : Begin
         *Record Result */
        isis_spf_record_result(ISIS_TR(node_info), ted_spf_root, curr_spf_data->node);
        /*Step 5  : End*/

        /*Step 6 : Begin */
        isis_spf_explore_nbrs(ISIS_TR(node_info), ted_spf_root, curr_spf_data->node, &priority_lst);
        /*Step 6 : End */
    }

    /*Step 7 : Begin*/ 
    /*Calculate final routing table from spf result of spf_root*/
    int count = isis_spf_install_routes(node_info, ted_spf_root);
    /*Step 7 : End*/

    tracer (ISIS_TR(node_info), TR_ISIS_SPF,
        "%s : ipv4 Route Installation Count = %d\n", ISIS_SPF, count);

     count = isis_spf_install_v6routes(node_info, ted_spf_root);

    tracer (ISIS_TR(node_info), TR_ISIS_SPF,
        "%s : ipv6 Route Installation Count = %d\n", ISIS_SPF, count);
}

void
isis_show_spf_results (isis_node_info_t *node_info){

    int i = 0, j = 0;
    glthread_t *curr;
    Interface *oif = NULL;
    ted_node_t *ted_node;
    isis_spf_result_t *res = NULL;

    if (!(node_info)) return;
    
    node_t *node = node_info->vrf->node;

    ted_db_t *ted_db = node_info->ted_db;

    if (!ted_db) return;

    ted_node = ted_lookup_node(ted_db, 
                        tcp_ip_convert_ip_p_to_n (NODE_RTRID_ADDR(node)), 0);

    if (!ted_node) return;

    isis_spf_data_t *node_spf_data = ISIS_NODE_SPF_DATA(ted_node);

    cprintf("\nSPF run results for node = %s\n", ted_node->node_name);

    ITERATE_GLTHREAD_BEGIN(&node_spf_data->spf_result_head, curr){
        
        res = isis_spf_res_glue_to_spf_result(curr);

        cprintf("DEST : %-10s spf_metric : %-6u", res->node->node_name, res->spf_metric);
        cprintf(" Nxt Hop : ");

        j = 0;

        for( i = 0; i < MAX_NXT_HOPS; i++, j++){

            if(!res->nexthops[i]) continue;

            oif = res->nexthops[i]->oif.get();
            if (!oif) {
                oif = node_get_intf_by_ifindex(node, res->nexthops[i]->ifindex);
            }

            if (j == 0){
                cprintf("OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name.c_str(),
                        res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
            else{
                cprintf("                                              : "
                        "OIF : %-7s    gateway : %-16s ref_count = %u\n",
                        oif->if_name.c_str(),
                        res->nexthops[i]->gw_ip, 
                        res->nexthops[i]->ref_count);
            }
        }
    }ITERATE_GLTHREAD_END(&node_spf_data->spf_result_head, curr)
}

static void
isis_run_spf(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size){

    isis_node_info_t *node_info = (isis_node_info_t *)arg;

    node_info->spf_job_task = NULL;

    ISIS_INCREMENT_NODE_STATS(node_info, spf_runs);
    ISIS_INCREMENT_NODE_STATS(node_info, isis_event_count[isis_event_spf_runs]);

    isis_compute_spf(node_info);
}

void
isis_schedule_spf_job (isis_node_info_t *node_info, isis_event_type_t event) {

    if (isis_is_protocol_admin_shutdown (node_info)) {
        tracer (ISIS_TR(node_info), TR_ISIS_SPF,
            "%s : spf job not scheduled, protocol is admin shutdown\n", ISIS_SPF);
        return;
    }
    
    ISIS_INCREMENT_NODE_STATS(node_info,
        isis_event_count[isis_event_spf_job_scheduled]);

    if (node_info->spf_job_task) {
        
        tracer (ISIS_TR(node_info), TR_ISIS_SPF | TR_ISIS_EVENTS,
            "%s : spf job already scheduled\n", ISIS_SPF);
        return;
    }
    
    if (!isis_validate_job_schedule  (node_info, ISIS_SPF_JOB )) return;
    isis_cancel_redundant_jobs (node_info, ISIS_SPF_JOB);

    isis_add_new_spf_log(node_info, event);
    
    node_info->spf_job_task =
        task_create_new_job (EV(node_info->vrf->node), node_info, isis_run_spf, 
                                            TASK_ONE_SHOT,
                                            TASK_PRIORITY_COMPUTE);

    if (node_info->spf_job_task) {
        
        tracer (ISIS_TR(node_info), TR_ISIS_SPF | TR_ISIS_EVENTS,
            "%s : New spf job successfully scheduled\n", ISIS_SPF);
    }
}

void
isis_add_new_spf_log(isis_node_info_t *node_info, isis_event_type_t event) {

    isis_spf_log_t *spf_log;

    if (!node_info) return;

    if (isis_is_protocol_shutdown_in_progress(node_info) ||
         isis_is_protocol_admin_shutdown(node_info) ||
         !isis_is_protocol_enable_on_node(node_info->vrf)) {
        return;
    }

    spf_log = XCALLOC2(0, 1, isis_spf_log_t);
    
    spf_log->timestamp = time(NULL);
    spf_log->event = event;
    init_glthread(&spf_log->glue);
    glthread_add_next(&node_info->spf_logc.head, &spf_log->glue);
    node_info->spf_logc.count++;

    if (node_info->spf_logc.count > ISIS_MAX_SPF_LOG_COUNT) {
        node_info->spf_logc.count = ISIS_MAX_SPF_LOG_COUNT;
        glthread_t *last_node = glthread_get_last(&node_info->spf_logc.head);
        spf_log = isis_glue_spf_log(last_node);
        remove_glthread(&spf_log->glue);
        XFREE(spf_log);
    }
}

void
isis_show_spf_logs(isis_node_info_t *node_info) {

    int i = 0;
    glthread_t *curr;
    isis_spf_log_t *spf_log;

    if (!node_info) return;

     ITERATE_GLTHREAD_BEGIN(&node_info->spf_logc.head, curr) {

         spf_log = isis_glue_spf_log(curr);
         cprintf("%d. %s  %s\n", i, ctime(&spf_log->timestamp), 
            isis_event_str(spf_log->event));
         i++;
     } ITERATE_GLTHREAD_END(&node_info->spf_logc.head, curr)
}

void
isis_init_spf_logc(isis_node_info_t *node_info) {

    init_glthread(&node_info->spf_logc.head);
    node_info->spf_logc.count = 0;
}

void
isis_cleanup_spf_logc(isis_node_info_t *node_info) {

    glthread_t *curr;
    isis_spf_log_t *spf_log;

    ITERATE_GLTHREAD_BEGIN(&node_info->spf_logc.head, curr) {

        spf_log = isis_glue_spf_log(curr);
        remove_glthread(&spf_log->glue);
        XFREE(spf_log);
    } ITERATE_GLTHREAD_END(&node_info->spf_logc.head, curr);
}

void
isis_spf_cleanup_spf_data (ted_node_t *ted_node) {

    glthread_t *curr;
    isis_spf_result_t *res;
    isis_spf_data_t *spf_data = (isis_spf_data_t *)ISIS_NODE_SPF_DATA(ted_node);
    
    if (!spf_data) return;

    ITERATE_GLTHREAD_BEGIN(&spf_data->spf_result_head, curr) {
        res = isis_spf_res_glue_to_spf_result(curr);
        isis_free_spf_result(res);
    } ITERATE_GLTHREAD_END(&spf_data->spf_result_head, curr);

    init_glthread(&spf_data->spf_result_head);
    remove_glthread(&spf_data->priority_thread_glue);
    nh_flush_nexthops(spf_data->nexthops);
    XFREE(spf_data);
    ISIS_NODE_SPF_DATA(ted_node) = NULL;
}
