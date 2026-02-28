#include <assert.h>
#include "cmn_prefix.h"
#include "../router_init.h"
#include "l3_hdrs.h"
#include "cp2dp.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../Layer2/mac_table.h"
#include "../Layer3/layer3.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/rt_table/nexthop.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../RTM/rtm_nh.h"
#include "../FIB/fib.h"
#include "../FIB/fib_route.h"
#include "../FIB/fib_nh.h"
#include "../datapath/Vrfs/dp_vrf.h"
#include "../datapath/dp_ctx.h"
#include "../datapath/Interface/dp_intf.h"
#include "../datapath/Interface/dp_intf_update.h"
#include "../datapath/Interface/dp_intf_store.h"
#include "../datapath/Interface/dp_intf_store.h"

extern void
np_tcp_ip_send_ip6_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

static void 
dp_mac_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {
    
    mac_update_msg_t *mac_update_msg;
    mac_table_t *mac_table = dp_ctx->mac_table;
    
    assert(dp_msg->component_type == MAC_TABLE);
    
    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_add (dp_ctx, mac_table, 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->flags,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_DEL:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_delete (dp_ctx, mac_table, 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_UPDATE:
            // Handle MAC entry updates if needed
            break;
            
        case DP_READ:
            // Handle MAC table reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}


static void
np_recv_cp_pkt_block(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg)
{
    pkt_block_t *pkt_block;
    hdr_type_t hdr_type;
    uint8_t vrf_id = dp_msg->vrf_id;

    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, vrf_id);

    pkt_block = *(pkt_block_t **)dp_msg->data;

    switch (dp_msg->opr_type)
    {
        case DP_L3_NORTHBOUND_IN:
        {
            hdr_type = pkt_block_get_starting_hdr(pkt_block);

            switch (hdr_type)
            {
            case IP_HDR:
                np_tcp_ip_send_ip_data(dp_ctx, vrf, pkt_block);
                break;
            case IP6_HDR:
                np_tcp_ip_send_ip6_data(dp_ctx, vrf, pkt_block);
                break;
            default:
                break;
            }
        }
    break;

    default:
        break;
    }

    pkt_block_dereference(pkt_block);
    cp2dp_msg_free(dp_msg);
}

static void
dp_fib_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {
    
    char nh_str[48];
    char route_str[48];
    fib_error_t rc;
    fib_t *fib = NULL;
    fib_nh_t *nh = NULL;
    fib_update_msg_t *fib_update_msg;

    assert(dp_msg->component_type == FIB_TABLE);

    fib_update_msg = (fib_update_msg_t *)dp_msg->data;

    tracer (dp_ctx->dptr, DFIB, 
        "FIB : Recvd fib update message : Route:%s vrf:%d idx[%u %u] ops:%d\n", 
            cmn_prefix_to_string(&fib_update_msg->prefix, &route_str), 
            fib_update_msg->target_fib_vrf_id,
            fib_update_msg->inhidx >> 32, 
            fib_update_msg->nhidx & 0x00000000FFFFFFFF, 
            dp_msg->opr_type);

    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
        {
            fib = fib_get (dp_ctx, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);
        
            if (!fib) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Create nexthop from forwarding info */
            fib_nh_t nh_template;
            memset (&nh_template, 0, sizeof(fib_nh_t));
            avltree_node_init (&nh_template.idx_glue);

            nh_template.fwd_info = new fib_nh_fwd_info_t;
            rtm_fib_copy_fwd_info (dp_ctx, 
                &fib_update_msg->fwd_info, nh_template.fwd_info);
            
            nh = fib_nh_lookup(fib, &nh_template);

            if (!nh) {

                nh = fib_nh_create(fib, &nh_template);
           
                if (!nh) {
                    tracer (dp_ctx->dptr, DFIB | DERR, 
                        "FIB[%s] : Error : Route %s : Failed to create nexthop %s\n", 
                        fib->name,
                        route_str,
                        cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                    delete nh_template.fwd_info;
                    cp2dp_msg_free(dp_msg);
                    return;
                }
                tracer (dp_ctx->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : New nexthop %s Created and Registered\n", 
                    fib->name,
                    route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                fib_register_nh(fib, nh);
            }
            else {
                tracer (dp_ctx->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : Existing nexthop %s Reused\n", 
                    fib->name, route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
            }

            delete nh_template.fwd_info;

            rc = fib_add_route(dp_ctx,
                    fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx, nh);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to add route %s, error: %s\n",
                       fib->name, route_str, fib_error_str(rc));
                delete nh->fwd_info;
                XFREE(nh);
            }
            break;
        }
            
        case DP_DEL:
        {   
            fib = fib_get (dp_ctx, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);

            if (!fib) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            rc = fib_del_route(dp_ctx, fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to delete route, error: %s\n",
                       fib->name, fib_error_str(rc));
            }
            break;
        }
            
        case DP_UPDATE:
            // Handle FIB entry updates if needed
            break;
            
        case DP_READ:
            // Handle FIB reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

static void
dp_vrf_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {

    assert(dp_msg->component_type == VRF_TABLE);

    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
        {
            dp_vrf_create_msg_t *vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
            dp_create_vrf(dp_ctx->dp_vrf_ht, vrf_msg->vrf_name, vrf_msg->vrf_id);
            break;
        }
        
        case DP_DEL:
        {
            dp_vrf_create_msg_t *vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
            dp_delete_vrf(dp_ctx, dp_ctx->dp_vrf_ht, vrf_msg->vrf_id);
            break;
        }
        
        case DP_UPDATE:
        {
            dp_vrf_intf_update_msg_t *msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
            switch (msg->op_code) {

                case DP_VRF_INTF_OP_ADD:
                {
                    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, msg->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(dp_ctx->dp_intf_ht, msg->ifindex);
                    assert (intf && vrf);
                    assert (!intf->vrf);
                    intf->vrf = vrf;
                }
                break;
                case DP_VRF_INTF_OP_DEL:
                {
                    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, msg->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(dp_ctx->dp_intf_ht, msg->ifindex);
                    assert(intf && vrf);
                    assert(intf->vrf && (intf->vrf == vrf));
                    intf->vrf = NULL;
                }   
                break;
            }
        }
        break;
        case DP_READ:
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

static void 
cp2dp_task_handler  (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    // This function is the task handler for the task submitted to the Data Path (DP)

    dp_msg_t *dp_msg = (dp_msg_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    node_t *node = (node_t *)dp_ctx->ctx_pvt_data;

    switch (dp_msg->component_type) {

        case MAC_TABLE:
            dp_mac_table_process_msg (dp_ctx, dp_msg);
            break;
        case PKT_BLOCK:
            np_recv_cp_pkt_block (dp_ctx, dp_msg);
            break;
        case FIB_TABLE:
            dp_fib_table_process_msg (dp_ctx, dp_msg);
            break;
        case VRF_TABLE:
            dp_vrf_table_process_msg (dp_ctx, dp_msg);
            break;
        case INTF_TABLE:
            dp_intf_table_process_msg(dp_ctx, dp_msg);
            break;
        default:
            break;
    }
    node->cp2dp_msg_count++;
}

dp_msg_t *
cp2dp_msg_alloc () {

    return new dp_msg_t;
}

void
cp2dp_msg_free (dp_msg_t *dp_msg) {
    
        delete (dp_msg);
}


void 
dp_pkt_xmit_intf_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    pkt_block_t *pkt_block;
	dp_intf_t *dp_intf;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		dp_intf = dp_look_up_interface(dp_ctx->dp_intf_ht, ev_dis_pkt_data->ifindex);

        if (!dp_intf) {
            free (ev_dis_pkt_data);
            continue;
        }
		pkt_block = (pkt_block_t *)ev_dis_pkt_data->pkt;		
        tracer (dp_ctx->dptr,  DIPC | DFLOW, "Pkt : %s : Recvd by Data path\n", pkt_block_str(pkt_block));
        dp_send_pkt_out(dp_ctx, dp_intf, pkt_block);
        pkt_block_dereference(pkt_block);
	    free (ev_dis_pkt_data);
	}
}

/* Fix me : cp2dp_xmit_pkt is allocated by CP but freed by DP. This is not a desirable thing to do.
    For now its not a problem, but in future when CP and DP will have separate memory mgr, 
    this would create problem.*/
void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) {
    
        ev_dis_pkt_data_t *ev_dis_pkt_data = (ev_dis_pkt_data_t *)
            calloc (1, sizeof (ev_dis_pkt_data_t));
        ev_dis_pkt_data->ifindex = xmit_interface->ifindex;
        ev_dis_pkt_data->pkt = (byte *)pkt_block;
        pkt_block_reference(pkt_block);
        tracer (node->cptr,  DIPC | DFLOW, "Pkt : %s : Xmit to Data path\n", pkt_block_str(pkt_block));
        pkt_q_enqueue(EV_DP(node->dp_ctx), 
                  &node->dp_ctx->cp_to_dp_xmit_intf_pkt_q ,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
}

/* This is Control plane API to push IP data to be sent out from L4+ layer down to L3.
    pkt_block must contain IP payload . If there is no ip payload, then send NULL*/
void 
cp2dp_send_ip_data ( node_t *node, 
                     pkt_block_t *pkt_block,
                     uint32_t dest_ip_addr,
                     uint16_t std_ip_protocol) {

    bool new_pkt_block = false;

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ip_hdr_t));
        new_pkt_block = true;
    }
    else {
        pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    pkt_size_t pkt_size = pkt_block->pkt_size;

    initialize_ip_hdr (ip_hdr);

    ip_hdr->protocol = (uint8_t)std_ip_protocol;
    ip_hdr->src_ip = htonl(tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node)));
    ip_hdr->dst_ip = htonl(dest_ip_addr);
    ip_hdr->total_length = htons(pkt_size);
    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
    if (new_pkt_block)pkt_block_dereference(pkt_block);
}

/* Write the ipv6 equivalent function of cp2dp_send_ip_data( )*/
void cp2dp_send_ip6_data(node_t *node,
                         pkt_block_t *pkt_block,
                         ipv6_addr_t dest_ip_addr,
                         uint16_t std_ip_protocol)
{
    bool new_pkt_block = false;
    pkt_size_t ipv6_payload_size = 0;

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ipv6_hdr_t));
        new_pkt_block = true;
    }
    else {
        ipv6_payload_size = pkt_block->pkt_size;
        pkt_block_expand_buffer_left (pkt_block, sizeof (ipv6_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP6_HDR);

    pkt_size_t pkt_size;
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_block_get_pkt (pkt_block, &pkt_size);

    initialize_ipv6_hdr (ipv6_hdr);

    ipv6_hdr->next_header = (uint8_t)(std_ip_protocol);
    ipv6_hdr->payload_length =  htons(ipv6_payload_size);
    memcpy (ipv6_hdr->dst_addr, dest_ip_addr.addr, 16);

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
    if (new_pkt_block) pkt_block_dereference (pkt_block);
}

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async) {

    // This function is used to submit a task to the DP
    // The task is submitted to the DP's event dispatcher
    // The task is submitted with the highest priority
    // The task is submitted as a one-shot task
    // The task is submitted with the task data as arg
    // The task data size is arg_size

    assert (dp_msg->data_size < sizeof(dp_msg->data));

    // Get the event dispatcher of the DP
    if (async) {
            task_create_new_job(EV_DP(node->dp_ctx), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
    else {
        task_create_new_job_synchronous(EV_DP(node->dp_ctx), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
}

/* Wrapper fn to add MAC entry to MAC table Asynchronously*/
void
cp2dp_mac_table_entry_add (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      uint16_t flags,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->flags = flags;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    
    cp2dp_submit(node, dp_msg, async);
}

void
cp2dp_mac_table_entry_del (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    mac_update_msg->flags = 0; // Not needed for delete
    
    cp2dp_submit(node, dp_msg, async);
}

void
cp2dp_fib_update (
        node_t *node,
        uint8_t target_fib_vrf_id,
        AFI_T target_fib_afi,
        cmn_prefix_t *prefix,
        uint32_t nh_idx,
        uint32_t inh_idx,
        rtm_nh_fwd_info_t *fwd_info,
        FIB_OPN_T operation) {

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    fib_update_msg_t *msg = (fib_update_msg_t *)dp_msg->data;

    /* Set message metadata */
    dp_msg->component_type = FIB_TABLE;
    dp_msg->opr_type = (operation == FIB_ADD) ? DP_CREATE : DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(fib_update_msg_t);

    /* Populate FIB update message */
    msg->target_fib_vrf_id = target_fib_vrf_id;
    msg->target_fib_afi = target_fib_afi;
    msg->fwd_flags = fwd_info ? fwd_info->fwd_flags : 0;
    msg->nhidx = nh_idx;
    msg->inhidx = inh_idx;
    msg->prefix = *prefix;

    if (fwd_info) memcpy(&msg->fwd_info, fwd_info, sizeof(fib_nh_fwd_info_t));    

    /* Submit to data plane */
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_create (node_t *node, char *vrf_name, uint8_t vrf_id) {

    dp_msg_t *dp_msg;
    dp_vrf_create_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_create_msg_t);
    
    vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
    vrf_msg->vrf_id = vrf_id;
    strncpy(vrf_msg->vrf_name, vrf_name, sizeof(vrf_msg->vrf_name) - 1);
    vrf_msg->vrf_name[sizeof(vrf_msg->vrf_name) - 1] = '\0';
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_delete (node_t *node, uint8_t vrf_id) {

    dp_msg_t *dp_msg;
    dp_vrf_create_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_create_msg_t);
    
    vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->vrf_name[0] = '\0';
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_delete_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex) {

    dp_msg_t *dp_msg;
    dp_vrf_intf_update_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_intf_update_msg_t);
    
    /* Fill in the header */
    vrf_msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
    vrf_msg->op_code = DP_VRF_INTF_OP_DEL;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->ifindex = ifindex;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_add_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex) {
    
    dp_msg_t *dp_msg;
    dp_vrf_intf_update_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_intf_update_msg_t);
    
    /* Fill in the header */
    vrf_msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
    vrf_msg->op_code = DP_VRF_INTF_OP_ADD;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->ifindex = ifindex;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
dp_simulate_wire_connection (node_t *node1, Interface *intf1, 
                             node_t *node2, Interface *intf2) {

    assert (intf1->iftype == INTF_TYPE_PHY);
    assert (intf2->iftype == INTF_TYPE_PHY);

    dp_intf_t *dp_intf1 = dp_look_up_interface(node1->dp_ctx->dp_intf_ht, intf1->ifindex);
    dp_intf_t *dp_intf2 = dp_look_up_interface(node2->dp_ctx->dp_intf_ht, intf2->ifindex);

    dp_intf1->att_node = node1;
    dp_intf1->nbr_intf = dp_intf2;
    dp_intf2->att_node = node2;
    dp_intf2->nbr_intf = dp_intf1;
}
