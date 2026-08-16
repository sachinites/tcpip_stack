#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "L2FwdObject.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_ctx.h"
#include "../../../libs/common/mpls_lstack.h"
#include "../../../libs/LinuxMemoryManager/uapi_mm.h"

static int
l2_fwd_cmp_u32 (uint32_t a, uint32_t b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

static int
l2_fwd_cmp_ptr (const void *a, const void *b)
{
    uintptr_t ua = (uintptr_t)a;
    uintptr_t ub = (uintptr_t)b;

    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

extern void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, 
                struct rte_mbuf *mbuf, dp_intf_t *pintf);

static void 
l2_flood_forwarding (dp_ctx_t *dp_ctx, 
                    mac_fwd_object_t *fwd_obj, 
                    struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == L2_FWD_FLOODING);

    assert (fwd_obj->u.l2_flood.vfif->if_type == DP_INTF_TYPE_VLAN_FLOOD || 
            fwd_obj->u.l2_flood.vfif->if_type == DP_INTF_TYPE_BD_FLOOD);

    assert  ( 
             fwd_obj->u.l2_flood.vlan_bd_port == NULL ||  /* For vlan flooding we pass NULL (which needs to be corrected )*/
             fwd_obj->u.l2_flood.vlan_bd_port->if_type == DP_INTF_TYPE_VLAN_FLOOD ||
             fwd_obj->u.l2_flood.vlan_bd_port->if_type == DP_INTF_TYPE_BD_FLOOD
            );

    dp_send_pkt_out(dp_ctx, fwd_obj->u.l2_flood.vfif, 
                    mbuf, 
                    fwd_obj->u.l2_flood.vlan_bd_port);
}

static void 
l2_mpls_tunnel_forwarding (dp_ctx_t *dp_ctx, 
                           mac_fwd_object_t *fwd_obj, 
                           struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == L2_FWD_MPLS_TUNNEL);

    assert (fwd_obj->u.lbl_stk);

    /* ToDo : 
        Resolve top Label in Lbl Stack from MPLS FIB to know
        Nexthop and egress physical interface 
        Merge the Label list in into pkt, and pass it down to L2 for forwarding    
    */
}

static void 
l2_srv6_tunnel_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, 
                           struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == L2_FWD_SRv6_TUNNEL);

    assert (fwd_obj->u.srv6.seg_lst_cnt);

    /* ToDo : 
        Resolve top Segment in Segment List from ipv6 FIB to know
        Nexthop and egress physical interface 
        Merge the Segment list into pkt, and pass it down to L2 for forwarding    
    */
}

static void 
l2_vxlan_tunnel_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, 
                            struct rte_mbuf *mbuf) {


}

static void 
l2_steer_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, 
                            struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == L2_FWD_STEERING);               

    switch (fwd_obj->u.steering.steering_type) {

        case STEER_INTO_VRF:
            assert (fwd_obj->u.steering.u_steer.steered_vrf );  
            break;
        case STEER_INTO_BD:
            assert (fwd_obj->u.steering.u_steer.steered_bd_ifindex );
            break;
        default:
            assert(0);
    }


}

static void 
l2_port_forwarding (dp_ctx_t *dp_ctx,
                    mac_fwd_object_t *fwd_obj, 
                    struct rte_mbuf *mbuf) {

    /* This can branch out further depending on interface type */

    /* This function is valid only for L2 forwarding objects which can
        be represented by single port alone */
    assert (fwd_obj->fwd_type == L2_FWD_PORT);

    switch (fwd_obj->u.dp_intf->if_type) {

        case DP_INTF_TYPE_PHY:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;
        case DP_INTF_TYPE_VLAN:
            /* For legacy reasons, flooding in the vlan is done by a forwarding
                object which is represented by single port alone. Unlike Vlans,
                NEw Implementation of BD uses two Interfaces : vfif and bd_intf_t*/
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;
        case DP_INTF_TYPE_GRE_TUNNEL:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;
        case DP_INTF_TYPE_LOOPBACK:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;
        case DP_INTF_TYPE_VIRTUAL_PORT:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;
        case DP_INTF_TYPE_RMAC:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;        
        case DP_INTF_TYPE_VLAN_FLOOD:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;                 
        case DP_INTF_TYPE_NVE:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;               
        case DP_INTF_TYPE_SRv6_DT4_STEER:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;               
        case DP_INTF_TYPE_VPNV4_STEER:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;     
        case DP_INTF_TYPE_AC:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;              
        case DP_INTF_TYPE_BD:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;          
        case DP_INTF_TYPE_BD_FLOOD:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;                 
        case DP_INTF_TYPE_BD_RMAC:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;    
        case DP_INTF_TYPE_L2VPN_EVPN_STEER:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;               
        case DP_INTF_TYPE_HOST_PATH:
            dp_send_pkt_out(dp_ctx, fwd_obj->u.dp_intf, mbuf, 0);
            break;          
        case DP_INTF_TYPE_UNKNOWN:
        default:
            break;
    }

}

/* Maintained in the order of L2_FWD_TYPE_T enums */
static l2_fwding_ptr l2_fwding[] = 
 {
    l2_port_forwarding,
    l2_flood_forwarding,
    l2_mpls_tunnel_forwarding,
    l2_srv6_tunnel_forwarding,
    l2_vxlan_tunnel_forwarding,
    l2_steer_forwarding,
    0
 };

void 
dp_l2fwd (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, struct rte_mbuf *mbuf) {

    (l2_fwding[fwd_obj->fwd_type])(dp_ctx, fwd_obj, mbuf);
}

/* L2 Forwarding Object Mgmt */

static int 
L2_forward_object_comp_fb (
        const avltree_node_t *node1, 
        const avltree_node_t *node2) {

    int rc;
    const mac_fwd_object_t *o1 =
        avltree_container_of(node1, mac_fwd_object_t, glue);
    const mac_fwd_object_t *o2 =
        avltree_container_of(node2, mac_fwd_object_t, glue);

    rc = l2_fwd_cmp_u32((uint32_t)o1->fwd_type, (uint32_t)o2->fwd_type);
    if (rc)
        return rc;

    switch (o1->fwd_type) {

        case L2_FWD_PORT:
            return l2_fwd_cmp_ptr(o1->u.dp_intf, o2->u.dp_intf);

        case L2_FWD_FLOODING:
            rc = l2_fwd_cmp_ptr(o1->u.l2_flood.vfif, o2->u.l2_flood.vfif);
            if (rc)
                return rc;
            return l2_fwd_cmp_ptr(o1->u.l2_flood.vlan_bd_port,
                                  o2->u.l2_flood.vlan_bd_port);

        case L2_FWD_MPLS_TUNNEL:
            return l2_fwd_cmp_ptr(o1->u.lbl_stk, o2->u.lbl_stk);

        case L2_FWD_SRv6_TUNNEL:
            rc = l2_fwd_cmp_u32(o1->u.srv6.seg_lst_cnt,
                                o2->u.srv6.seg_lst_cnt);
            if (rc)
                return rc;
            return l2_fwd_cmp_ptr(o1->u.srv6.seg_lst, o2->u.srv6.seg_lst);

        case L2_FWD_VxLAN:
            rc = l2_fwd_cmp_u32(o1->u.vxlan.l2vni, o2->u.vxlan.l2vni);
            if (rc)
                return rc;
            return l2_fwd_cmp_u32(o1->u.vxlan.vtep_ip, o2->u.vxlan.vtep_ip);

        case L2_FWD_STEERING:
            rc = l2_fwd_cmp_u32(o1->u.steering.steering_type,
                                o2->u.steering.steering_type);
            if (rc)
                return rc;
            rc = l2_fwd_cmp_ptr(o1->u.steering.u_steer.steered_vrf,
                                o2->u.steering.u_steer.steered_vrf);
            if (rc)
                return rc;
            return l2_fwd_cmp_u32(o1->u.steering.u_steer.steered_bd_ifindex,
                                  o2->u.steering.u_steer.steered_bd_ifindex);

        case L2_FWD_MAX:
        default:
            break;
    }

    return 0;
}

void
dp_l2fwd_objects_init (dp_ctx_t *dp_ctx)
{
    int i;

    for (i = 0; i < L2_FWD_MAX; i++) {
        dp_ctx->l2_fwd_obj_tree[i] = (avltree_t *)XCALLOC2(0, 1, avltree_t);
        avltree_init(dp_ctx->l2_fwd_obj_tree[i], L2_forward_object_comp_fb);
    }
}

mac_fwd_object_t *
dp_ctx_lookup_mac_fwd_object (avltree_t *tree, mac_fwd_object_t *tmplate)
{
    avltree_node_t *node;

    if (!tree || !tmplate)
        return NULL;

    node = avltree_lookup(&tmplate->glue, tree);
    if (!node)
        return NULL;

    return avltree_container_of(node, mac_fwd_object_t, glue);
}

bool
dp_ctx_insert_fwd_object (avltree_t *tree, mac_fwd_object_t *fwd_obj)
{
    if (!tree || !fwd_obj)
        return false;

    avltree_node_init(&fwd_obj->glue);

    if (avltree_insert(&fwd_obj->glue, tree))
        return false;

    assert (fwd_obj->ref_count == 0);

    return true;
}

static void
mac_fwd_object_copy_union (mac_fwd_object_t *dst, mac_fwd_object_t *src)
{
    /* Shared/external objects (intf, vrf) are pointer-copied, not cloned.
        Heap payloads owned by this object (label stack, SID list) are
        deep-copied so src and dst do not free the same buffer. */
    switch (src->fwd_type) {

        case L2_FWD_PORT:
            dst->u.dp_intf = src->u.dp_intf;
            break;

        case L2_FWD_FLOODING:
            dst->u.l2_flood.vfif = src->u.l2_flood.vfif;
            dst->u.l2_flood.vlan_bd_port = src->u.l2_flood.vlan_bd_port;
            break;

        case L2_FWD_MPLS_TUNNEL:
            dst->u.lbl_stk = NULL;
            if (src->u.lbl_stk) {
                dst->u.lbl_stk = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                memcpy(dst->u.lbl_stk, src->u.lbl_stk, sizeof(mpls_lstack_t));
            }
            break;

        case L2_FWD_SRv6_TUNNEL:
            dst->u.srv6.seg_lst_cnt = src->u.srv6.seg_lst_cnt;
            dst->u.srv6.seg_lst = NULL;
            if (src->u.srv6.seg_lst && src->u.srv6.seg_lst_cnt) {
                size_t nbytes = (size_t)src->u.srv6.seg_lst_cnt * 16;
                dst->u.srv6.seg_lst = (uint8_t (*)[][16])XCALLOC_BUFF(0, nbytes);
                memcpy(dst->u.srv6.seg_lst, src->u.srv6.seg_lst, nbytes);
            }
            break;

        case L2_FWD_VxLAN:
            dst->u.vxlan.l2vni = src->u.vxlan.l2vni;
            dst->u.vxlan.vtep_ip = src->u.vxlan.vtep_ip;
            break;

        case L2_FWD_STEERING:
            dst->u.steering.steering_type = src->u.steering.steering_type;
            dst->u.steering.u_steer.steered_vrf = src->u.steering.u_steer.steered_vrf;
            dst->u.steering.u_steer.steered_bd_ifindex = src->u.steering.u_steer.steered_bd_ifindex;
            break;

        case L2_FWD_MAX:
        default:
            break;
    }
}

static void
mac_fwd_object_free_owned (mac_fwd_object_t *fwd_obj)
{
    switch (fwd_obj->fwd_type) {

        case L2_FWD_MPLS_TUNNEL:
            if (fwd_obj->u.lbl_stk) {
                XFREE(fwd_obj->u.lbl_stk);
                fwd_obj->u.lbl_stk = NULL;
            }
            break;

        case L2_FWD_SRv6_TUNNEL:
            if (fwd_obj->u.srv6.seg_lst) {
                XFREE(fwd_obj->u.srv6.seg_lst);
                fwd_obj->u.srv6.seg_lst = NULL;
            }
            break;

        default:
            break;
    }
}

mac_fwd_object_t *
mac_fwd_object_clone (mac_fwd_object_t *fwd_obj_src, mac_fwd_object_t *fwd_obj_dst)
{
    if (!fwd_obj_src)
        return NULL;

    if (!fwd_obj_dst)
        fwd_obj_dst = (mac_fwd_object_t *)XCALLOC2(0, 1, mac_fwd_object_t);

    memcpy(fwd_obj_dst, fwd_obj_src, sizeof(*fwd_obj_src));
    fwd_obj_dst->ref_count = 0;
    avltree_node_init(&fwd_obj_dst->glue);
    memset(&fwd_obj_dst->u, 0, sizeof(fwd_obj_dst->u));
    mac_fwd_object_copy_union(fwd_obj_dst, fwd_obj_src);

    return fwd_obj_dst;
}

void
mac_fwd_object_reference (mac_fwd_object_t *fwd_obj)
{
    fwd_obj->ref_count++;
}

void
mac_fwd_object_dereference (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj)
{
    assert(fwd_obj);
    assert(fwd_obj->ref_count);

    fwd_obj->ref_count--;
    if (fwd_obj->ref_count)
        return;

    
    assert(avltree_remove(&fwd_obj->glue, dp_ctx->l2_fwd_obj_tree[fwd_obj->fwd_type]));
    mac_fwd_object_free_owned(fwd_obj);
    XFREE(fwd_obj);
}

