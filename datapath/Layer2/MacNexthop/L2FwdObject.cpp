#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "L2FwdObject.h"
#include "../../Interface/dp_intf.h"
#include "../../Interface/dp_intf_store.h"
#include "../../dp_ctx.h"
#include "../../dp_utils.h"
#include "../../../libs/common/mpls_lstack.h"
#include "../../../libs/common/l2_hdrs.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../vxlan/vlan_vni_ht.h"
#include "../../../tcpconst.h"
#include "../../../libs/common/l3_hdrs.h"
#include "../../FIB/fib_nh.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp-program/dp-prog-struct.h"
#include "../../Layer3/layer3.h"
#include "../../Layer3/ipv6/ipv6-fwd.h"

extern void
dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                        dp_vrf_t *vrf,
                        uint32_t next_hop_ip,
                        dp_intf_t *oif,
                        struct rte_mbuf *mbuf,
                        gen_proto_id_t hdr_type);
#include "../../Layer3/SRv6/srv6-endpoint.h"
#include "../../../libs/common/ipv6_hdrs.h"

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
                struct rte_mbuf *mbuf, uint32_t ctx);

static dp_intf_t *
l2_fwd_resolve_port (dp_ctx_t *dp_ctx, uint32_t ifindex)
{
    if (ifindex >= DP_MAX_INTF)
        return NULL;
    return dp_ctx->intf_table[ifindex];
}

static void
l2_flood_forwarding (dp_ctx_t *dp_ctx,
                    mac_fwd_object_t *fwd_obj,
                    struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == L2_FWD_FLOODING);
    assert (fwd_obj->u.l2_flood.vfif);
    assert (fwd_obj->u.l2_flood.vfif->if_type == DP_INTF_TYPE_VLAN_FLOOD ||
            fwd_obj->u.l2_flood.vfif->if_type == DP_INTF_TYPE_BD_FLOOD);

    dp_send_pkt_out(dp_ctx, fwd_obj->u.l2_flood.vfif,
                    mbuf,
                    fwd_obj->u.l2_flood.vlan_bd_port);
}

static void
l2_tunnel_strip_eth_fcs_if_needed(struct rte_mbuf *mbuf)
{
    if (pkt_mbuf_get_starting_hdr(mbuf) == ETHERNET_HEADER)
        pkt_mbuf_slide(mbuf, 1, -1, ETH_FCS_SIZE);
}

static void
l2_mpls_tunnel_forwarding (dp_ctx_t *dp_ctx,
                           mac_fwd_object_t *fwd_obj,
                           struct rte_mbuf *mbuf) {

    mpls_lstack_t *lstack;
    bool top_hdr_is_mpls;
    gen_proto_id_t hdr_type;
    pkt_size_t pkt_size = 0;
    char ops_buf[128];
    char wire_buf[128];

    assert (fwd_obj->fwd_type == L2_FWD_MPLS_TUNNEL);
    assert (fwd_obj->u.mpls_tunnel.lbl_stk);

    hdr_type = pkt_mbuf_get_starting_hdr(mbuf);
    pkt_mbuf_get_pkt(mbuf, &pkt_size);

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
        "L2 MPLS tunnel: enter start_hdr=%u size=%u oif=%u nh=%u.%u.%u.%u\n",
        (unsigned)hdr_type, (unsigned)pkt_size,
        fwd_obj->u.mpls_tunnel.oif_ifindex,
        (fwd_obj->u.mpls_tunnel.nh_ip >> 24) & 0xFF,
        (fwd_obj->u.mpls_tunnel.nh_ip >> 16) & 0xFF,
        (fwd_obj->u.mpls_tunnel.nh_ip >> 8) & 0xFF,
        fwd_obj->u.mpls_tunnel.nh_ip & 0xFF);

    /* Prevent Split horizon, if the pkt is recvd from the same MPLS
        Overlay, do not pump back it again to MPLS Overlay again */
    uint32_t recv_intf_index =  pkt_mbuf_get_ingress_ifindex(mbuf);

    if (recv_intf_index == MPLS_TO_BD_INTF_STEER_IFINDEX) {

        pkt_tracer(mbuf, dp_ctx->dptr, DTUNNEL_DET,
            "Pkt:%s Split Horizon Prevented, Pkt is dropped\n", 
            pkt_mbuf_str(mbuf));

        return;
    }

    pkt_mbuf_clear_ingress_intf(mbuf);

    lstack = fwd_obj->u.mpls_tunnel.lbl_stk;
    if (mpls_lstack_is_empty(lstack)) {
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET | DERR,
            "L2 MPLS tunnel: empty label stack, dropping\n");
        dp_ctx->pkt_dropped++;
        return;
    }

    mpls_format_lstack(lstack, ops_buf, sizeof(ops_buf));
    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
        "L2 MPLS tunnel: configured nh_ops=[%s] (index 0=BoS)\n", ops_buf);

    /* Merge into existing MPLS header or impose a new stack on the L2 payload. */
    top_hdr_is_mpls = mpls_apply_nh_label_stack(dp_ctx, mbuf, lstack);
    if (!top_hdr_is_mpls) {
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET | DERR,
            "L2 MPLS tunnel: label stack did not produce MPLS header, dropping\n");
        dp_ctx->pkt_dropped++;
        return;
    }

    /* Trace labels from the packet header (outer → inner), not from lstack. */
    {
        mpls_label_wire_t *pkt_label =
            (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
        mpls_format_wire_stack(pkt_label, (size_t)pkt_size, wire_buf, sizeof(wire_buf));
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
            "L2 MPLS tunnel: imposed label stack [outer->inner]: [%s] size=%u\n",
            wire_buf, (unsigned)pkt_size);
    }
    
    pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_MPLS_IN_IP);

    /* If fwd Object is already resolved, then pass it down to L2 Layer,
        if not resolved (actually partially resolved, which is only possible) 
        is you install the Type 2 EVPN route statically) then do run time 
        resolution by passing it to  LFIB for forwarding */
    if (fwd_obj->u.mpls_tunnel.nh_ip &&
        fwd_obj->u.mpls_tunnel.oif_ifindex) {

        dp_intf_t *oif =
            dp_ctx->intf_table[fwd_obj->u.mpls_tunnel.oif_ifindex];

        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
                "L2 MPLS tunnel: direct L2 encap OIF %s nh %u.%u.%u.%u\n",
                oif->if_name,
                (fwd_obj->u.mpls_tunnel.nh_ip >> 24) & 0xFF,
                (fwd_obj->u.mpls_tunnel.nh_ip >> 16) & 0xFF,
                (fwd_obj->u.mpls_tunnel.nh_ip >> 8) & 0xFF,
                fwd_obj->u.mpls_tunnel.nh_ip & 0xFF);

        dp_demote_pkt_to_layer2(dp_ctx, dp_ctx->default_vrf,
                                    fwd_obj->u.mpls_tunnel.nh_ip,
                                    oif, mbuf, IP_PROTO_MPLS_IN_IP);
        return;
    }

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
        "L2 MPLS tunnel: handing to LFIB (dp_mpls_fwd_pkt) in default VRF\n");

    dp_mpls_fwd_pkt(dp_ctx, dp_ctx->default_vrf, NULL, mbuf);
}

static void
l2_srv6_tunnel_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj,
                           struct rte_mbuf *mbuf) {

    gen_proto_id_t hdr_type;
    srh_hdr_t *srh = NULL;
    ipv6_addr_t *seg_lst = NULL;
    uint8_t seg_cnt;
    dp_vrf_t *vrf;

    assert (fwd_obj->fwd_type == L2_FWD_SRv6_TUNNEL);
    assert (fwd_obj->u.srv6.seg_lst_cnt);
    assert (fwd_obj->u.srv6.seg_lst);

    seg_cnt = fwd_obj->u.srv6.seg_lst_cnt;

    if (!seg_cnt) {
        dp_ctx->pkt_dropped++;
        return;
    }

    /* Prevent Split horizon, if the pkt is recvd from the same SRv6 
        Overlay, do not pump back it again to SRv6 Overlay again */
    uint32_t recv_intf_index =  pkt_mbuf_get_ingress_ifindex(mbuf);

    if (recv_intf_index == SRv6_TO_BD_STEER_IFINDEX) {

        pkt_tracer(mbuf, dp_ctx->dptr, DTUNNEL_DET,
            "Pkt:%s Split Horizon Prevented, Pkt is dropped\n", 
            pkt_mbuf_str(mbuf));

        return;
    }

    pkt_mbuf_clear_ingress_intf(mbuf);

    vrf = dp_ctx->default_vrf;
    
    hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    if (hdr_type == IP_PROTO_IPv6) {

        pkt_size_t pkt_size;
        byte *pkt = pkt_mbuf_get_pkt(mbuf, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

        if (ipv6_hdr->next_header == IP_PROTO_SRH &&
            pkt_size >= sizeof(ipv6_hdr_t) + sizeof(srh_hdr_t)) {

            /* Merge fwd_obj segment list ahead of the remaining SRH segments. */
            srh_hdr_t *old_srh = (srh_hdr_t *)(ipv6_hdr + 1);
            uint8_t old_sl = old_srh->segments_left;
            uint8_t old_remaining = (uint8_t)(old_sl + 1);
            uint8_t total = (uint8_t)(seg_cnt + old_remaining);

            seg_lst = (ipv6_addr_t *)XCALLOC_BUFF(0, total * sizeof(ipv6_addr_t));

            for (uint8_t i = 0; i < seg_cnt; i++)
                memcpy(seg_lst[i].addr, (*fwd_obj->u.srv6.seg_lst)[i], 16);

            for (uint8_t j = 0; j < old_remaining; j++)
                memcpy(seg_lst[seg_cnt + j].addr,
                       old_srh->segments[old_sl - j], 16);

            Srv6_decapsulate(mbuf);
            srh = srh_hdr_prepare(seg_lst, total);
            XFREE(seg_lst);
            seg_lst = NULL;
        }
        else {

            /* Bare IPv6 outer header: peel it, then SRv6-encapsulate the payload. */
            Srv6_decapsulate(mbuf);
            seg_lst = (ipv6_addr_t *)XCALLOC_BUFF(0, seg_cnt * sizeof(ipv6_addr_t));

            for (uint8_t i = 0; i < seg_cnt; i++)
                memcpy(seg_lst[i].addr, (*fwd_obj->u.srv6.seg_lst)[i], 16);

            srh = srh_hdr_prepare(seg_lst, seg_cnt);
            XFREE(seg_lst);
        }
    }
    else {

        seg_lst = (ipv6_addr_t *)XCALLOC_BUFF(0, seg_cnt * sizeof(ipv6_addr_t));

        for (uint8_t i = 0; i < seg_cnt; i++)
            memcpy(seg_lst[i].addr, (*fwd_obj->u.srv6.seg_lst)[i], 16);

        srh = srh_hdr_prepare(seg_lst, seg_cnt);
        XFREE(seg_lst);
    }

    Srv6_encapsulate(mbuf, srh);
    XFREE(srh);

    pkt_tracer(mbuf, dp_ctx->dptr, DL3FWD | DL2FWD,
        "L2 SRv6 tunnel: encapsulated with %u segment(s), forwarding in default VRF\n",
        seg_cnt);

    layer3_ipv6_route_pkt(dp_ctx, vrf, NULL, mbuf, NULL);
}

static void
l2_vxlan_tunnel_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj,
                            struct rte_mbuf *mbuf) {

    uint32_t vni;
    dp_intf_t *nve;
    pkt_mbuf_pvt_data_t *pvt_data;
    pkt_mbuf_encap_meta_data_t *encap_data;

    assert (fwd_obj->fwd_type == L2_FWD_VxLAN);

    nve = DP_NVE_INTF(dp_ctx);

    /* Prevent Split horizon, if the pkt is recvd from the same NVE 
        interface, do not pump back it again to VxLAN Overlay again */
    uint32_t recv_intf_index =  pkt_mbuf_get_ingress_ifindex(mbuf);

    if (recv_intf_index == NVE_IFINDEX) {

        pkt_tracer(mbuf, dp_ctx->dptr, DTUNNEL_DET,
            "Pkt:%s Split Horizon Prevented, Pkt is dropped\n", 
            pkt_mbuf_str(mbuf));

        return;
    }

    pkt_mbuf_clear_ingress_intf(mbuf);

    vni = fwd_obj->u.vxlan.l2vni;
    if (!vni) {
        ethernet_hdr_t *eth =
            (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL);
        vlan_8021q_hdr_t *vlan_hdr = eth ? is_pkt_vlan_tagged(eth) : NULL;
        if (vlan_hdr)
            vni = vlan_vni_ht_vlan_to_vni_lookup(dp_ctx,
                                                 (uint16_t)TCI_VID(vlan_hdr->tci));
    }

    if (!vni || !fwd_obj->u.vxlan.vtep_ip) {
        dp_ctx->pkt_dropped++;
        return;
    }

    encap_data = (pkt_mbuf_encap_meta_data_t *)XCALLOC2(0, 1, pkt_mbuf_encap_meta_data_t);
    encap_data->u.vxlan.vni = vni;
    encap_data->u.vxlan.remote_vtep_ip = fwd_obj->u.vxlan.vtep_ip;

    pvt_data = pkt_mbuf_get_pvt_data(mbuf);
    if (pvt_data->encap_data)
        XFREE(pvt_data->encap_data);
    pvt_data->encap_data = encap_data;

    dp_send_pkt_out(dp_ctx, nve, mbuf, 0);
}

static void
mpls_l2_steer_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj,
                            struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == MPLS_L2_FWD_STEERING);

    switch (fwd_obj->u.steering.steering_type) {

        case STEER_INTO_VRF:
            assert (fwd_obj->u.steering.u_steer.steered_obj_ifindex );
            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS | DL2FWD,
                "MPLS L2 steer: into VRF ifindex=%u\n",
                fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            assert(pkt_mbuf_verify_pkt (mbuf, IP_PROTO_IP_IN_IP));
            /* Steer into VRF */
            dp_send_pkt_out(dp_ctx, dp_ctx->intf_table[DP_INTF_TYPE_MPLS_TO_VRF_STEER], 
                mbuf, fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            break;
        case STEER_INTO_BD:
            assert (fwd_obj->u.steering.u_steer.steered_obj_ifindex );
            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS | DL2FWD,
                "MPLS L2 steer: into BD ifindex=%u\n",
                fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            assert(pkt_mbuf_verify_pkt (mbuf, ETHERNET_HEADER));
            /* Steer into BD */
            dp_send_pkt_out(dp_ctx, dp_ctx->intf_table[DP_INTF_TYPE_MPLS_TO_BD_STEER], 
                mbuf, fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            break;
        default:
            assert(0);
    }
}

static void
srv6_l2_steer_forwarding (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj,
                            struct rte_mbuf *mbuf) {

    assert (fwd_obj->fwd_type == MPLS_L2_FWD_STEERING);

    switch (fwd_obj->u.steering.steering_type) {

        case STEER_INTO_VRF:
            assert (fwd_obj->u.steering.u_steer.steered_obj_ifindex );
            assert(pkt_mbuf_verify_pkt (mbuf, IP_PROTO_IP_IN_IP));
            /* Steer into VRF */
            dp_send_pkt_out(dp_ctx, dp_ctx->intf_table[DP_INTF_TYPE_SRV6_TO_VRF_STEER], 
                mbuf, fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            break;
        case STEER_INTO_BD:
            assert (fwd_obj->u.steering.u_steer.steered_obj_ifindex );
            assert(pkt_mbuf_verify_pkt (mbuf, ETHERNET_HEADER));
            /* Steer into BD */
            dp_send_pkt_out(dp_ctx, dp_ctx->intf_table[DP_INTF_TYPE_SRV6_TO_BD_STEER], 
                mbuf, fwd_obj->u.steering.u_steer.steered_obj_ifindex);
            break;
        default:
            assert(0);
    }
}

static void
l2_port_forwarding (dp_ctx_t *dp_ctx,
                    mac_fwd_object_t *fwd_obj,
                    struct rte_mbuf *mbuf) {

    dp_intf_t *oif;
    dp_intf_t *ingress;

    assert (fwd_obj->fwd_type == L2_FWD_PORT);
    oif = l2_fwd_resolve_port(dp_ctx, fwd_obj->u.dp_intf);
    if (!oif) return;
    ingress = pkt_mbuf_get_ingress_intf(dp_ctx, mbuf);
    if (oif == ingress) return;
    dp_send_pkt_out(dp_ctx, oif->ac_intf ? oif->ac_intf : oif, mbuf, 0);
}

static void
l2_rmac_forwarding (dp_ctx_t *dp_ctx,
                    mac_fwd_object_t *fwd_obj,
                    struct rte_mbuf *mbuf) {

    uint32_t vlan_bd_port;
    dp_intf_t *vlan_intf;
    ethernet_hdr_t *eth_hdr;
    vlan_8021q_hdr_t *vlan_hdr;

    assert (fwd_obj->fwd_type == L2_FWD_RMAC);

    vlan_bd_port = fwd_obj->u.rmac.vlan_bd_port;

    if (!vlan_bd_port) {
        eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);
        vlan_hdr = is_pkt_vlan_tagged(eth_hdr);
        if (vlan_hdr) {
            vlan_intf = dp_look_up_interface_by_vlan_id(
                            dp_ctx->dp_vlan_intf_ht,
                            (uint16_t)GET_802_1Q_VLAN_ID(vlan_hdr));
            if (vlan_intf)
                vlan_bd_port = vlan_intf->port_id;
        }
    }

    dp_send_pkt_out(dp_ctx, fwd_obj->u.rmac.rmacif, mbuf, vlan_bd_port);
}

/* Maintained in the order of L2_FWD_TYPE_T enums */
static l2_fwding_ptr l2_fwding[] =
 {
    l2_port_forwarding,
    l2_rmac_forwarding,
    l2_flood_forwarding,
    l2_mpls_tunnel_forwarding,
    l2_srv6_tunnel_forwarding,
    l2_vxlan_tunnel_forwarding,
    mpls_l2_steer_forwarding,
    srv6_l2_steer_forwarding, /* Not used */
    0
 };

void
dp_l2fwd (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, struct rte_mbuf *mbuf) {

    if (!fwd_obj || fwd_obj->fwd_type >= L2_FWD_MAX) {
        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD_DET | DERR,
            "dp_l2fwd: invalid fwd_obj type, drop\n");
        return;
    }

    if (!l2_fwding[fwd_obj->fwd_type]) {
        pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD_DET | DERR,
            "dp_l2fwd: no handler for fwd_type %u\n",
            (unsigned)fwd_obj->fwd_type);
        return;
    }

    pkt_tracer(mbuf, dp_ctx->dptr, DL2FWD_DET,
        "dp_l2fwd: dispatch fwd_type=%u\n", (unsigned)fwd_obj->fwd_type);

    fwd_obj->hit_count++;
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
            return l2_fwd_cmp_u32(o1->u.dp_intf, o2->u.dp_intf);

        case L2_FWD_RMAC:
            rc = l2_fwd_cmp_ptr(o1->u.rmac.rmacif, o2->u.rmac.rmacif);
            if (rc) return rc;
            return l2_fwd_cmp_u32(o1->u.rmac.vlan_bd_port,
                                  o2->u.rmac.vlan_bd_port);

        case L2_FWD_FLOODING:
            rc = l2_fwd_cmp_ptr(o1->u.l2_flood.vfif, o2->u.l2_flood.vfif);
            if (rc)
                return rc;
            return l2_fwd_cmp_u32(o1->u.l2_flood.vlan_bd_port,
                                  o2->u.l2_flood.vlan_bd_port);

        case L2_FWD_MPLS_TUNNEL: {
            int rc_oif = l2_fwd_cmp_u32(o1->u.mpls_tunnel.oif_ifindex,
                                        o2->u.mpls_tunnel.oif_ifindex);
            int rc_nh = l2_fwd_cmp_u32(o1->u.mpls_tunnel.nh_ip,
                                       o2->u.mpls_tunnel.nh_ip);
            if (rc_oif)
                return rc_oif;
            if (rc_nh)
                return rc_nh;
            if (!o1->u.mpls_tunnel.lbl_stk && !o2->u.mpls_tunnel.lbl_stk)
                return 0;
            if (!o1->u.mpls_tunnel.lbl_stk || !o2->u.mpls_tunnel.lbl_stk)
                return o1->u.mpls_tunnel.lbl_stk ? 1 : -1;
            return mpls_lstack_compare(o1->u.mpls_tunnel.lbl_stk,
                                      o2->u.mpls_tunnel.lbl_stk) ? 0 : -1;
        }

        case L2_FWD_SRv6_TUNNEL: {
            int rc_oif = l2_fwd_cmp_u32(o1->u.srv6.oif_ifindex,
                                        o2->u.srv6.oif_ifindex);
            int rc_nh = l2_fwd_cmp_u32(o1->u.srv6.nh_ip,
                                       o2->u.srv6.nh_ip);
            if (rc_oif)
                return rc_oif;
            if (rc_nh)
                return rc_nh;
            rc = l2_fwd_cmp_u32(o1->u.srv6.seg_lst_cnt,
                                o2->u.srv6.seg_lst_cnt);
            if (rc)
                return rc;
            return l2_fwd_cmp_ptr(o1->u.srv6.seg_lst, o2->u.srv6.seg_lst);
        }

        case L2_FWD_VxLAN:
            rc = l2_fwd_cmp_u32(o1->u.vxlan.l2vni, o2->u.vxlan.l2vni);
            if (rc)
                return rc;
            return l2_fwd_cmp_u32(o1->u.vxlan.vtep_ip, o2->u.vxlan.vtep_ip);

        case MPLS_L2_FWD_STEERING:
        case SRV6_L2_FWD_STEERING:
            rc = l2_fwd_cmp_u32(o1->u.steering.steering_type,
                                o2->u.steering.steering_type);
            if (rc)
                return rc;
            return l2_fwd_cmp_u32(o1->u.steering.u_steer.steered_obj_ifindex,
                                  o2->u.steering.u_steer.steered_obj_ifindex);

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

        case L2_FWD_RMAC:
            dst->u.rmac.rmacif = src->u.rmac.rmacif;
            dst->u.rmac.vlan_bd_port = src->u.rmac.vlan_bd_port;
            break;

        case L2_FWD_FLOODING:
            dst->u.l2_flood.vfif = src->u.l2_flood.vfif;
            dst->u.l2_flood.vlan_bd_port = src->u.l2_flood.vlan_bd_port;
            break;

        case L2_FWD_MPLS_TUNNEL:
            dst->u.mpls_tunnel.oif_ifindex = src->u.mpls_tunnel.oif_ifindex;
            dst->u.mpls_tunnel.nh_ip = src->u.mpls_tunnel.nh_ip;
            dst->u.mpls_tunnel.lbl_stk = NULL;
            if (src->u.mpls_tunnel.lbl_stk) {
                dst->u.mpls_tunnel.lbl_stk =
                    (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                memcpy(dst->u.mpls_tunnel.lbl_stk, src->u.mpls_tunnel.lbl_stk,
                       sizeof(mpls_lstack_t));
            }
            break;

        case L2_FWD_SRv6_TUNNEL:
            dst->u.srv6.seg_lst_cnt = src->u.srv6.seg_lst_cnt;
            dst->u.srv6.oif_ifindex = src->u.srv6.oif_ifindex;
            dst->u.srv6.nh_ip = src->u.srv6.nh_ip;
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

        case MPLS_L2_FWD_STEERING:
        case SRV6_L2_FWD_STEERING:
            dst->u.steering.steering_type = src->u.steering.steering_type;
            dst->u.steering.u_steer.steered_obj_ifindex =
                src->u.steering.u_steer.steered_obj_ifindex;
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
            if (fwd_obj->u.mpls_tunnel.lbl_stk) {
                XFREE(fwd_obj->u.mpls_tunnel.lbl_stk);
                fwd_obj->u.mpls_tunnel.lbl_stk = NULL;
            }
            fwd_obj->u.mpls_tunnel.oif_ifindex = 0;
            fwd_obj->u.mpls_tunnel.nh_ip = 0;
            break;

        case L2_FWD_SRv6_TUNNEL:
            if (fwd_obj->u.srv6.seg_lst) {
                XFREE(fwd_obj->u.srv6.seg_lst);
                fwd_obj->u.srv6.seg_lst = NULL;
            }
            fwd_obj->u.srv6.seg_lst_cnt = 0;
            fwd_obj->u.srv6.oif_ifindex = 0;
            fwd_obj->u.srv6.nh_ip = 0;
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
    fwd_obj_dst->hit_count = 0;
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

void
mac_fwd_object_spec_init (mac_fwd_object_spec_t *spec)
{
    memset(spec, 0, sizeof(*spec));
}

void
mac_fwd_object_spec_from_ifindex (mac_fwd_object_spec_t *spec,
                                  uint32_t ifindex,
                                  uint32_t remote_dst_ip,
                                  uint32_t vlan_bd_ifindex)
{
    mac_fwd_object_spec_init(spec);

    if (ifindex == NVE_IFINDEX && remote_dst_ip) {
        spec->fwd_type = L2_FWD_VxLAN;
        spec->u.vxlan.vtep_ip = remote_dst_ip;
        return;
    }

    if (ifindex == VLAN_FLOOD_INDEX || ifindex == BD_FLOOD_IFINDEX) {
        spec->fwd_type = L2_FWD_FLOODING;
        spec->u.flood.vfif_ifindex = ifindex;
        spec->u.flood.vlan_bd_port = vlan_bd_ifindex;
        return;
    }

    if (ifindex == RMAC_INTF_INDEX || ifindex == BD_RMAC_INTF_INDEX) {
        spec->fwd_type = L2_FWD_RMAC;
        spec->u.rmac.rmacif = ifindex;
        spec->u.rmac.vlan_bd_port = vlan_bd_ifindex;
        return;
    }

    spec->fwd_type = L2_FWD_PORT;
    spec->u.dp_intf = ifindex;
}

void
mac_fwd_object_spec_from_mpls_tunnel (mac_fwd_object_spec_t *spec,
                                      const mpls_lstack_t *label_stack,
                                      uint32_t oif_ifindex,
                                      uint32_t nh_ip)
{
    mac_fwd_object_spec_init(spec);
    spec->fwd_type = L2_FWD_MPLS_TUNNEL;
    spec->u.mpls_tunnel.oif_ifindex = oif_ifindex;
    spec->u.mpls_tunnel.nh_ip = nh_ip;

    if (label_stack)
        memcpy(&spec->u.mpls_tunnel.label_stack, label_stack,
               sizeof(spec->u.mpls_tunnel.label_stack));
}

void
dp_mac_fwd_object_init_from_spec (dp_ctx_t *dp_ctx,
                                  mac_fwd_object_t *tmpl,
                                  const mac_fwd_object_spec_t *spec,
                                  uint32_t overlay_vlan)
{
    dp_intf_t *intf;

    assert(tmpl && spec);
    memset(tmpl, 0, sizeof(*tmpl));
    avltree_node_init(&tmpl->glue);

    tmpl->fwd_type = (L2_FWD_TYPE_T)spec->fwd_type;

    switch (tmpl->fwd_type) {

        case L2_FWD_PORT:
            tmpl->u.dp_intf = spec->u.dp_intf;
            break;

        case L2_FWD_RMAC:
            tmpl->u.rmac.rmacif = dp_ctx->intf_table[spec->u.rmac.rmacif];
            tmpl->u.rmac.vlan_bd_port = spec->u.rmac.vlan_bd_port;
            break;

        case L2_FWD_FLOODING:
            if (spec->u.flood.vfif_ifindex < DP_MAX_INTF)
                tmpl->u.l2_flood.vfif =
                    dp_ctx->intf_table[spec->u.flood.vfif_ifindex];
            tmpl->u.l2_flood.vlan_bd_port = spec->u.flood.vlan_bd_port;
            break;

        case L2_FWD_VxLAN:
            tmpl->u.vxlan.vtep_ip = spec->u.vxlan.vtep_ip;
            tmpl->u.vxlan.l2vni = spec->u.vxlan.l2vni;
            if (!tmpl->u.vxlan.l2vni && overlay_vlan &&
                overlay_vlan != DEFAULT_VLAN_ID)
                tmpl->u.vxlan.l2vni =
                    vlan_vni_ht_vlan_to_vni_lookup(dp_ctx, (uint16_t)overlay_vlan);
            break;

        case MPLS_L2_FWD_STEERING:
        case SRV6_L2_FWD_STEERING:
            tmpl->u.steering.steering_type = spec->u.steering.steering_type;
            tmpl->u.steering.u_steer.steered_obj_ifindex =
                spec->u.steering.steered_obj_ifindex;
            break;

        case L2_FWD_MPLS_TUNNEL:
            tmpl->u.mpls_tunnel.oif_ifindex = spec->u.mpls_tunnel.oif_ifindex;
            tmpl->u.mpls_tunnel.nh_ip = spec->u.mpls_tunnel.nh_ip;
            tmpl->u.mpls_tunnel.lbl_stk =
                (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
            memcpy(tmpl->u.mpls_tunnel.lbl_stk,
                   &spec->u.mpls_tunnel.label_stack,
                   sizeof(*tmpl->u.mpls_tunnel.lbl_stk));
            break;

        case L2_FWD_SRv6_TUNNEL:
        case L2_FWD_MAX:
        default:
            break;
    }
}

mac_fwd_object_t *
dp_l2fwd_object_acquire (dp_ctx_t *dp_ctx, mac_fwd_object_t *tmplate)
{
    avltree_t *tree;
    mac_fwd_object_t *found;
    mac_fwd_object_t *obj;

    if (!dp_ctx || !tmplate || tmplate->fwd_type >= L2_FWD_MAX)
        return NULL;

    tree = dp_ctx->l2_fwd_obj_tree[tmplate->fwd_type];
    found = dp_ctx_lookup_mac_fwd_object(tree, tmplate);
    if (found) {
        mac_fwd_object_reference(found);
        return found;
    }

    obj = mac_fwd_object_clone(tmplate, NULL);
    if (!obj)
        return NULL;

    if (!dp_ctx_insert_fwd_object(tree, obj)) {
        found = dp_ctx_lookup_mac_fwd_object(tree, tmplate);
        mac_fwd_object_free_owned(obj);
        XFREE(obj);
        if (!found)
            return NULL;
        mac_fwd_object_reference(found);
        return found;
    }

    mac_fwd_object_reference(obj);
    return obj;
}

bool 
dp_mac_table_is_invalid_l2_fwding (dp_ctx_t *dp_ctx, 
                                   uint8_t VLAN_OR_BD,
                                   uint32_t bd_vlan_ifindex,
                                   mac_fwd_object_t *tmplate) {

    switch (tmplate->fwd_type) 
    {
        case L2_FWD_VxLAN:
        {
            /* Do not install VxLAN Tunnels to self */

            fib_nh_t *nh;

            uint32_t vtep_ip = tmplate->u.vxlan.vtep_ip;

            /* This IP should not be 0.inet FIB as local route*/
            cmn_prefix_t prefix; 
            cmn_prefix_initialize_v4 (&prefix, vtep_ip, 32);

            switch ((DP_COMPONENT_TYPE_T)VLAN_OR_BD) 
            {
                case MAC_TABLE:
                    {
                        dp_vrf_t *def_vrf = dp_look_up_vrf(dp_ctx, DEFAULT_VRF);
                        nh = fib_get_forwarding_nh(def_vrf->fib_inet0, &prefix);

                        if (nh &&
                            ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_CONNECTED) || 
                            (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL))) {

                            return true;   
                        }
                    }
                    break;

                case BD_MAC_TABLE:
                {
                    dp_vrf_t *vrf;
                    dp_intf_t *bd_intf = dp_ctx->intf_table[bd_vlan_ifindex];
                    assert (bd_intf);
                    if (!bd_intf->vrf) vrf = dp_look_up_vrf(dp_ctx, DEFAULT_VRF);
                    else vrf = bd_intf->vrf;
                    nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

                    if (nh &&
                        ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_CONNECTED) ||
                        (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL))) {

                        return true;
                    }
                }
                break;
            }
        }
        break;        
    }

    return false;
}