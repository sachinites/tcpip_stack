#include <assert.h>
#include <arpa/inet.h>

#include "ipv6-fwd.h"
#include "../layer3.h"
#include "../../../tcpconst.h"
#include "../../../libs/pkt-block/pkt_block.h"

#include "../../FIB/fib_nh.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_ctx.h"

#include "../../../libs/Tracer/tracer.h"
#include "../../Interface/dp_intf_log.h"
#include "../../Vrfs/dp_vrf.h"
#include "../SRv6/srv6-endpoint.h"

extern void
dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf,
                     uint32_t next_hop_ip,
                     dp_intf_t *outgoing_intf,
                     pkt_block_t *pkt_block,
                     gen_proto_id_t hdr_type);


void 
ipv6_layer3_forward_nexthop (dp_ctx_t *dp_ctx, 
                dp_vrf_t *vrf, 
                fib_nh_t *nexthop, 
                pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    unsigned char *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    dp_intf_t *oif = nexthop->fwd_info->oif;

    if (!oif) return;

    /* If the ipv6 hdr do not have any src address yet, because it is locally generated pkt, use OIF ipv6 link local address */
    if (is_ipv6_addr_unspecified (&ipv6_hdr->src_addr) && 
        !is_ipv6_addr_unspecified ((uint8_t (*)[16])oif->v6addr_link_local)) {

        memcpy (ipv6_hdr->src_addr, oif->v6addr_link_local, 16);
    }

    ipv6_hdr->hop_limit--;

    if (ipv6_hdr->hop_limit == 0) {

        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Pkt Dropped : TTL Expired\n", 
            vrf->vrf_name, pkt_block_str(pkt_block));
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
        vrf->vrf_name, pkt_block_str(pkt_block), oif->if_name , "::");

    tcp_dump_l3_fwding_logger(dp_ctx, vrf,  (c_string)oif->if_name, 0);

    dp_demote_pkt_to_layer2(
            dp_ctx,
            vrf,
            0,
            oif,
            pkt_block,
            IP_PROTO_IPv6);

    nexthop->hit_count++;
}

void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx, 
                           dp_vrf_t *vrf,
                           dp_intf_t *interface,
                           pkt_block_t *pkt_block,
                           fib_nh_t *_nh)
{
    fib_nh_t *nh = _nh;
    pkt_size_t pkt_size;
    char dst_addr_str[48];
    char route_addr_str[48];
    cmn_prefix_t prefix_key;

    #if 0
    /* L3VPN case, on Ingress router pkt_block can be IPv4 
        pkt with SRv6 Nexthop */
    if (pkt_block_get_starting_hdr(pkt_block) == IP_PROTO_IP_IN_IP && 
            (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_SRv6_FORWARD)) &&
             nh->fwd_info->u.v6_fwd.endfn == END_DT4) {

        assert (nh->fwd_info->oif->if_type == DP_INTF_TYPE_SRv6_DT4);
        dp_send_pkt_out(dp_ctx, nh->fwd_info->oif, pkt_block);
        return;
    }
    #endif

    unsigned char *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Should be ipv6 pkt*/
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_PROTO_IPv6);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    /* Get v6 address in string form for logging*/
    inet_ntop (AF_INET6, &ipv6_hdr->dst_addr, dst_addr_str, INET6_ADDRSTRLEN);

    if (!nh) {
        cmn_prefix_initialize_v6(&prefix_key, &ipv6_hdr->dst_addr, 128);
        nh = fib_get_forwarding_nh(vrf->fib_inet6, &prefix_key);
    }

    if(!nh){
        tracer (dp_ctx->dptr, DL3FWD | DERR, 
            "VRF %s: Pkt : %s :  Pkt Dropped :  No L3 Route\n", vrf->vrf_name, pkt_block_str(pkt_block));
        return;
    }

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s : L3 route found\n", vrf->vrf_name, dst_addr_str);

    /* Reject if the nexthop action is Reject */
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_REJECT) {

        tracer (dp_ctx->dptr, DL3FWD, 
            "VRF %s: Dest : %s : Pkt rejected by REJECT route\n", vrf->vrf_name, dst_addr_str);
        return;
    }

    /* For local routes , Trap the packet for local processing*/
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL) {

        tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Pkt : %s : L3 Route found is local route\n", 
            vrf->vrf_name, pkt_block_str(pkt_block));

        /* Strip the IPv6 header: shrink head by sizeof(ipv6_hdr_t). */
        gen_proto_id_t next = (gen_proto_id_t)ipv6_hdr->next_header;
        pkt_block_slide(pkt_block, -1, 1, (uint16_t)sizeof(ipv6_hdr_t));

        pkt_block_update_new_hdr_type (pkt_block, next);
        ipv6_process_v6_payload (dp_ctx, vrf, pkt_block) ;
        return;
    }

    /* For Connnected route, forward it to in local v6 connected subnet*/
    if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_FORWARD)) {    

        ipv6_layer3_forward_nexthop (dp_ctx, vrf, nh, pkt_block);
        return;
    }

    if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_SRv6_FORWARD)) {

        /* Do SRv6 forwarding */
        /* TODO: Process_Srv6_Packet needs old Interface type */
        Process_Srv6_Packet(dp_ctx, 
                            vrf,
                            NULL,
                            pkt_block,
                            ipv6_hdr,
                            ipv6_hdr->next_header == IP_PROTO_SRH ? (srh_hdr_t *)(ipv6_hdr + 1) : NULL,
                            nh);
        return;
    }
}

void
dp_send_ip6_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    assert (pkt_block_verify_pkt (pkt_block, ETH_TYPE_IPv6));

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_block_get_pkt (pkt_block,  &pkt_size);

    /* This API expects that IP-HDR must have following fields set */
    assert (ipv6_hdr->next_header);

    // Src IP may or may not be set already. If not set, we will determine it
    //assert (ip_hdr->src_ip);

    assert (!is_ipv6_addr_unspecified (&ipv6_hdr->dst_addr));

    tracer (dp_ctx->dptr, DL3FWD, "VRF %s: Dest : %s : NP Recvd Routing Request\n", 
        vrf->vrf_name, pkt_block_str(pkt_block));

    layer3_ipv6_route_pkt (dp_ctx, vrf, NULL, pkt_block, NULL); 
}
