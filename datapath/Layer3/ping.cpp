#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "../../tcp_public.h"
#include "../Vrfs/dp_vrf.h"
#include "ping.h"
#include "../FIB/fib_nh.h"
#include "../Interface/dp_intf.h"


extern int cprintf (const char *format, ...);
extern void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

static uint64_t
ping_get_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

void *
ping_send4 (void *_pctx)
{
    uint32_t     i;
    uint16_t     seq;
    pkt_size_t   ps;
    pkt_block_t *pkt_block;
    struct timespec abs_timeout;
    char dst_addr_str[48];
    char src_addr_str[48];

    ping_ctx_t *pctx = (ping_ctx_t *)_pctx;
    dp_ctx_t *dp_ctx = pctx->dp_ctx;

    dp_vrf_t *vrf = dp_look_up_vrf (dp_ctx->dp_vrf_ht, pctx->vrf_id);

    for (i = 0; i < pctx->count; i++) {

        seq = pctx->seq_no;

        pkt_block = pkt_block_get_new_pkt_buffer (
                        sizeof (icmp_hdr_t) + 
                        sizeof (ip_hdr_t));

        ip_hdr_t *ip_hdr  = (ip_hdr_t *)pkt_block_get_pkt (pkt_block, &ps);

        /* Prepare IPv4 header and send using dp_send_ip_data */

        initialize_ip_hdr(ip_hdr);
        ip_hdr->total_length = htons(sizeof(ip_hdr_t) + sizeof(icmp_hdr_t));
        ip_hdr->identification = htons(seq);
        ip_hdr->flags = 0;
        ip_hdr->ttl = 64;
        ip_hdr->protocol = IP_PROTO_ICMP;
        ip_hdr->src_ip = htonl(pctx->src.u.v4_addr);
        ip_hdr->dst_ip = htonl(pctx->dst.u.v4_addr);

        /* Determine the Src ip address */

        if (ip_hdr->src_ip == 0) {
            /* IF the dest is connected route, then take interface local IP*/
            /* IF the dest is local route, then take RTR ID */
            /* If the dest is remote route, then take nh-oif ip*/
            cmn_prefix_t prefix;
            cmn_prefix_initialize_v4(&prefix, ntohl(ip_hdr->dst_ip), 32);
            fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

            if (!nh) {

                tracer (dp_ctx->dptr, DL3FWD_DET | DERR, 
                     "VRF:%s Pkt:%s  Pkt Dropped : Src Addr cannot be determined\n", 
                     vrf->vrf_name, 
                     cmn_prefix_to_string (&pctx->dst, &dst_addr_str));
                return;
            }

            if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL) {

                ip_hdr->src_ip = htonl (dp_ctx->rtr_id);
            }
            else if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_CONNECTED)) {

                ip_hdr->src_ip = htonl (nh->fwd_info->oif->ip_addr);
            }
            else if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_FORWARD)) {

                ip_hdr->src_ip = htonl (dp_ctx->rtr_id);
            }            
        }

        ip_hdr->checksum = 0;

        icmp_hdr_t *icmp_hdr  = (icmp_hdr_t *)INCREMENT_IPHDR (ip_hdr);
        icmp_hdr->type       = ICMP_ECHO_REQ;
        icmp_hdr->code       = 0;
        icmp_hdr->checksum   = 0;
        icmp_hdr->identifier = htons (pctx->identifier);
        icmp_hdr->seq_no     = htons (seq);

        pkt_block_update_new_hdr_type(pkt_block, IP_PROTO_IP_IN_IP);
        
        /* Timestamp before handing off to the DP so RTT includes queuing time */
        pctx->send_time[seq % PING_MAX_SEQ] = ping_get_time_us ();

        tcp_ip_covert_ip_n_to_p (ntohl (ip_hdr->dst_ip), (c_string)dst_addr_str);
        tcp_ip_covert_ip_n_to_p (ntohl (ip_hdr->src_ip), (c_string)src_addr_str);

        tracer (dp_ctx->dptr, DL3FWD_DET, 
            "vrf:%s Dest:%s Src:%s Sending ping ... \n",
            vrf->vrf_name, 
            dst_addr_str, src_addr_str);

        cprintf ("\nPING %s --> %s\n", src_addr_str, dst_addr_str);
        refresh();

        dp_send_ip_data(pctx->dp_ctx, vrf, pkt_block );

        pkt_block_dereference (pkt_block);

        pctx->sent++;
        pctx->seq_no++;

        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        abs_timeout.tv_sec += 1;
        int rc = sem_timedwait(&pctx->reply_sem, &abs_timeout);

        if (rc == -1 && errno == ETIMEDOUT) {
            cprintf ("Timeout\n");
            refresh();
        }

    }

    /* Save cli_sem before touching pctx to avoid any use-after-free */
    sem_t *cli_sem = &pctx->cli_unblock_sem;

    /* Safe to free now: no thread holds a reference to pctx any longer */
    sem_destroy(&pctx->reply_sem);

    free(pctx->ping_thread);
    pctx->ping_thread = NULL;

    /* Unblock the CLI last, after all cleanup is done */
    sem_post (cli_sem);
    
    //ToDo : should be Atomic
    dp_ctx->active_ping_ctx = NULL;

    return NULL;
}

static const char *
icmp_unreach_str (uint8_t code)
{
    switch (code) {
        case ICMP_NET_UNREACH:    return "Destination Net Unreachable";
        case ICMP_HOST_UNREACH:   return "Destination Host Unreachable";
        case ICMP_PROTO_UNREACH:  return "Destination Protocol Unreachable";
        case ICMP_PORT_UNREACH:   return "Destination Port Unreachable";
        case ICMP_FRAG_NEEDED:    return "Fragmentation Needed and DF Bit Set";
        case ICMP_SR_FAILED:      return "Source Route Failed";
        case ICMP_NET_UNKNOWN:    return "Destination Network Unknown";
        case ICMP_HOST_UNKNOWN:   return "Destination Host Unknown";
        case ICMP_HOST_ISOLATED:  return "Source Host Isolated";
        case ICMP_NET_ANO:        return "Network Administratively Prohibited";
        case ICMP_HOST_ANO:       return "Host Administratively Prohibited";
        case ICMP_NET_UNR_TOS:    return "Network Unreachable for TOS";
        case ICMP_HOST_UNR_TOS:   return "Host Unreachable for TOS";
        case ICMP_PKT_FILTERED:   return "Communication Administratively Prohibited";
        case ICMP_PREC_VIOLATION: return "Host Precedence Violation";
        case ICMP_PREC_CUTOFF:    return "Precedence Cutoff in Effect";
        default:                  return "Destination Unreachable";
    }
}

static const char *
icmp_time_exceeded_str (uint8_t code)
{
    switch (code) {
        case ICMP_EXC_TTL:      return "Time to Live Exceeded in Transit";
        case ICMP_EXC_FRAGTIME: return "Fragment Reassembly Time Exceeded";
        default:                return "Time Exceeded";
    }
}

void
ping_echo_reply_recvd (ping_ctx_t *pctx, pkt_block_t *pkt_block)
{
    ip_hdr_t   *ip_hdr;
    icmp_hdr_t *icmp_hdr;
    uint16_t    seq;
    byte        src_str[IPV4_ADDR_LEN_STR];

    ip_hdr   = pkt_block_get_ip_hdr (pkt_block);
    icmp_hdr = (icmp_hdr_t *)INCREMENT_IPHDR (ip_hdr);

    tcp_ip_covert_ip_n_to_p (ntohl (ip_hdr->src_ip), src_str);

    if (icmp_hdr->type == ICMP_ECHO_REP) {

        if (ntohs (icmp_hdr->identifier) != pctx->identifier) return;

        seq = ntohs (icmp_hdr->seq_no);
        uint32_t rtt_us = (uint32_t)(ping_get_time_us () -
                                     pctx->send_time[seq % PING_MAX_SEQ]);
        pctx->received++;

        if (pctx->received == 1 || rtt_us < pctx->rtt_min) pctx->rtt_min = rtt_us;
        if (rtt_us > pctx->rtt_max)                         pctx->rtt_max = rtt_us;
        pctx->rtt_sum += rtt_us;

        cprintf ("Reply from %s: icmp_seq=%u ttl=%d time=%u us\n", 
            src_str, seq, ip_hdr->ttl, rtt_us);

    } else {
        /* ICMP error types 3 / 11 / 12 carry the original IP header followed
         * by the first 8 bytes of the original datagram (= our ICMP echo
         * header) starting at byte 8 of the error ICMP header. */
        ip_hdr_t   *inner_ip   = (ip_hdr_t *)((char *)icmp_hdr + 8);
        icmp_hdr_t *inner_icmp = (icmp_hdr_t *)INCREMENT_IPHDR (inner_ip);

        if (ntohs (inner_icmp->identifier) != pctx->identifier) return;

        seq = ntohs (inner_icmp->seq_no);

        switch (icmp_hdr->type) {

            case ICMP_DEST_UNREACH:
                cprintf ("From %s: icmp_seq=%u %s\n",
                         src_str, seq, icmp_unreach_str (icmp_hdr->code));
                break;

            case ICMP_TIME_EXCEEDED:
                cprintf ("From %s: icmp_seq=%u %s\n",
                         src_str, seq, icmp_time_exceeded_str (icmp_hdr->code));
                break;

            case ICMP_PARAM_PROBLEM:
                cprintf ("From %s: icmp_seq=%u Parameter Problem (pointer=%u)\n",
                         src_str, seq, icmp_hdr->code);
                break;

            default:
                cprintf ("From %s: icmp_seq=%u ICMP type=%u code=%u\n",
                         src_str, seq, icmp_hdr->type, icmp_hdr->code);
                break;
        }
    }

    /* Unblock the per-probe wait in ping_send4 for any recognised reply */
    sem_post (&pctx->reply_sem);
}

void 
dp_handle_ping_request (
        dp_ctx_t *dp_ctx, 
        ping_ctx_t *pctx) {

    pctx->dp_ctx = dp_ctx;
    dp_ctx->active_ping_ctx = pctx;

    pctx->ping_thread = (pthread_t *)calloc(1, sizeof (pthread_t));
    pthread_create (pctx->ping_thread, 0, ping_send4, (void *)pctx);
}
