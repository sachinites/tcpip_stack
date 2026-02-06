#include <arpa/inet.h>
#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_lspdb.h"
#include "isis_tlv_struct.h"
#include "isis_utils.h"
#include "isis_advt.h"

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)(tlv130_start + TLV_OVERHEAD_SIZE);

    rc += cprintf("\tTLV%d IP-REACH TLV   len:%dB\n", ISIS_TLV_IP_REACH, tlv_len);
    rc += cprintf("\t  %s/%d  metric = %u  %s\n",
                tcp_ip_covert_ip_n_to_p(htonl(tlv_130->prefix), ip_addr_str),
                tcp_ip_convert_bin_mask_to_dmask(tlv_130->mask),
                htonl(tlv_130->metric), 
                IS_BIT_SET (tlv_130->flags, ISIS_EXTERN_ROUTE_F) ? "External" : "Internal");
                
    return rc;
}

uint32_t
isis_print_formatted_tlv236( byte* out_buff, byte* tlv236_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ipv6_addr_str[48];

    isis_tlv_236_t *tlv_236 = (isis_tlv_236_t *)(tlv236_start + TLV_OVERHEAD_SIZE);
    inet_ntop (AF_INET6, tlv_236->prefix, ipv6_addr_str, 16);
    rc += cprintf("\tTLV%d IPV6-REACH TLV   len:%dB\n", ISIS_TLV_IPV6_REACH, tlv_len);
    rc += cprintf("\t  %s/%d  metric = %u  %s\n",
                ipv6_addr_str, tlv_236->prefix_len, htonl(tlv_236->metric),
                IS_BIT_SET (tlv_236->bits, TLV236_XBIT ) ? "External" : "Internal");
                
    return rc;
}

uint32_t
isis_print_formatted_tlv27( byte* out_buff, byte* tlv27_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ipv6_addr_str[48];
    ipv6_addr_t ipv6_addr;
    srv6_pfxsid_subtlv_t *pfxsid_subtlv;

    locator_tlv_t *loc_tlv = (locator_tlv_t *)(tlv27_start + TLV_OVERHEAD_SIZE);
    memset (&ipv6_addr, 0, sizeof(ipv6_addr_t));
    memcpy (ipv6_addr.addr, loc_tlv->locator, (loc_tlv->loc_size + 7)/8);

    inet_ntop (AF_INET6, ipv6_addr.addr, ipv6_addr_str, 16);

    rc += cprintf("\tTLV%d SRV6-LOCATOR TLV   len:%dB\n", ISIS_TLV_LOCATOR, tlv_len);
    rc += cprintf("\t  %s/%d  metric:%u  Flags:0x%x  Algorithm:%d  MT-Id:%d  Subtlv-len:%d\n",
                ipv6_addr_str, 
                loc_tlv->loc_size, 
                htonl(loc_tlv->metric),
                loc_tlv->flags,
                loc_tlv->algorithm,
                loc_tlv->RRRR_mt_id,
                locator_tlv_get_subtlv_len(loc_tlv));

    byte *subtlv = (byte *)(loc_tlv->locator + 1) + ((loc_tlv->loc_size + 7)/8);
    uint8_t tlv_type, tlv_len2, *tlv_value;
    uint8_t subtlv_len = locator_tlv_get_subtlv_len(loc_tlv);

    ITERATE_TLV_BEGIN(subtlv, tlv_type, tlv_len2, tlv_value, subtlv_len) {

        switch (tlv_type) {

            case ISIS_LOCATOR_PFX_SID_SUBTLV:

                pfxsid_subtlv = (srv6_pfxsid_subtlv_t *)tlv_value;
                inet_ntop (AF_INET6, pfxsid_subtlv->prefix, ipv6_addr_str, 16);

                rc += cprintf("\t    SubTLV:%d  len:%d  Prefix-SID : %s  Endfn : %s  Flags : 0x%x\n",
                    tlv_type, tlv_len2,
                    ipv6_addr_str,
                    srv6_end_fn_str(pfxsid_subtlv->endfn),
                    pfxsid_subtlv->flags);
            break;
            default: 
                assert(0);
        }

    } ITERATE_TLV_END(subtlv, tlv_type, tlv_len2, tlv_value, subtlv_len);

    return rc;
}

pkt_size_t
isis_print_formatted_rtr_cap_tlv242 (byte* out_buff, byte* tlv242_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    
    isis_rtr_cap_tlv242_t *tlv_242 = (isis_rtr_cap_tlv242_t *)(tlv242_start + TLV_OVERHEAD_SIZE);

    rc += cprintf("\tTLV%d RTR-CAP   len:%dB\n",    
                    ISIS_TLV_RTR_CAP, tlv_len - TLV_OVERHEAD_SIZE); 
    rc += cprintf("\t  Rtr ID : %s  Flags : 0x%x\n",
                tcp_ip_covert_ip_n_to_p(tlv_242->rtr_id, ip_addr_str), tlv_242->flags);

    /* Does it have Subtlvs ?*/
    if (tlv_len == (sizeof(isis_rtr_cap_tlv242_t) + TLV_OVERHEAD_SIZE)) {
        return rc;
    }

    /* It may have two SubTLVs : Algorithm Sub TLV and SRv6 Sub TLV*/
    byte *subtlv = (byte *)(tlv242_start + TLV_OVERHEAD_SIZE + sizeof(isis_rtr_cap_tlv242_t));
    bool next_subtlv = false;

    do
    {
        next_subtlv = false;

        switch (*subtlv)
        {

        case ISIS_TLV_RTR_CAP_ALGO_SUBTLV:
        {
            isis_rtr_cap_algorithm_subtlv19_t *algo_subtlv = (isis_rtr_cap_algorithm_subtlv19_t *)subtlv;
            rc += cprintf("\t  SubTLV%d  Algorithm Subtlv  len:%d\n", 
                            algo_subtlv->type, algo_subtlv->length);

            int n_algo = algo_subtlv->length / 8;
            for (int i = 0; i < n_algo; i++)
            {
                rc += cprintf("\t   SPRING Algorithm : %d\n", algo_subtlv->algorithms[i]);
            }

            if (tlv_len > (TLV_OVERHEAD_SIZE + sizeof(isis_rtr_cap_tlv242_t) + 
                                        TLV_OVERHEAD_SIZE + algo_subtlv->length))
            {
                subtlv = tlv242_start + (TLV_OVERHEAD_SIZE + sizeof(isis_rtr_cap_tlv242_t) +
                                         TLV_OVERHEAD_SIZE + algo_subtlv->length);
                next_subtlv = true;
            }
        }
        break;

        case ISIS_TLV_RTR_CAP_SRV6_SUBTLV:
        {
            isis_rtr_cap_srv6_subtlv2_t *srv6_subtlv = (isis_rtr_cap_srv6_subtlv2_t *)subtlv;
            rc += cprintf("\t  SubTLV%d  SRv6 Capability Subtlv  len:%d\n", srv6_subtlv->type, srv6_subtlv->length);
            rc += cprintf("\t    flags : 0x%x\n", srv6_subtlv->flags);
            rc += cprintf("\t    Max # of SL in SRH supported by platform                : %d\n", srv6_subtlv->max_sl_msd);
            rc += cprintf("\t    Max # of SIDs when applying PSP or USP flavors          : %d\n", srv6_subtlv->max_end_pop_srh_msd);
            rc += cprintf("\t    Max # of T-INSERT SIDs supported by platform            : %d\n", srv6_subtlv->max_t_ins_srh_msd);
            rc += cprintf("\t    Max # of T-ENCAP SIDs supported by platform             : %d\n", srv6_subtlv->max_t_encap_srh_msd);
            rc += cprintf("\t    Max # of END.DX6 or END.DT6 SIDs supported by platform  : %d\n", srv6_subtlv->max_end_D_srh_msd);

            if (tlv_len > (TLV_OVERHEAD_SIZE + sizeof(isis_rtr_cap_tlv242_t) + 
                                        TLV_OVERHEAD_SIZE + srv6_subtlv->length))
            {
                subtlv = tlv242_start + (TLV_OVERHEAD_SIZE + sizeof(isis_rtr_cap_tlv242_t) +
                                         TLV_OVERHEAD_SIZE + srv6_subtlv->length);
                next_subtlv = true;
            }
        }
        break;
        }

    } while (next_subtlv);

    return rc;
}

pkt_size_t
isis_get_adv_data_size(isis_adv_data_t *adv_data)
{
    pkt_size_t ptlv_data_len = 0;
    pkt_size_t total_subtlv_len = 0;

    switch (adv_data->tlv_no) {
    
    case ISIS_TLV_HOSTNAME:
        ptlv_data_len += TLV_OVERHEAD_SIZE + NODE_NAME_SIZE;
        break;
    case ISIS_IS_REACH_TLV:
        ptlv_data_len += TLV_OVERHEAD_SIZE;
        ptlv_data_len += sizeof(isis_system_id_t); /* Nbr Sys Id */
        ptlv_data_len += 4;                                      /* Cost/Metric */
        ptlv_data_len += 1;                                      /* total Sub TLV len */

        /* encode subtlv 4 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4 + 4;
        /* encode subtlv 6 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4;
        /* encode subtlv 8 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4;

        ptlv_data_len += total_subtlv_len;
        break;

    case ISIS_TLV_IP_REACH:
        ptlv_data_len += sizeof (isis_tlv_130_t) + TLV_OVERHEAD_SIZE;
        break;
    case ISIS_TLV_IPV6_REACH:
        ptlv_data_len += sizeof (isis_tlv_236_t) + TLV_OVERHEAD_SIZE;
        break;
    case ISIS_TLV_IPV6_MT_REACH:
        ptlv_data_len += sizeof (isis_tlv_237_t) + TLV_OVERHEAD_SIZE;        
        break;
    case ISIS_TLV_LOCATOR:
        ptlv_data_len += sizeof (locator_tlv_t) + (adv_data->u.srv6_loc.prefix_len + 7)/8 +
                                     TLV_OVERHEAD_SIZE;    
        total_subtlv_len += adv_data->u.srv6_loc.subtlv_len;
        ptlv_data_len += total_subtlv_len;
        break;
    case ISIS_LOCATOR_PFX_SID_SUBTLV:
        ptlv_data_len += sizeof (srv6_pfxsid_subtlv_t) + adv_data->u.srv6_pfxsid.subtlv_len + TLV_OVERHEAD_SIZE;
        break;
    case ISIS_TLV_RTR_CAP:
        ptlv_data_len += sizeof (isis_rtr_cap_tlv242_t) + TLV_OVERHEAD_SIZE;
        if (adv_data->u.rtr_cap.is_rtr_cap_algo_subtlv19_present) {
            ptlv_data_len += TLV_OVERHEAD_SIZE + adv_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.length;
        }
        if (adv_data->u.rtr_cap.is_rtr_cap_srv6_subtlv2_present) {
            ptlv_data_len += sizeof (isis_rtr_cap_srv6_subtlv2_t) ;
        }
        break;
    case ISIS_TLV_RTR_CAP_ALGO_SUBTLV:
        ptlv_data_len += TLV_OVERHEAD_SIZE + adv_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.length;
        break;
    case ISIS_TLV_RTR_CAP_SRV6_SUBTLV:
        ptlv_data_len += sizeof (isis_rtr_cap_srv6_subtlv2_t) ;
        break;
    default:
        assert (0);
    }
    return ptlv_data_len;
}

byte *
isis_get_adv_data_tlv_content(
            isis_adv_data_t *advt_data, 
            byte *tlv_content) {

    uint32_t if_indexes[2];
    byte *start_ptr = tlv_content;
    uint8_t total_subtlv_len = 0;

    assert ((advt_data->tlv_size - TLV_OVERHEAD_SIZE) <= 255);

    switch (advt_data->tlv_no) {

        case ISIS_IS_REACH_TLV:
            memcpy(tlv_content, (byte *)&advt_data->u.adj_data.nbr_sys_id, sizeof(isis_system_id_t));
            tlv_content += sizeof(isis_system_id_t);
            *(uint32_t *)tlv_content = htonl(advt_data->u.adj_data.metric);
            tlv_content += sizeof(uint32_t);

            /* encode subtlv 4 */
            total_subtlv_len += TLV_OVERHEAD_SIZE + 4 + 4;
            /* encode subtlv 6 */
            total_subtlv_len += TLV_OVERHEAD_SIZE + 4;
            /* encode subtlv 8 */
            total_subtlv_len += TLV_OVERHEAD_SIZE + 4;

            *(uint8_t *)tlv_content =  total_subtlv_len;
            tlv_content += sizeof(uint8_t);

            /* Now We are at the start of Ist SubTLV,
                encode local and remote if index Encoding SubTLV 4 */
            if_indexes[0]  = htonl(advt_data->u.adj_data.local_ifindex);
            if_indexes[1]  = htonl(advt_data->u.adj_data.remote_ifindex);
            tlv_content= tlv_buffer_insert_tlv(tlv_content,
                        ISIS_TLV_IF_INDEX, 8,
                        (byte *)if_indexes);

            /* Encode local ip Address Encoding SubTLV 6 */
            {
                uint32_t local_ip = htonl(advt_data->u.adj_data.local_intf_ip);
                tlv_content = tlv_buffer_insert_tlv(tlv_content,
                            ISIS_TLV_LOCAL_IP, 4,
                            (byte *)&local_ip);

                /* Encode remote ip Address  Encoding SubTLV 8 */
                uint32_t remote_ip = htonl(advt_data->u.adj_data.remote_intf_ip);
                tlv_content = tlv_buffer_insert_tlv(tlv_content,
                            ISIS_TLV_REMOTE_IP, 4,
                            (byte *)&remote_ip);
            }
        break;

        case ISIS_TLV_IP_REACH:
             *(uint32_t *)tlv_content = htonl(advt_data->u.pfx.prefix);
            tlv_content += sizeof(uint32_t);
             *(uint32_t *)tlv_content = htonl(tcp_ip_convert_dmask_to_bin_mask(advt_data->u.pfx.mask));
            tlv_content += sizeof(uint32_t);
            *(uint32_t *)tlv_content = htonl(advt_data->u.pfx.metric);
            tlv_content += sizeof(uint32_t);
            *(uint8_t *)tlv_content = advt_data->u.pfx.flags;
        break;
        case ISIS_TLV_IPV6_REACH:
        {
            isis_tlv_236_t *tlv_fmt = (isis_tlv_236_t *)tlv_content;
            tlv_fmt->metric = htonl(advt_data->u.v6pfx.metric);
            tlv_fmt->bits = advt_data->u.v6pfx.flags;
            tlv_fmt->prefix_len =  advt_data->u.v6pfx.mask;
            memcpy(tlv_fmt->prefix ,  advt_data->u.v6pfx.prefix, 16);
        }
        break;
        case ISIS_TLV_HOSTNAME:
                strncpy ((char *)tlv_content, advt_data->u.host_name, 
                    advt_data->tlv_size - TLV_OVERHEAD_SIZE);
        break;
        case ISIS_TLV_LOCATOR:
        {
            locator_tlv_t *tlv_fmt = (locator_tlv_t *)tlv_content;
            tlv_fmt->RRRR_mt_id = advt_data->u.srv6_loc.mt_id;
            tlv_fmt->metric = advt_data->u.srv6_loc.metric;
            tlv_fmt->flags = advt_data->u.srv6_loc.flags;
            tlv_fmt->algorithm = advt_data->u.srv6_loc.algorithm;
            tlv_fmt->loc_size = advt_data->u.srv6_loc.prefix_len;
            memcpy(tlv_fmt->locator, advt_data->u.srv6_loc.prefix.addr, 
                 (advt_data->u.srv6_loc.prefix_len + 7)/8);
            locator_tlv_set_subtlv_len(tlv_fmt, advt_data->u.srv6_loc.subtlv_len);
            tlv_content += sizeof(locator_tlv_t) + ((advt_data->u.srv6_loc.prefix_len + 7)/8);

            glthread_t *curr;
            isis_adv_data_t *pfxsid_adv_data ;

            /* Insert type length for SubTLVs*/

            ITERATE_GLTHREAD_BEGIN(&advt_data->u.srv6_loc.pfxsid_list_head, curr) {

                pfxsid_adv_data = srv6_pfxsid_sibling_glue_to_pfxsid_adv_data (curr);

                tlv_buffer_insert_tlv (tlv_content, 
                                    pfxsid_adv_data->tlv_no ,
                                    pfxsid_adv_data->tlv_size - TLV_OVERHEAD_SIZE, 0 );

                tlv_content += TLV_OVERHEAD_SIZE;
                isis_get_adv_data_tlv_content(pfxsid_adv_data, tlv_content);
                tlv_content += pfxsid_adv_data->tlv_size - TLV_OVERHEAD_SIZE;

            } ITERATE_GLTHREAD_END(&advt_data->u.srv6_loc.pfxsid_list_head, curr)
        }
        break;
        case ISIS_LOCATOR_PFX_SID_SUBTLV:
        {
            srv6_pfxsid_subtlv_t *tlv_fmt = (srv6_pfxsid_subtlv_t *)tlv_content;
            tlv_fmt->flags = advt_data->u.srv6_pfxsid.flags;
            tlv_fmt->endfn = advt_data->u.srv6_pfxsid.endfn;
            memcpy(tlv_fmt->prefix, advt_data->u.srv6_pfxsid.prefix.addr, 16);
            tlv_fmt->subtlv_len = 0; /* Not supported */
        }
        break;

        case ISIS_TLV_RTR_CAP:
        {
            isis_rtr_cap_tlv242_t *tlv_fmt = (isis_rtr_cap_tlv242_t *)tlv_content;
            tlv_fmt->rtr_id = advt_data->u.rtr_cap.rtr_cap.rtr_id;
            tlv_fmt->flags = advt_data->u.rtr_cap.rtr_cap.flags;
            tlv_content = (byte *)(tlv_fmt + 1);

            if (advt_data->u.rtr_cap.is_rtr_cap_algo_subtlv19_present) {

                 tlv_content = tlv_buffer_insert_tlv (tlv_content, 
                                                    ISIS_TLV_RTR_CAP_ALGO_SUBTLV,
                                                    advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.length,
                                                    (byte *)advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.algorithms);
            }

            if (advt_data->u.rtr_cap.is_rtr_cap_srv6_subtlv2_present) {
                
                tlv_content = tlv_buffer_insert_tlv (tlv_content, 
                                                    ISIS_TLV_RTR_CAP_SRV6_SUBTLV,
                                                    advt_data->u.rtr_cap.rtr_cap_srv6_subtlv2.length,
                                                    (byte *)&advt_data->u.rtr_cap.rtr_cap_srv6_subtlv2.flags);  
            }
            
        }
        break;


        default: ;
    }
    return start_ptr;
}

pkt_size_t
isis_format_nbr_tlv22(byte *out_buff, 
                             byte *nbr_tlv_buffer,
                             uint8_t tlv_buffer_len) {
    
    pkt_size_t rc = 0;
    uint32_t metric;
    uint8_t subtlv_len;
    byte system_id_str[32];
    uint32_t ip_addr_int;
    byte *subtlv_navigator;
    unsigned char ip_addr[IPV4_ADDR_LEN_STR];
    isis_system_id_t system_id;

    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len) {

        rc += cprintf("\tTLV%d  Len : %d\n", tlv_type, tlv_len);

        tlv22_hdr_t *tlv22_hdr = (tlv22_hdr_t *)tlv_value;
        system_id = tlv22_hdr->system_id;
        /* Convert metric from network byte order to host byte order */
        metric = ntohl(tlv22_hdr->metric);
        subtlv_len = tlv22_hdr->subtlv_len;

        rc += cprintf("\tNbr System ID : %s   Metric : %u   SubTLV Len : %d\n",
                     isis_system_id_tostring(&system_id, system_id_str), 
                      metric, subtlv_len);

        subtlv_navigator = (byte *)(tlv22_hdr + 1);

        /* Now Read the Sub TLVs */
        byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

        ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len) {

            switch(tlv_type2) {
                case ISIS_TLV_IF_INDEX:
                    /* Convert interface indexes from network byte order to host byte order */
                    rc += cprintf(
                                  "\t SubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                  tlv_type2, tlv_len2,
                                  ntohl(*(uint32_t *)tlv_value2),
                                  ntohl(*(uint32_t *)((uint32_t *)tlv_value2 + 1)));

                    break;
                case ISIS_TLV_LOCAL_IP:
                    /* Convert IP from network byte order to host byte order */
                    /* tcp_ip_covert_ip_n_to_p expects host byte order input */
                    ip_addr_int = ntohl(*(uint32_t *)tlv_value2);

                    rc += cprintf("\t SubTLV%d  Len : %d   Local IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, ip_addr));

                    break;
                case ISIS_TLV_REMOTE_IP:
                    /* Convert IP from network byte order to host byte order */
                    /* tcp_ip_covert_ip_n_to_p expects host byte order input */
                    ip_addr_int = ntohl(*(uint32_t *)tlv_value2);

                    rc += cprintf(
                                  "\t SubTLV%d  Len : %d   Remote IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, ip_addr));

                    break;
                default:
                    ;
            }

        } ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len);
 
    } ITERATE_TLV_END(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len);
    return rc;
}

uint32_t
isis_show_one_lsp_pkt_detail_info (byte *buff, isis_lsp_pkt_t *lsp_pkt) {

    uint32_t rc = 0;
    byte ip_addr[IPV4_ADDR_LEN_STR];
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    byte tlv_type, tlv_len, *tlv_value = NULL;

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    isis_pkt_hdr_flags_t flags = isis_lsp_pkt_get_flags(lsp_pkt);

    rc += cprintf ("LSP PKT\nLSP : %s\n", isis_print_lsp_id (lsp_pkt,  lsp_id_str));

    rc += cprintf ("Flags :  \n");
    rc += cprintf ("  OL bit : %s\n", flags & ISIS_LSP_PKT_F_OVERLOAD_BIT ? "Set" : "UnSet");
    rc += cprintf("  Purge bit : %s\n", flags & ISIS_LSP_PKT_F_PURGE_BIT ? "Set" : "UnSet");
    rc += cprintf("\tTLVs\n");

    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);
    pkt_size_t lsp_tlv_buffer_size = (uint16_t)(lsp_pkt->pkt_size -
                                        ETH_HDR_SIZE_EXCL_PAYLOAD -
                                        sizeof(isis_pkt_hdr_t)) ;

    ITERATE_TLV_BEGIN(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size) {

        switch(tlv_type) {
            case ISIS_TLV_HOSTNAME:
                rc += cprintf("\tTLV%d Host-Name : %s\n", 
                        tlv_type, tlv_value);
            break;
            case ISIS_IS_REACH_TLV:
                 rc += isis_format_nbr_tlv22( 0,
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_IP_REACH:
                rc += isis_print_formatted_tlv130(0, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_IPV6_REACH:
                rc += isis_print_formatted_tlv236(0, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_LOCATOR:
                rc += isis_print_formatted_tlv27(0, 
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            case ISIS_TLV_RTR_CAP:
                rc += isis_print_formatted_rtr_cap_tlv242(0,
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;  
            default: ;
        }
    } ITERATE_TLV_END(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size);

    return rc;
}

bool
isis_is_zero_fragment_tlv (uint16_t tlv_no) {

    switch (tlv_no) {
        case  ISIS_TLV_HOSTNAME:
        case ISIS_TLV_RTR_CAP:
            return true;
        case ISIS_IS_REACH_TLV:
        case ISIS_TLV_IP_REACH:
         case ISIS_TLV_IPV6_REACH:
         case ISIS_TLV_IPV6_MT_REACH:
         case ISIS_TLV_LOCATOR:
            return false;
        default: 
            return false;
    }
    return false;
}

/* Helper functions for TLV 27 - Locator TLV. We need these because 
    TLV27 is complex because of variable locator size field */
void 
locator_tlv_set_subtlv_len (locator_tlv_t *loc_tlv, uint8_t subtlv_len) {

    size_t loc_offset =  (size_t)&((locator_tlv_t *) 0 )->locator;
    uint8_t *ptr = (uint8_t *)((char *)loc_tlv + loc_offset + ((loc_tlv->loc_size + 7)/8));
    *ptr = subtlv_len;
}

uint8_t 
locator_tlv_get_subtlv_len (locator_tlv_t *loc_tlv) {

    size_t loc_offset =  (size_t)&((locator_tlv_t *) 0 )->locator;
    uint8_t *ptr = (uint8_t *)((char *)loc_tlv + loc_offset + ((loc_tlv->loc_size + 7)/8));
    return (*ptr);
}

uint8_t 
locator_tlv_get_total_size (locator_tlv_t *loc_tlv) {
    
    return (sizeof (*loc_tlv) + ((loc_tlv->loc_size + 7)/8) + loc_tlv->subtlv_len);
}
