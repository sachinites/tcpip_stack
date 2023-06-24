#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_lspdb.h"
#include "isis_tlv_struct.h"
#include "isis_utils.h"

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ip_addr_str[16];

    isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)(tlv130_start + TLV_OVERHEAD_SIZE);

    rc += cprintf("\tTLV%d IP-REACH TLV   len:%dB\n", ISIS_TLV_IP_REACH, tlv_len);
    rc += cprintf("\t\t%s/%d  metric = %u  %s\n",
                tcp_ip_covert_ip_n_to_p(htonl(tlv_130->prefix), ip_addr_str),
                tcp_ip_convert_bin_mask_to_dmask(tlv_130->mask),
                htonl(tlv_130->metric), 
                IS_BIT_SET (tlv_130->flags, ISIS_EXTERN_ROUTE_F) ? "External" : "Internal");
                
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
    default: ;
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
            *(uint32_t *)tlv_content = advt_data->u.adj_data.metric;
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
            if_indexes[0]  = advt_data->u.adj_data.local_ifindex;
            if_indexes[1]  = advt_data->u.adj_data.remote_ifindex;
            tlv_content= tlv_buffer_insert_tlv(tlv_content,
                        ISIS_TLV_IF_INDEX, 8,
                        (byte *)if_indexes);

            /* Encode local ip Address Encoding SubTLV 6 */
            tlv_content = tlv_buffer_insert_tlv(tlv_content,
                        ISIS_TLV_LOCAL_IP, 4,
                        (byte *)&advt_data->u.adj_data.local_intf_ip);

            /* Encode remote ip Address  Encoding SubTLV 8 */
            tlv_content = tlv_buffer_insert_tlv(tlv_content,
                        ISIS_TLV_REMOTE_IP, 4,
                        (byte *)&advt_data->u.adj_data.remote_intf_ip);
        break;

        case ISIS_TLV_IP_REACH:
             *(uint32_t *)tlv_content = advt_data->u.pfx.prefix;
            tlv_content += sizeof(uint32_t);
             *(uint32_t *)tlv_content = tcp_ip_convert_dmask_to_bin_mask(advt_data->u.pfx.mask);
            tlv_content += sizeof(uint32_t);
            *(uint32_t *)tlv_content = advt_data->u.pfx.metric;
            tlv_content += sizeof(uint32_t);
            *(uint8_t *)tlv_content = advt_data->u.pfx.flags;
        break;
        case ISIS_TLV_HOSTNAME:
                strncpy (tlv_content, advt_data->u.host_name, advt_data->tlv_size - TLV_OVERHEAD_SIZE);
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
    unsigned char ip_addr[16];
    isis_system_id_t system_id;

    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len) {

        rc += cprintf("\tTLV%d  Len : %d\n", tlv_type, tlv_len);

        tlv22_hdr_t *tlv22_hdr = (tlv22_hdr_t *)tlv_value;
        system_id = tlv22_hdr->system_id;
        metric = tlv22_hdr->metric;
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

                    rc += cprintf(
                                  "\t SubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                  tlv_type2, tlv_len2,
                                  *(uint32_t *)tlv_value2,
                                  *(uint32_t *)((uint32_t *)tlv_value2 + 1));

                    break;
                case ISIS_TLV_LOCAL_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

                    rc += cprintf("\t SubTLV%d  Len : %d   Local IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, ip_addr));

                    break;
                case ISIS_TLV_REMOTE_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

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
    byte ip_addr[16];
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
            return true;
        case ISIS_IS_REACH_TLV:
        case ISIS_TLV_IP_REACH:
            return false;
        default: 
            return false;
    }
    return false;
}
