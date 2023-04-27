#include "../../tcp_public.h"
#include "isis_tlv_struct.h"

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ip_addr_str[16];

    isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)(tlv130_start + TLV_OVERHEAD_SIZE);

    rc += sprintf(out_buff + rc, "\tTLV%d IP-REACH TLV : \n", ISIS_TLV_IP_REACH);
    rc += sprintf(out_buff + rc, "\t\t%s/%d  metric = %u  %s\n",
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
        default: ;
    }
    return start_ptr;
}