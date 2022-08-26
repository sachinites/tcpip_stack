#include "../../tcp_public.h"
#include "isis_tlv_struct.h"
#include "isis_const.h"

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len) {

    uint32_t rc = 0;
    char ip_addr_str[16];

    isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)(tlv130_start + TLV_OVERHEAD_SIZE);

    rc += sprintf(out_buff + rc, "\tTLV%d IP-REACH TLV : \n", ISIS_TLV_IP_REACH);
     rc += sprintf(out_buff + rc, "\t\t%s/%d  metric = %u  %s\n",
                tcp_ip_covert_ip_n_to_p(htonl(tlv_130->prefix), ip_addr_str),
                tlv_130->mask,
                htonl(tlv_130->metric), 
                IS_BIT_SET (tlv_130->flags, ISIS_EXTERN_ROUTE_F) ? "External" : "Internal");
                
    return rc;
}