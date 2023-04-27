#ifndef __ISIS_TLV_STRUCT__
#define __ISIS_TLV_STRUCT__

#include <stdint.h>
#include "isis_struct.h"
#include "isis_const.h"
#include "isis_advt.h"

#pragma pack (push,1)

#define ISIS_EXTERN_ROUTE_F   (1<<7)
#define ISIS_INTERNAL_ROUTE_F   (1<<6)

typedef struct isis_tlv_130_ {

    uint32_t prefix;
    uint32_t mask;
    uint32_t metric;
    uint8_t flags;
}isis_tlv_130_t;

#pragma pack(pop)

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len); 
                    
pkt_size_t
isis_get_adv_data_size(isis_adv_data_t *adv_data);

byte *
isis_get_adv_data_tlv_content(
            isis_adv_data_t *advt_data, 
            byte *tlv_content) ;

#endif