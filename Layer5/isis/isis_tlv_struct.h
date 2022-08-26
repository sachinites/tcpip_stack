#ifndef __ISIS_TLV_STRUCT__
#define __ISIS_TLV_STRUCT__

#include <stdint.h>

#pragma pack (push,1)

#define ISIS_EXTERN_ROUTE_F   (1<<7)
#define ISIS_INTERNAL_ROUTE_F   (1<<6)

typedef struct isis_tlv_130_ {

    uint32_t prefix;
    uint8_t mask;
    uint32_t metric;
    uint8_t flags;
}isis_tlv_130_t;

#pragma pack(pop)

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len); 
                    

#endif