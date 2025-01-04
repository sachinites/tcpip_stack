#ifndef __ISIS_TLV_STRUCT__
#define __ISIS_TLV_STRUCT__

#include <stdint.h>
#include "isis_struct.h"
#include "isis_const.h"
#include "isis_advt.h"

#pragma pack (push,1)

#define ISIS_EXTERN_ROUTE_F   (1<<7)
#define ISIS_INTERNAL_ROUTE_F   (1<<6)

#define SPF_ALOGORITHM 0
#define SPF_STRICT_ALOGORITHM 1

typedef struct isis_tlv_130_ {

    uint32_t prefix;
    uint32_t mask;
    uint32_t metric;
    uint8_t flags;
}isis_tlv_130_t;

/* IPV6 IP REACH TLV*/
typedef struct isis_tlv_236_ {

    uint32_t metric;
    #define TLV236_UBIT (1 << 7)
    #define TLV236_XBIT (1 << 6)
    #define TLV236_SBIT (1 << 5)
    uint8_t bits;
    uint8_t prefix_len;
    uint8_t prefix[16];

}isis_tlv_236_t;

/* IPV6 IP MT REACH TLV*/
typedef struct isis_tlv_237_ {

    uint32_t metric;
    #define TLV236_UBIT (1 << 7)
    #define TLV236_XBIT (1 << 6)
    #define TLV236_SBIT (1 << 5)
    uint8_t bits;
    uint8_t prefix_len;
    uint8_t prefix[16];

}isis_tlv_237_t;

typedef struct tlv22_hdr_ {

    isis_system_id_t system_id;
    uint32_t metric;
    uint8_t subtlv_len;
} tlv22_hdr_t;


typedef struct isis_tlv_27_ {

    //uint8_t type;
    //uint8_t length;
    /* Ist 4 bits are reserved, last 12 bits is MT-ID*/
    uint16_t RRRR_mt_id;
    uint32_t metric;
    /* MSB is Down bit*/
    #define LOCATPR_DOWN_BIT (1 << 7) // set by ISIS when locator is leaked from L2 to L1
    #define LOCATOR_ANYCAST_BIT (1 << 6) // set by SRv6 when locator is anycast
    uint8_t flags;
    // 0 for spf, 1 for strict
    // 128 - 255 for flex algo
    uint8_t algorithm;
    char padding[2];
    // 1 to 128
    uint8_t loc_size; 
    uint8_t locator[0];
    /* Never Access this member directly*/
    uint8_t subtlv_len;

} locator_tlv_t;

void locator_tlv_set_subtlv_len (locator_tlv_t *loc_tlv, uint8_t subtlv_len) ;
uint8_t locator_tlv_get_subtlv_len (locator_tlv_t *loc_tlv);
uint8_t locator_tlv_get_total_size (locator_tlv_t *loc_tlv) ;

typedef struct isis_tlv_27_subtlv_5_ {

    // not defined yet. // not defined yet. 7.2
    uint8_t flags;
    uint16_t endfn;
    uint8_t prefix[16];
    uint8_t subtlv_len;

} srv6_pfxsid_subtlv_t;

#pragma pack(pop)

uint32_t
isis_print_formatted_tlv130( byte* out_buff, byte* tlv130_start,  uint8_t tlv_len); 
uint32_t
isis_print_formatted_tlv236( byte* out_buff, byte* tlv236_start,  uint8_t tlv_len);

uint32_t
isis_print_formatted_tlv27( byte* out_buff, byte* tlv27_start,  uint8_t tlv_len);

pkt_size_t
isis_format_nbr_tlv22(byte *buff, 
                             byte *nbr_tlv_buffer,
                             uint8_t tlv_buffer_len);

pkt_size_t
isis_get_adv_data_size(isis_adv_data_t *adv_data);

byte *
isis_get_adv_data_tlv_content(
            isis_adv_data_t *advt_data, 
            byte *tlv_content) ;

uint32_t
isis_show_one_lsp_pkt_detail_info (byte *buff, isis_lsp_pkt_t *lsp_pkt);

bool isis_is_zero_fragment_tlv (uint16_t tlv_no);

#endif