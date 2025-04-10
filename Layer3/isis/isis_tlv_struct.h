#ifndef __ISIS_TLV_STRUCT__
#define __ISIS_TLV_STRUCT__

#include <stdint.h>
#include "isis_struct.h"
#include "isis_const.h"

typedef struct isis_adv_data_ isis_adv_data_t;
typedef struct isis_pkt_ isis_lsp_pkt_t;

#pragma pack (push,1)

#define ISIS_EXTERN_ROUTE_F   (1<<7)
#define ISIS_INTERNAL_ROUTE_F   (1<<6)

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


/* SRv6 Rtr Capability SubTLV(2) */
typedef struct isis_rtr_cap_srv6_subtlv2_ {

    uint8_t type;
    uint8_t length;
    #define RTR_CAP_SUBTLV2_FLAG_T_ENCAP ( 1 << 14 )
    uint16_t flags;

    /* Max SL in SRH supported by platform*/
    /* The Maximum Segments Left MSD Type signals the maximum value of the
        "Segments Left" field [RFC8754] in the SRH of a received packet
        before applying the Endpoint behavior associated with a SID.

      SRH Max Segments Left Type: 41

      If no value is advertised, the supported value is 0.*/
    uint8_t max_sl_msd;


    /* MAX # of SIDs when applying PSP or USP flavors */
    /* The Maximum End Pop MSD Type signals the maximum number of SIDs in
        the SRH to which the router can apply "Penultimate Segment Pop (PSP)
        of the SRH" or "Ultimate Segment Pop (USP) of the SRH" behavior, as
        defined in "Flavors" (Section 4.16 of [RFC8986]).

      SRH Max End Pop Type: 42

      If the advertised value is zero or no value is advertised, then
      the router cannot apply PSP or USP flavors. */
    uint8_t max_end_pop_srh_msd;


    /* MAX # of T-INSERT SIDs supported by platform */
    uint8_t max_t_ins_srh_msd;



    /* MAX # of T-ENCAP SIDs supported by platform, valid when T_ENCAP flag is set */
    /* The Maximum H.Encaps MSD Type signals the maximum number of SIDs that
        can be added to the segment list of an SRH as part of the "H.Encaps"
        behavior, as defined in [RFC8986].

      SRH Max H.encaps Type: 44

      If the advertised value is zero or no value is advertised, then
      the headend can apply an SR Policy that only contains one segment
      without inserting any SRH header.

      A non-zero SRH Max H.encaps MSD indicates that the headend can
      insert an SRH up to the advertised number of SIDs. */
    uint8_t max_t_encap_srh_msd;



    /* MAX # of END.DX6 or END.DT6 SIDs supported by platform */
   /* The Maximum End D MSD Type specifies the maximum number of SIDs
   present in an SRH when performing decapsulation.  As specified in
   [RFC8986], the permitted SID types include, but are not limited to,
   End.DX6, End.DT4, End.DT46, End with USD, and End.X with USD.

      SRH Max End D Type: 45

      If the advertised value is zero or no value is advertised, then
      the router cannot apply any behavior that results in decapsulation
      and forwarding of the inner packet if the outer IPv6 header
      contains an SRH. */
    uint8_t max_end_D_srh_msd;

} isis_rtr_cap_srv6_subtlv2_t;

/* segment Routing Rtr Capability SubTLV 19 : RFC 8667 
    if not advertised at all, then default is SPF algo 0.
*/
typedef struct isis_rtr_cap_algorithm_subtlv19_ {

    uint8_t type;
    uint8_t length;
    uint8_t algorithms[2];

} isis_rtr_cap_algorithm_subtlv19_t;

/* Router Capability TLV :
    https://datatracker.ietf.org/doc/html/rfc7981#page-3
*/
typedef struct isis_rtr_cap_tlv242_ {

    uint32_t rtr_id;

    /* If the S bit is set(1), the IS-IS Router CAPABILITY TLV
        MUST be flooded across the entire routing domain.  If the S bit is
        not set(0), the TLV MUST NOT be leaked between levels.  This bit MUST
        NOT be altered during the TLV leaking. */
    #define RTR_CAP_FLAG_SBIT (1)
    /* Set if leaked from L2 to L1*/
    #define RTR_CAP_FLAG_DBIT (2)
    uint8_t flags;

    /* rtr cap SRv6 Sub-TLVs*/
    isis_rtr_cap_algorithm_subtlv19_t rtr_cap_algorithm_subtlv19[0];
    /* rtr cap SRv6 Sub-TLV*/
    isis_rtr_cap_srv6_subtlv2_t rtr_cap_srv6_subtlv2[0];

} isis_rtr_cap_tlv242_t;

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