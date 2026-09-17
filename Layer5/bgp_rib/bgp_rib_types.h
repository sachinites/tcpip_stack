#ifndef BGP_RIB_TYPES_H_
#define BGP_RIB_TYPES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BGP_NLRI_WIRE_MAX      320
#define BGP_RIB_EXT_COMM_MAX   16
#define BGP_RIB_EXT_COMM_TEXT_MAX 80

typedef enum bgp_rib_err_ {
    BGP_RIB_OK = 0,
    BGP_RIB_ERR_NULL,
    BGP_RIB_ERR_NOMEM,
    BGP_RIB_ERR_NOT_FOUND,
    BGP_RIB_ERR_INVALID_KEY,
    BGP_RIB_ERR_UNSUPPORTED_NLRI,
    BGP_RIB_ERR_DECODE,
    BGP_RIB_ERR_ENCODE
} bgp_rib_err_t;

typedef struct bgp_nlri_key_ {
    uint16_t wire_len;
    uint8_t  wire[BGP_NLRI_WIRE_MAX];
} bgp_nlri_key_t;

typedef struct bgp_rib_ext_comm_ {
    uint16_t type;
    uint16_t subtype;
    char     text[BGP_RIB_EXT_COMM_TEXT_MAX];
} bgp_rib_ext_comm_t;

typedef struct bgp_rib_attrs_ {
    char     nexthop[48];
    uint8_t  origin;
    bool     origin_present;
    uint32_t med;
    bool     med_present;
    uint32_t local_pref;
    bool     local_pref_present;
    char     import_rt[32];
    bool     rt_present;
    bool     best;
    bool     is_from_external;
    uint8_t  ext_comm_count;
    bgp_rib_ext_comm_t ext_comms[BGP_RIB_EXT_COMM_MAX];
    uint32_t evpn_label1;
    bool     evpn_label1_present;
    bool     evpn_label1_from_ext_comm;
    uint32_t mac_mobility_seq;
    bool     mac_mobility_seq_present;
    uint32_t pmsi_label;
    bool     pmsi_label_present;
    uint8_t  pmsi_tunnel_type;
    uint16_t tunnel_encap_type;
    bool     tunnel_encap_present;
} bgp_rib_attrs_t;

const char *
bgp_rib_err_to_string(bgp_rib_err_t err);

#endif /* BGP_RIB_TYPES_H_ */
