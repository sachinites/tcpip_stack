#ifndef __SRV6_CONST_H_
#define __SRV6_CONST_H_

#include <stdint.h>

#define SRV6_MAX_PFX_SID_PER_RTR    8
#define SRV6_DATA_BLOCK_SIZE 4          /* 4 Bytes */

typedef enum Srv6_flavor_ {

    PSP = 1, // Remove SRH on penultimate node
    USP = 2, // Remove SRH on ultimate nod, but keep ipv6 hdr
    USD = 4 // Remove SRH and ipv6 hdr on ultimate node, and expose payload

} Srv6_flavor_t;

#define DEFAULT_FLAVOR (0)
#define LOCATOR_NAME_SIZE   32

/* https://www.rfc-editor.org/rfc/rfc8986.pdf : page 33*/
typedef enum Srv6_endpcode_ {
    
    SRV6_END_FN_NONE,
    END = 1,
    END_w_PSP,
    END_w_USP,
    END_w_PSP_USP,
    END_X,
    END_X_w_PSP,
    END_X_w_USP,
    END_X_w_PSP_USP,
    END_T,
    END_T_w_PSP,
    END_T_w_USP,
    END_T_w_PSP_USP,
    SRV6_END_UNASSIGNED1,
    END_B6_ENCAP = 14,
    END_BM,
    END_DX6,
    END_DX4,
    END_DT6,
    END_DT4,
    END_DT46,
    END_DX2,
    END_DX2V,
    END_DT2U,
    END_DT2M,
    SRV6_END_UNASSIGNED2,
    SRV6_END_UNASSIGNED3,
    END_B6_ENCAPS_Red,
    END_w_USD,
    END_w_PSP_USD,
    END_X_USP_USD,
    END_w_PSP_USP_USD,
    END_X_w_USD,
    END_X_w_PSP_USD,
    END_X_w_USP_USD,
    END_X_w_PSP_USP_USD,
    END_T_w_USD,
    END_T_w_PSP_USD,
    END_T_w_USP_USD,
    END_T_w_PSP_USP_USD

} Srv6_endpcode_t;

Srv6_endpcode_t 
srv6_split_endpcode (Srv6_endpcode_t endpcode, uint8_t *flavor) ;

const char *
srv6_end_fn_str(Srv6_endpcode_t end_fn);

const char *
srv6_flavor_str(uint8_t flavors) ;

Srv6_endpcode_t 
srv6_get_composite_END_X_endpcode (uint8_t flavor) ;

Srv6_endpcode_t 
srv6_get_composite_END_endpcode (uint8_t flavor) ;

#endif 