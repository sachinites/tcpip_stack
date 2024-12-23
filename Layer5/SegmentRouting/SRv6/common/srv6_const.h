#ifndef __SRV6_CONST_H_
#define __SRV6_CONST_H_

#define SRV6_MAX_PFX_SID_PER_RTR    8
#define SRV6_DATA_BLOCK_SIZE 4          /* 4 Bytes */

typedef enum Srv6_flavor_ {

    PSP = 1,
    PSD = 2,
    USD = 4

} Srv6_flavor_t;

#define DEFAULT_FLAVOR (PSP | USD)

typedef enum Srv6_endpcode_ {
    
    END = 0,
    END_X = 1,
    END_T = 2,
    END_DX6 = 3,
    END_DX4 = 4,
    END_DT6 = 5,
    END_DT4 = 6,
    END_B6_ENCAP = 7,
    END_B6_ENCAP_X = 8

} Srv6_endpcode_t;


#endif 