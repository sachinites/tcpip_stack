#ifndef __FIB_ENUMS__
#define __FIB_ENUMS__

typedef enum FIB_AFI_ {

    FIB_AF_IPV4,
    FIB_AF_IPV6,
    FIB_AF_LABEL,
    FIB_AFI_MAC,
    FIB_AFI_MAX

} FIB_AFI_T;

typedef enum fib_mpls_op_ {

    FIB_LBL_STACK_OPS_UNKNOWN,
    FIB_LBL_SWAP,
    FIB_LBL_CONTINUE = FIB_LBL_SWAP,
    FIB_LBL_NEXT,
    FIB_LBL_PUSH = FIB_LBL_NEXT,
    FIB_LBL_POP

} fib_mpls_op_t;

#define FIB_NH_FWD_F_IPV4 1
#define FIB_NH_FWD_F_IPV6 2
#define FIB_NH_FWD_F_MPLS_LBL_STCK 4
#define FIB_NH_FWD_F_IPV6_STCK 8

#define FIB_MAX_ECMP_NH 8

#endif 