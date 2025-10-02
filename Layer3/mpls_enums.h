#ifndef  __MPLS_ENUMS__
#define __MPLS_ENUMS__

#include <stdint.h>
#include "../tcpconst.h"

#define MAX_LBL_DEPTH 8

typedef uint32_t label_val_t;

typedef enum mpls_op_ {

    LBL_STACK_OPS_UNKNOWN,
    LBL_SWAP,
    LBL_CONTINUE = LBL_SWAP,
    LBL_NEXT,
    LBL_PUSH = LBL_NEXT,
    LBL_POP

} mpls_op_t;

static inline const char *
mpls_op_tostring(mpls_op_t op)
{

    switch (op)
    {

    case LBL_SWAP:
        return "swap";
    case LBL_PUSH:
        return "push";
    case LBL_POP:
        return "pop";
    default:
        return "unknown";
    }
}

typedef enum {

    lbl_proto_nxthop_first,
    lbl_proto_nxthop_static = lbl_proto_nxthop_first,
    lbl_proto_nxthop_isis,
    lbl_proto_nxthop_ldp,
    lbl_proto_nxthop_max

} labelled_nxthop_proto_id_t;

static inline  labelled_nxthop_proto_id_t
lbl_next_next_hop_proto ( labelled_nxthop_proto_id_t proto_id ) {

    switch (proto_id) {

        case lbl_proto_nxthop_static:
            return lbl_proto_nxthop_isis;
        case lbl_proto_nxthop_isis:
            return lbl_proto_nxthop_ldp;
        case lbl_proto_nxthop_ldp:
            return lbl_proto_nxthop_max;
    }

    return lbl_proto_nxthop_max;
}

static inline labelled_nxthop_proto_id_t
labelled_rt_map_proto_id_to_nxthop_index(uint16_t proto_id) {

    switch(proto_id) {

        case PROTO_STATIC:
            return lbl_proto_nxthop_static;
        case PROTO_ISIS:
            return lbl_proto_nxthop_isis;
        case PROTO_LDP:
            return lbl_proto_nxthop_ldp;
        default:
        ;
    }
    return lbl_proto_nxthop_max;
}

#define FOR_ALL_LABELLED_NXTHOP_PROTO(nh_proto)  \
    for (nh_proto =lbl_proto_nxthop_first; nh_proto < lbl_proto_nxthop_max; \
         nh_proto = lbl_next_next_hop_proto(nh_proto))


static const char * 
labelled_nxthop_proto_id_tostring (labelled_nxthop_proto_id_t proto_id) {

    switch (proto_id) {

        case lbl_proto_nxthop_static:
            return "static";
        case lbl_proto_nxthop_isis:
            return "l-isis";
        case lbl_proto_nxthop_ldp:
            return "ldp";
        default:
            return "unknown";
    }
}
#endif // ! __MPLS_ENUMS__