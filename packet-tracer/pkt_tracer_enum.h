#ifndef __PKT_TRACER_ENUM__
#define __PKT_TRACER_ENUM__

typedef enum pkt_tracer_type_ {

    PTK_TR_TYPE_CAPTURE,
    PKT_TR_TYPE_ARP,
    PKT_TR_TYPE_L3,
    PKT_TR_TYPE_IP_ACCESS_LIST,
    PKT_TR_TYPE_L2,
    PKT_TR_TYPE_L4,
    PKT_TR_TYPE_L5,
    PKT_TR_TYPE_NAT,
    PKT_TR_TYPE_MAX
}pkt_tracer_type_t;

static inline const unsigned char *
pkt_tracer_type_to_str(pkt_tracer_type_t type)
{
    switch (type)
    {
    case PTK_TR_TYPE_CAPTURE:
        return "CAPTURE";
    case PKT_TR_TYPE_ARP:
        return "ARP";
    case PKT_TR_TYPE_L3:
        return "L3";
    case PKT_TR_TYPE_IP_ACCESS_LIST:
        return "ACCESS LIST";
    case PKT_TR_TYPE_L2:
        return "L2";
    case PKT_TR_TYPE_L4:
        return "L4";
    case PKT_TR_TYPE_L5:
        return "L5";
    case PKT_TR_TYPE_NAT:
        return "NAT";
    case PKT_TR_TYPE_MAX:
    default:
        return NULL;
    }
}

typedef enum pkt_tracer_subtype_ {

    PKT_TR_TYPE_CAPTURE_SUBTYPE_IN,
    PKT_TR_TYPE_CAPTURE_SUBTYPE_OUT,

    PKT_TR_TYPE_ARP_SUBTYPE_BROADCAST,
    PKT_TR_TYPE_ARP_SUBTYPE_RESOLVE,
    PKT_TR_TYPE_ARP_SUBTYPE_ADJACENCY_LOOKUP,

    PKT_TR_TYPE_L3_SUBTYPE_ROUTE_LOOKUP,
    PKT_TR_TYPE_L3_SUBTYPE_FWD,
    PKT_TR_TYPE_L3_SUBTYPE_TO_L4,
    PKT_TR_TYPE_L3_SUBTYPE_TO_L5,
    PKT_TR_TYPE_L3_SUBTYPE_TO_L2,

    PKT_TR_TYPE_IP_ACCESS_LIST_SUBTYPE_LOG,

    PKT_TR_TYPE_L2_SUBTYPE_MACTABLE_LOOKUP,
    PKT_TR_TYPE_L2_SUBTYPE_MACTABLE_INSTALL_ENTRY,

    PKT_TR_TYPE_L4_SUBTYPE_NONE,

    PKT_TR_TYPE_L5_SUBTYPE_NONE,

    PKT_TR_TYPE_NAT_SUBTYPE_LOOKUP,

    PKT_TR_TYPE_SUBTYPE_MAX

}pkt_tracer_subtype_t;

static inline const unsigned char *
pkt_tracer_subtype_to_str(pkt_tracer_subtype_t subtype) {

    return NULL;
}

typedef enum pkt_tracer_result_ {

    PKT_TR_ALLOW,
    PKT_TR_DROP
}pkt_tracer_result_t;


#endif 

