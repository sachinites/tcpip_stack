#ifndef __ISIS_CONST__
#define __ISIS_CONST__

#define ISIS_HELLO_ETH_PKT_TYPE     231 // ( Randomly chosen, no logic)
#define ISIS_LSP_ETH_PKT_TYPE       232 // ( Randomly chosen, no logic)
#define ISIS_LAN_L1_HELLO_PKT_TYPE  15 // as per standard
#define ISIS_LAN_L2_HELLO_PKT_TYPE  16 // as per standard
#define ISIS_PTP_HELLO_PKT_TYPE 17  // as per standard
#define ISIS_L1_LSP_PKT_TYPE       18  // as per standard
#define ISIS_L2_LSP_PKT_TYPE       20  // as per standard
#define ISIS_DEFAULT_HELLO_INTERVAL 3
#define ISIS_DEFAULT_INTF_COST  10  // as per standard
#define ISIS_HOLD_TIME_FACTOR   2
#define ISIS_ADJ_DEFAULT_DELETE_TIME (5 * 1000) // 5 sec
#define ISIS_LSP_DEFAULT_FLOOD_INTERVAL  30 // 1200 sec is standard
#define ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL (ISIS_LSP_DEFAULT_FLOOD_INTERVAL * 2)
#define ISIS_INTF_DEFAULT_PRIORITY  64
#define ISIS_LSP_ID_STR_SIZE    48 // xxx.xxx.xxx.xxx-65535-255[4294967295]

/*ISIS TLVs */
#define ISIS_TLV_HOSTNAME   137 // as per standard 
#define ISIS_TLV_RTR_ID     134 // as per standard 
#define ISIS_TLV_IF_IP      132 // as per standard 
#define ISIS_TLV_IPV6_REACH 236 // as per standard 
#define ISIS_TLV_IPV6_MT_REACH 237 // as per standard 
#define ISIS_TLV_LOCATOR    27 // as per standard 
#define ISIS_LOCATOR_PFX_SID_SUBTLV  5 // as per standard 
#define ISIS_TLV_HOLD_TIME  5
#define ISIS_TLV_METRIC_VAL 6

#define ISIS_IS_REACH_TLV  22 // as per standard 
#define ISIS_TLV_IF_INDEX   4 // as per standard
#define ISIS_TLV_LOCAL_IP   6 // as per standard
#define ISIS_TLV_REMOTE_IP  8 // as per standard
#define ISIS_TLV_IF_MAC      131 // Imaginary
#define ISIS_TLV_IP_REACH   130

/* Router Capability TLV */
#define ISIS_TLV_RTR_CAP    242
#define ISIS_TLV_RTR_CAP_ALGO_SUBTLV 19
#define ISIS_TLV_RTR_CAP_SRV6_SUBTLV 2

/* Segment Routing ( SR-MPLS ) - very basic / minimal support.
    NOTE : RFC 8667 assigns Sub-TLV type 2 to the SR-Capabilities (SRGB)
    Sub-TLV of TLV 242. This codebase already uses type 2 for the SRv6
    Capability Sub-TLV (see ISIS_TLV_RTR_CAP_SRV6_SUBTLV above), so a
    distinct, non-conflicting type is used here so that SRv6 and SR-MPLS
    can be advertised independently, in the same LSP, without clashing. */
#define ISIS_TLV_RTR_CAP_SR_CAP_SUBTLV 9
/* Self-contained, non-standard Node-SID TLV. Real IS-IS Segment Routing
    (RFC 8667) encodes the Prefix-SID as a Sub-TLV of the Extended IP
    Reachability TLV(135), but this stack's IPv4 Reachability TLV(130)
    does not support Sub-TLVs. To keep this minimal, the Node-SID is
    advertised in its own dedicated top level TLV instead. */
#define ISIS_TLV_NODE_SID    149

/* Default SRGB ( Segment Routing Global Block ) */
#define ISIS_SR_DEFAULT_SRGB_BASE    16000
#define ISIS_SR_DEFAULT_SRGB_RANGE    8000

/* SRv6 MSD Defauls Values */
#define MAX_END_D_SRH_MSD 4
#define MAX_T_ENCAP_SRH_MSD 4
#define MAX_T_INS_SRH_MSD 4
#define MAX_END_POP_SRH_MSD 4
#define MAX_SL_MSD 4

#define SPF_ALOGORITHM 0
#define SPF_STRICT_ALOGORITHM 1




#define ISIS_LSP_HDR_SIZE   sizeof(isis_pkt_hdr_t)
#define ISIS_LSP_MAX_PKT_SIZE   1492
#define ISIS_MAX_FRAGMENT_SUPPORTED 256
#define ISIS_MAX_PN_SUPPORTED   256

/* Common Error Msgs */
#define ISIS_ERROR_NON_EXISTING_INTF \
    "Error : Non Existing Interface Specified"

#define ISIS_ERROR_PROTO_NOT_ENABLE \
    "Error : Protocol not enabled on Device"

#define ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF \
    "Error : Protocol not enabled on interface"

/* Feature Name for logging */
#define ISIS_ADJ_MGMT   " ISIS(ADJ MGMT)"
#define ISIS_LSPDB_MGMT " ISIS(LSPDB MGMT)"
#define ISIS_SPF        " ISIS(SPF)"
#define ISIS_ERROR      " ISIS(ERROR)"
#define ISIS_PKT        " ISIS(PKT)"
#define ISIS_EXPOLICY " ISIS(EX-POLICY)"
#define ISIS_ROUTE " ISIS(ROUTE)"
#define ISIS_SRV6 " ISIS(SRV6)"
#define ISIS_SR_MPLS " ISIS(SR-MPLS)"

/* ISIS Trace Codes*/
#define TR_ISIS_SPF                   (1 << 0)
#define TR_ISIS_EVENTS          (1 << 1)
#define TR_ISIS_LSDB               (1 << 2)
#define TR_ISIS_PKT                  (1 << 3)
#define TR_ISIS_PKT_HELLO   (1 << 4)
#define TR_ISIS_PKT_LSP         (1 << 5)
#define TR_ISIS_ADJ                  (1 << 6)
#define TR_ISIS_ROUTE            (1 << 7)
#define TR_ISIS_POLICY           (1 << 8)
#define TR_ISIS_ERRORS         (1 << 9)
#define TR_ISIS_IPC                   (1 << 10)
#define TR_ISIS_SRV6                (1 << 11)
#define TR_ISIS_SR_MPLS         (1 << 12)
#define TR_ISIS_ALL                 (TR_ISIS_SPF |  \
                                                       TR_ISIS_EVENTS | \
                                                       TR_ISIS_LSDB | \
                                                       TR_ISIS_PKT | \
                                                       TR_ISIS_PKT_HELLO | \
                                                       TR_ISIS_PKT_LSP | \
                                                       TR_ISIS_ADJ | \
                                                       TR_ISIS_ROUTE | \
                                                       TR_ISIS_POLICY | \
                                                       TR_ISIS_ERRORS | \
                                                       TR_ISIS_IPC | \
                                                       TR_ISIS_SRV6 | \
                                                       TR_ISIS_SR_MPLS )

#endif 
