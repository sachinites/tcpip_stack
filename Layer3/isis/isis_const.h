#ifndef __ISIS_CONST__
#define __ISIS_CONST__

#define ISIS_HELLO_ETH_PKT_TYPE       131 // ( Randomly chosen, no logic)
#define ISIS_LSP_ETH_PKT_TYPE       132 // ( Randomly chosen, no logic)
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
#define ISIS_LSP_ID_STR_SIZE    32 //  abc.def.ghi.jkl-123-123

/*ISIS TLVs */
#define ISIS_TLV_HOSTNAME   137 // as per standard 
#define ISIS_TLV_RTR_ID     134 // as per standard 
#define ISIS_TLV_IF_IP      132 // as per standard 
#define ISIS_TLV_HOLD_TIME  5
#define ISIS_TLV_METRIC_VAL 6

#define ISIS_IS_REACH_TLV  22 // as per standard 
#define ISIS_TLV_IF_INDEX   4 // as per standard
#define ISIS_TLV_LOCAL_IP   6 // as per standard
#define ISIS_TLV_REMOTE_IP  8 // as per standard
#define ISIS_TLV_IF_MAC      131 // Imaginary
#define ISIS_TLV_IP_REACH   130

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
#define TR_ISIS_ALL                 (TR_ISIS_SPF |  \
                                                       TR_ISIS_EVENTS | \
                                                       TR_ISIS_LSDB | \
                                                       TR_ISIS_PKT | \
                                                       TR_ISIS_PKT_HELLO | \
                                                       TR_ISIS_PKT_LSP | \
                                                       TR_ISIS_ADJ | \
                                                       TR_ISIS_ROUTE | \
                                                       TR_ISIS_POLICY | \
                                                       TR_ISIS_ERRORS \
                                                        )

#endif 
