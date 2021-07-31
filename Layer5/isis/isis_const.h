#ifndef __ISIS_CONST__
#define __ISIS_CONST__

#define ISIS_ETH_PKT_TYPE       131 // ( Randomly chosen, no logic)
#define ISIS_PTP_HELLO_PKT_TYPE 17  // as per standard
#define ISIS_LSP_PKT_TYPE       18  // as per standard
#define ISIS_DEFAULT_HELLO_INTERVAL 3
#define ISIS_DEFAULT_INTF_COST  10  // as per standard
#define ISIS_HOLD_TIME_FACTOR   2
#define ISIS_ADJ_DEFAULT_DELETE_TIME (5 * 1000) // 5 sec
#define ISIS_LSP_DEFAULT_FLOOD_INTERVAL  30 // 1200 sec is standardc
#define ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL (ISIS_LSP_DEFAULT_FLOOD_INTERVAL * 2)
#define ISIS_DEFAULT_ON_DEMAND_FLOODING_STATUS false

/* Reconciliation Constants */
#define ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME   (5 * 1000) // msec
#define ISIS_DEFAULT_RECONCILIATION_FLOOD_INTERVAL   (3 * 3000) // msec

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
#define ISIS_TLV_ON_DEMAND  111 // imaginary


#define ISIS_LSP_HDR_SIZE   (sizeof(isis_pkt_type_t) + \
                             sizeof(uint32_t) +        \
                             sizeof(uint32_t))

/* Common Error Msgs */
#define ISIS_ERROR_NON_EXISTING_INTF \
    "Error : Non Existing Interface Specified"

#define ISIS_ERROR_PROTO_NOT_ENABLE \
    "Error : Protocol not enabled on Device"

#endif 
