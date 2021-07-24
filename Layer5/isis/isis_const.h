#ifndef __ISIS_CONST__
#define __ISIS_CONST__

#define ISIS_ETH_PKT_TYPE       131
#define ISIS_PTP_HELLO_PKT_TYPE 17
#define ISIS_LSP_PKT_TYPE       18
#define ISIS_DEFAULT_HELLO_INTERVAL 3
#define ISIS_DEFAULT_INTF_COST  10
#define ISIS_HOLD_TIME_FACTOR   2
#define ISIS_ADJ_DEFAULT_DELETE_TIME (5 * 1000) // 5k msec

/*ISIS TLVs */
#define ISIS_TLV_NODE_NAME  1
#define ISIS_TLV_RTR_ID     2
#define ISIS_TLV_IF_IP      3
#define ISIS_TLV_IF_MAC     4
#define ISIS_TLV_HOLD_TIME  5
#define ISIS_TLV_METRIC_VAL 6

/* Common Error Msgs */
#define ISIS_ERROR_NON_EXISTING_INTF \
    "Error : Non Existing Interface Specified"

#define ISIS_ERROR_PROTO_NOT_ENABLE \
    "Error : Protocol not enabled on Device"

#endif 
