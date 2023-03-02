#ifndef __ISIS_CONST_H__
#define __ISIS_CONST_H__

#define ISIS_ETH_PKT_TYPE 131
//x values in the ethernet packet
#define ISIS_PTP_HELLO_PKT_TYPE 17 //as per the standard 
#define ISIS_LSP_PKT_TYPE 18 //as per the standard 

#define ISIS_DEFAULT_HELLO_INTERVAL 3 
#define ISIS_DEFAULT_INTF_COST 10
#define ISIS_HOLD_TIME_FACTOR 2 

#define ISIS_TLV_HOSTNAME 137 //as per standard 
#define ISIS_TLV_RTR_ID 134 //as per standard 
#define ISIS_TLV_IF_IP 132 //as per standard 
#define ISIS_TLV_HOLD_TIME 5 
#define ISIS_TLV_METRIC 6 
#define ISIS_TLV_IF_INDEX 4 //as per stanard 

#endif
