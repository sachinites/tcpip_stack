#ifndef __ISIS_CONST__
#define __ISIS_CONST__

#define ISIS_ETH_PKT_TYPE               131
#define ISIS_PTP_HELLO_PKT_TYPE 17
#define ISIS_LSP_PKT_TYPE                18
#define ISIS_DEFAULT_HELLO_INTERVAL 3
#define ISIS_DEFAULT_INTF_COST  10  // as per standard
#define ISIS_ADJ_DEFAULT_DELETE_TIME (5 * 1000)
#define ISIS_LSP_DEFAULT_FLOOD_INTERVAL  1200
#define ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL (ISIS_LSP_DEFAULT_FLOOD_INTERVAL * 2)
/* Reconciliation Constants*/
#define ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME   (10 * 1000) 
#define ISIS_DEFAULT_RECONCILIATION_FLOOD_INTERVAL ( 2 * 1000) 

/*ISIS TLVs */
#define ISIS_TLV_HOSTNAME    137  // as per standard 
#define ISIS_TLV_RTR_ID            134  // as per standard 
#define ISIS_TLV_IF_IP                 132  // as per standard
#define ISIS_TLV_IF_MAC            131 // Imaginary
#define ISIS_TLV_HOLD_TIME   5
#define ISIS_TLV_METRIC_VAL 6
#define ISIS_TLV_IF_INDEX        4    // as per standard

#define ISIS_IS_REACH_TLV  22 // as per standard 0
#define ISIS_TLV_LOCAL_IP   6 // as per standard
#define ISIS_TLV_REMOTE_IP  8 // as per standard

#define ISIS_TLV_ON_DEMAND 111

#define ISIS_HOLD_TIME_FACTOR 2

/* Flags in LSP pkt isis_lsp_pkt_t->lsp_gen_flags */
#define ISIS_LSP_F_PURGE_LSP    1
#define ISIS_LSP_F_OVERLOAD    (1 << 1 )



#define ISIS_CONFIG_TRACE   "ISIS(CONFIG)"
#define ISIS_ADJ_TRACE   "ISIS(ADJ_MGMT)"
#define ISIS_LSPDB_TRACE "ISIS(LSPDB MGMT)"

#define ISIS_ERROR_NON_EXISTING_INTF \
    "Error : Non Existing Interface Specified"
    
#endif 
