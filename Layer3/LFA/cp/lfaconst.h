#ifndef __LFA_CONST__
#define __LFA_CONST__


#define ISIS_L1_LFA_INFEX     0
#define ISIS_L2_LFA_INFEX     1
#define OSPF_LFA_INDEX  2
#define LDP_LFA_INDEX    3
#define RSVP_LFA_INDEX  4
#define MAX_LFA_INDEX  5

#define FOR_ALL_LFA_INDEXES(i)  \
    for (i = 0; i < MAX_LFA_INDEX; i++)

#define TR_LFA_ISIS (1 << 0)
#define TR_LFA_DB_UPDATE (1 << 1)
#define TR_LFA_SPF_COMPUTE  (1 << 2)
#define TR_LFA_SPF_COMPUTE_DETAIL (1 << 3)
#define TR_LFA_RLFA (1 << 4)
#define TR_LFA_LFA (1 << 5)
#define TR_LFA_TILFA (1 << 6)
#define TR_LFA_EVENTS ( 1<< 7)
#define TR_LFA_ERROR (1 << 8)
#define TR_LFA_ALL  (0xFFFFFFFF)

#define LFA_NODE_INFO(node_ptr) \
    (node_ptr->node_nw_prop.lfa)

#define LFA_TR(node_ptr)  \
    ((LFA_NODE_INFO(node_ptr))->tr)

#define LFA_ISIS_LSP_LOG "ISIS LSP"

#endif 