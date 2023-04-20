#ifndef __ISIS_ADVT__
#define __ISIS_ADVT__

#include "isis_const.h"
#include "isis_rtr.h"
#include "isis_pn.h"

typedef struct node_info_ isis_node_info_t;
typedef uint64_t advt_id_t;


typedef enum isis_tlv_record_advt_return_code_ {

    ISIS_TLV_RECORD_ADVT_SUCCESS,
    ISIS_TLV_RECORD_ADVT_ALREADY,
    ISIS_TLV_RECORD_ADVT_NO_SPACE,
    ISIS_TLV_RECORD_ADVT_NO_FRAG,
    ISIS_TLV_RECORD_ADVT_NOT_FOUND,
    ISIS_TLV_RECORD_ADVT_FAILED
}isis_tlv_record_advt_return_code_t;

typedef enum isis_tlv_wd_return_code_ {

    ISIS_TLV_WD_SUCCESS,
    ISIS_TLV_WD_FRAG_NOT_FOUND,
    ISIS_TLV_WD_TLV_NOT_FOUND,
    ISIS_TLV_WD_FAILED
}isis_tlv_wd_return_code_t;


/* LSP PKT Regen control flags*/
#define ISIS_SHOULD_INCL_PURGE_BIT  1
#define ISIS_SHOULD_INCL_OL_BIT (1 << 1)
#define ISIS_SHOULD_INCL_ON_DEM_BIT (1 << 2)
#define ISIS_SHOULD_RENEW_LSP_PKT_HDR   (1 << 3)
#define ISIS_SHOULD_REWRITE_ETH_HDR (1 << 4)

typedef struct isis_advt_info_ {

    uint8_t pn_no;
    uint8_t fr_no;
    advt_id_t advt_id;
} isis_advt_info_t;

static inline bool
isis_is_advt_info_empty (isis_advt_info_t *advt_info) {

    return (!advt_info->pn_no && !advt_info->fr_no && !advt_info->advt_id);
}

pkt_size_t
isis_get_adv_data_size (isis_adv_data_t *adv_data);

typedef struct isis_fragment_ {

    pkt_size_t bytes_filled;
    glthread_t tlv_list_head;
    glthread_t priority_list_glue;
    uint32_t seq_no;
    uint8_t pn_no;
    uint8_t fr_no;
    pkt_block_t *lsp_pkt;
    uint32_t regen_flags;
    uint8_t ref_count;
}isis_fragment_t;
GLTHREAD_TO_STRUCT(isis_priority_list_glue_to_fragment,
                                               isis_fragment_t,
                                               priority_list_glue);

typedef struct isis_advt_db_ {

    isis_fragment_t *fragments[ISIS_MAX_FRAGMENT_SUPPORTED];
    glthread_t fragment_priority_list;
} isis_advt_db_t;

/* A Data structure which holds the data to be advertised as TLVs in 
    LSPs */
typedef struct isis_adv_data_ {

    advt_id_t advt_id;
    uint16_t tlv_no;

    union {
        
        uint32_t rtr_id;

        struct {
            isis_system_id_t nbr_sys_id;
            uint32_t metric;
            uint32_t local_ifindex;
            uint32_t remote_ifindex;
            uint32_t local_intf_ip;
            uint32_t remote_intf_ip;
        } adj_data;

        bool on_demand_tlv;
      
        char host_name[NODE_NAME_SIZE];

        uint32_t flags;

        struct {
            uint32_t prefix;
            uint8_t mask;
            uint32_t cost;
        } pfx;

    }u;

    glthread_t glue;
    isis_fragment_t *fragment;
    struct isis_adv_data_ **holder;
} isis_adv_data_t;
GLTHREAD_TO_STRUCT(glue_to_isis_advt_data, isis_adv_data_t, glue);

/* Short hand macros */
#define ISIS_GET_FRAGMENT(node_info, advt_info)   \
    (node_info->advt_db[advt_info->pn_no]->fragments[advt_info->fr_no])

static inline void
isis_fragment_lock (isis_fragment_t *fragment) {

    fragment->ref_count++;
}

static inline void
isis_fragment_unlock (isis_node_info_t *node_info, isis_fragment_t *fragment) {

    fragment->ref_count--;
    if (fragment->ref_count) return;
    /* Should not leak any memory*/
    assert(IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head));
    assert(!fragment->lsp_pkt);
    /*should not leave dangling pointers by referenced objects*/
    assert(!node_info->advt_db[fragment->pn_no]->fragments[fragment->fr_no]);
    assert(!IS_QUEUED_UP_IN_THREAD(&fragment->priority_list_glue));
    printf ("fragment [%hu][%hu] deleted\n", fragment->pn_no, fragment->fr_no);
    XFREE(fragment);
}

isis_tlv_record_advt_return_code_t
isis_record_tlv_advertisement (node_t *node, 
                                    pn_id_t pn_no,
                                    isis_adv_data_t *adv_data,
                                    isis_adv_data_t **back_linkage,
                                    isis_advt_info_t *advt_info_out);

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_adv_data_t *adv_data);

void isis_create_advt_db(isis_node_info_t *node_info, pn_id_t pn_no);
void isis_destroy_advt_db (node_t *node, pn_id_t pn_no);
void isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info);
void isis_discard_fragment (node_t *node, isis_fragment_t *fragment, bool purge) ;
uint32_t isis_show_advt_db (node_t *node) ;
uint32_t isis_fragment_print (node_t *node, isis_fragment_t *fragment, byte *buff) ;

#endif  