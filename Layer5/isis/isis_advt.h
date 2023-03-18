#ifndef __ISIS_ADVT__
#define __ISIS_ADVT__

#if 0

Dependencies 
    <stdint.h>
    "../../gluethread/glthread.h"
    "../../graph.h"

#endif 

typedef struct node_info_ isis_node_info_t;

typedef struct isis_advt_info_ {

    uint8_t pn_no;
    uint8_t fr_no;
    uint64_t advt_id;
} isis_advt_info_t;


/* A Data structure which holds the data to be advertised as TLVs in 
    LSPs */
typedef struct isis_adv_data_ {

    uint64_t advt_id;
    uint16_t tlv_no;

    union {
        
        uint32_t rtr_id;

        struct {

            char nbr_name[NODE_NAME_SIZE];
            uint32_t nbr_rtr_id;
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

    isis_advt_info_t advt_info;
    glthread_t glue;
    
} isis_adv_data_t;
GLTHREAD_TO_STRUCT(glue_to_isis_advt_data, isis_adv_data_t, glue);

uint16_t 
isis_get_adv_data_size (isis_adv_data_t *adv_data);

typedef struct isis_fragment_ {

    uint16_t bytes_filled;
    glthread_t tlv_list_head;
    glthread_t priority_list_glue;
    uint32_t seq_no;
    uint8_t pn_no;
    uint8_t fr_no;
    pkt_block_t *lsp_pkt;
}isis_fragment_t;
GLTHREAD_TO_STRUCT(isis_priority_list_glue_to_fragment,
                                               isis_fragment_t,
                                               priority_list_glue);

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
    ISIS_TLV_WD_NOT_FOUND,
    ISIS_TLV_WD_FAILED
}isis_tlv_wd_return_code_t;

typedef struct isis_advt_db_ {

    isis_fragment_t *fragments[ISIS_MAX_FRAGMENT_SUPPORTED];
    glthread_t fragment_priority_list;
} isis_advt_db_t;

/* LSP PKT Regen control flags*/
#define ISIS_SHOULD_INCL_PURGE_BIT  1
#define ISIS_SHOULD_INCL_OL_BIT 2
#define ISIS_SHOULD_INCL_ON_DEM_BIT 4

isis_tlv_record_advt_return_code_t
isis_record_tlv_advertisement (node_t *node, 
                                    uint8_t pn_no,
                                    isis_adv_data_t *adv_data,
                                    isis_advt_info_t *advt_info_out);

void
isis_regenerate_lsp_fragment (node_t *node, isis_fragment_t *fragment, uint32_t regen_ctrl_flags);

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_advt_info_t *advt_info);

void isis_create_advt_db(isis_node_info_t *node_info, uint8_t pn_no);
void isis_destroy_advt_db (isis_node_info_t *node_info, uint8_t pn_no);
void isis_destroy_all_advt_db(isis_node_info_t *node_info);
void isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info);

#endif  