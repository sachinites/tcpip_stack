#ifndef __ISIS_ADVT__
#define __ISIS_ADVT__

#include "isis_const.h"
#include "isis_enums.h"
#include "isis_events.h"
#include "isis_rtr.h"
#include "isis_tlv_struct.h"

typedef struct node_info_ isis_node_info_t;

/* LSP PKT Regen control flags*/
#define ISIS_SHOULD_INCL_PURGE_BIT  1
#define ISIS_SHOULD_INCL_OL_BIT (1 << 1)
#define ISIS_SHOULD_INCL_IS_REACH_TLVS (1 << 2)
#define ISIS_SHOULD_INCL_IP_REACH_TLVS (1 << 3)
#define ISIS_SHOULD_INCL_IPV6_REACH_TLVS (1 << 4)
#define ISIS_SHOULD_INCL_SRV6_TLVS (1 << 5)

#define ISIS_LSP_DEF_REGEN_FLAGS \
    ( ISIS_SHOULD_INCL_IS_REACH_TLVS | \
      ISIS_SHOULD_INCL_IP_REACH_TLVS  | \
      ISIS_SHOULD_INCL_IPV6_REACH_TLVS | \
      ISIS_SHOULD_INCL_SRV6_TLVS )

typedef struct isis_advt_info_ {

    uint8_t pn_no;
    uint8_t fr_no;
} isis_advt_info_t;

typedef struct isis_fragment_ {

    glthread_t tlv_list_head;
    glthread_t priority_list_glue;
    glthread_t frag_regen_glue;
    isis_lsp_pkt_t *lsp_pkt;
    uint32_t seq_no;
    uint32_t regen_flags;
    pkt_size_t bytes_filled;
    uint8_t pn_no;
    uint8_t fr_no;
    uint8_t ref_count;
    
} __attribute__((aligned(8))) isis_fragment_t;
GLTHREAD_TO_STRUCT(isis_priority_list_glue_to_fragment,
                                               isis_fragment_t,
                                               priority_list_glue);
GLTHREAD_TO_STRUCT(isis_frag_regen_glue_to_fragment,
                                               isis_fragment_t,
                                               frag_regen_glue);

typedef struct isis_advt_db_ {

    isis_fragment_t *fragments[ISIS_MAX_FRAGMENT_SUPPORTED];
    glthread_t fragment_priority_list;
    glthread_t advt_data_wait_list_head;

} __attribute__((aligned(8))) isis_advt_db_t;

/* This TLV is Waitlisted */
#define ISIS_ADVT_DATA_F_WAIT_LISTED  (1 << 0)
/* This TLV is being advertised */
#define ISIS_ADVT_DATA_F_ADVERTISED    (1 << 1)  

/* A Data structure which holds the data to be advertised as TLVs in 
    LSPs */
typedef struct isis_adv_data_ {

    union {

        char host_name[NODE_NAME_SIZE];

        struct {
            isis_system_id_t nbr_sys_id;
            uint32_t metric;
            uint32_t local_ifindex;
            uint32_t remote_ifindex;
            uint32_t local_intf_ip;
            uint32_t remote_intf_ip;
        } adj_data;

        /* Srv6 Locators - TLV 27*/
        struct {

                ipv6_addr_t prefix;
                glthread_t sibling_glue;
                glthread_t pfxsid_list_head;
                uint32_t metric;
                uint16_t mt_id;
                uint8_t prefix_len;
                uint8_t algorithm;
                uint8_t flags;
                uint8_t subtlv_len;

        } __attribute__((aligned(8)))   srv6_loc;


        /* SRv6 Prefix Sid locator Subtlvs*/
        struct {
            
            ipv6_addr_t prefix;
            struct isis_adv_data_ *parent;
            glthread_t sibling_glue;
            Srv6_endpcode_t endfn;
            uint8_t flags;
            uint8_t subtlv_len;

        } __attribute__((aligned(8))) srv6_pfxsid;

        /* SRv6 Adj Sid Subtlv*/
        struct {
            
            ipv6_addr_t prefix;
            Srv6_endpcode_t endfn;
            uint8_t flags;

        } srv6_adjsid;


        /* IPV6 Reachability TLVs - TLV236, 237*/
        struct {
            uint8_t prefix[16];
            uint32_t metric;
            uint8_t mask;
            uint8_t flags;
        } v6pfx;


        /* IPV4 Reachability TLVs */
        struct {
            uint32_t prefix;
            uint8_t mask;
            uint32_t metric;
            uint8_t flags;
        } pfx;


        /* Router Capability TLV: TLV 242*/
        struct {

            isis_rtr_cap_tlv242_t rtr_cap;
            bool is_rtr_cap_algo_subtlv19_present;
            isis_rtr_cap_algorithm_subtlv19_t rtr_cap_algorithm_subtlv19;
            bool is_rtr_cap_srv6_subtlv2_present;
            isis_rtr_cap_srv6_subtlv2_t rtr_cap_srv6_subtlv2;

        } __attribute__((aligned(8))) rtr_cap;

    } __attribute__((aligned(8))) u;

    isis_fragment_t *fragment;

    union {
        struct isis_adv_data_ **holder; // for IS REACH
    }src;

    glthread_t glue;
    pkt_size_t tlv_size;
    uint16_t tlv_no;
    uint16_t flags;

} __attribute__((aligned(8)))  isis_adv_data_t;
GLTHREAD_TO_STRUCT(glue_to_isis_advt_data, isis_adv_data_t, glue);
GLTHREAD_TO_STRUCT(
    srv6_loc_sibling_glue_to_locator_adv_data, 
    isis_adv_data_t, 
    u.srv6_loc.sibling_glue);
GLTHREAD_TO_STRUCT(
    srv6_pfxsid_sibling_glue_to_pfxsid_adv_data,
    isis_adv_data_t, 
    u.srv6_pfxsid.sibling_glue);

/* Fragment locking and Unlocking APIs */
void isis_fragment_lock (isis_fragment_t *fragment);
u_int8_t isis_fragment_unlock (node_t *node, isis_fragment_t *fragment);
void isis_fragment_dealloc_lsp_pkt (node_t *node, isis_fragment_t *fragment) ;
void isis_fragment_alloc_new_lsp_pkt (isis_fragment_t *fragment) ;
void isis_advt_data_clear_backlinkage(isis_node_info_t *node_info, isis_adv_data_t * isis_adv_data);

#define isis_fragment_prevent_premature_deletion    isis_fragment_lock
#define isis_fragment_relieve_premature_deletion  isis_fragment_unlock

isis_advt_tlv_return_code_t
isis_advertise_tlv (node_t *node, 
                                    pn_id_t pn_no,
                                    isis_adv_data_t *adv_data,
                                    isis_advt_info_t *advt_info_out);

bool 
isis_externally_learnt_tlv (uint8_t tlv_no);

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_adv_data_t *adv_data);

void isis_create_advt_db(isis_node_info_t *node_info, pn_id_t pn_no);
void isis_destroy_advt_db (node_t *node, pn_id_t pn_no);
void isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info);
void isis_discard_fragment (node_t *node, isis_fragment_t *fragment);
uint32_t isis_show_advt_db (node_t *node) ;
uint32_t isis_fragment_print (node_t *node, isis_fragment_t *fragment, byte *buff) ;
void isis_schedule_regen_fragment (node_t *node, 
                            isis_fragment_t *fragment,
                            isis_event_type_t event_type) ;
void isis_cancel_lsp_fragment_regen_job (node_t *node) ;
void isis_cancel_all_fragment_regen_job (node_t *node) ;
void isis_schedule_all_fragment_regen_job (node_t *node) ;
isis_fragment_t *isis_alloc_new_fragment () ;
void  isis_regenerate_lsp_fragment (node_t *node, isis_fragment_t *fragment, uint32_t regen_flags);
void isis_regen_all_fragments_from_scratch (event_dispatcher_t *, void *, uint32_t);
void isis_regen_zeroth_fragment(node_t *node) ;
bool isis_advertise_advt_data_in_this_fragment (node_t *node,
            isis_adv_data_t *advt_data, isis_fragment_t *fragment, bool force) ;
void isis_wait_list_advt_data_add (node_t *node, uint8_t pn_no, isis_adv_data_t *adv_data);
void isis_wait_list_advt_data_remove (node_t *node, isis_adv_data_t *adv_data);
void isis_free_advt_data (isis_adv_data_t *adv_data);
uint32_t isis_get_waitlisted_advt_data_count (node_t *node);

#endif  
