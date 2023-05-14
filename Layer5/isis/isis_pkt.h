#ifndef __ISIS_PKT__
#define __ISIS_PKT__

#include "isis_events.h"
#include "isis_const.h"
#include "isis_struct.h"

typedef uint16_t isis_pkt_type_t;
typedef struct event_dispatcher_ event_dispatcher_t;
typedef struct isis_fragment_ isis_fragment_t;
typedef struct node_info_ isis_node_info_t;

typedef struct isis_pkt_ {

    /* The wired form of pkt */
    byte *pkt;
    /* pkt content size, including eithernet hdr */
    pkt_size_t pkt_size;
    /* Actually allocated size of the pkt*/
    pkt_size_t alloc_size;
    /* ref count on this pkt */
    uint16_t ref_count;
    /* No of interfaces out of which LSP has been
    Queued to xmit */
    uint16_t flood_queue_count;
    /* if set to false, this LSP would not xmit out */
    bool flood_eligibility;
    /* glue to attach this lsp pkt to lspdb*/
    avltree_node_t avl_node_glue;
    /* Life time timer */
    timer_event_handle *expiry_timer;
    /* to check if this LSP is present in lspdb or not */
    bool installed_in_db;
    /* Back pointer to the owning fragment*/
    isis_fragment_t *fragment;
    /*Timer to flood self LSP periodically */
    timer_event_handle *periodic_lsp_flood_timer;
} isis_lsp_pkt_t;

/*LSP Flags in lsp pkts*/

#define ISIS_LSP_PKT_F_OVERLOAD_BIT 1
#define ISIS_LSP_PKT_F_PURGE_BIT    (1 << 1)
#define ISIS_LSP_PKT_F_ON_DEMAND_BIT (1 << 2)

/*  LSP generation flags, used to control lsp manufacturing,
    these flags are set in node_info->lsp_generation_flags 
*/
#define ISIS_LSP_F_INCLUDE_PURGE_BIT    (1 << 0)
#define ISIS_LSP_F_INCLUDE_OL_BIT       (1 << 1)

#pragma pack (push,1)
/* Header of ISIS PKTS, common for Hellos and LSPs */

typedef uint8_t isis_pkt_hdr_flags_t;

typedef struct isis_pkt_hdr_{

    isis_pkt_type_t isis_pkt_type;
    uint32_t seq_no; /* meaningful only for LSPs */
    uint32_t rtr_id;
    uint16_t priority;/* meaningful only for hellos */
    uint8_t pn_no;
    uint8_t fr_no;
    isis_pkt_hdr_flags_t flags;
} isis_pkt_hdr_t;
#pragma pack(pop)

bool
isis_hello_pkt_trap_rule(char *pkt, size_t pkt_size);

bool
isis_lsp_pkt_trap_rule(char *pkt, size_t pkt_size);

void
isis_lsp_pkt_recieve_cbk(event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

void
isis_hello_pkt_recieve_cbk(event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

void
isis_lsp_pkt_flood_timer_start (node_t *node, isis_lsp_pkt_t *lsp_pkt) ;

void
isis_lsp_pkt_flood_timer_stop (isis_lsp_pkt_t *lsp_pkt) ;

void
isis_lsp_pkt_flood_timer_restart (node_t *node, isis_lsp_pkt_t *lsp_pkt) ;

void
isis_print_lsp_pkt_cbk(event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

void
isis_print_hello_pkt_cbk(event_dispatcher_t *ev_dis, void *arg, size_t arg_size);

void
isis_cancel_lsp_pkt_generation_task(node_t *node);

byte *
isis_prepare_hello_pkt(Interface *intf, size_t *hello_pkt_size);

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt) ;

uint32_t *
isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt);

pn_id_t
isis_get_lsp_pkt_pn_id(isis_lsp_pkt_t *lsp_pkt) ;

uint8_t
isis_get_lsp_pkt_fr_no (isis_lsp_pkt_t *lsp_pkt) ;

isis_pkt_hdr_flags_t
isis_lsp_pkt_get_flags(isis_lsp_pkt_t *lsp_pkt);

uint32_t
isis_deref_isis_pkt(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_ref_isis_pkt(isis_lsp_pkt_t *lsp_pkt);

#define isis_lsp_pkt_prevent_premature_deletion isis_ref_isis_pkt
#define isis_lsp_pkt_relieve_premature_deletion isis_deref_isis_pkt

uint16_t
isis_count_tlv_occurrences (byte *tlv_buffer,
                                              uint16_t tlv_buff_size, uint8_t tlv_no) ;

const c_string 
isis_pkt_type_str (isis_pkt_type_t pkt_type) ;

/* For ISIS RFC complying pkts , refer to 
https://techhub.hpe.com/eginfolib/networking/docs/switches/3600v2/5998-7619r_l3-ip-rtng_cg/content/442284234.htm
*/

#pragma pack (push,1)
typedef struct isis_common_hdr_ {

    uint8_t desc;
    uint8_t length_indicator;
    uint8_t protocol;
    uint8_t id_len;
    uint8_t pdu_type;
    uint8_t version;
    uint8_t reserved;
    uint8_t max_area_addr;
}  isis_common_hdr_t;

typedef struct isis_p2p_hello_pkt_hdr_ {

    uint8_t circuit_type;
    isis_system_id_t source_id;
    uint16_t hold_time;
    uint16_t pdu_len;
    uint8_t local_circuit_id;
} isis_p2p_hello_pkt_hdr_t;

typedef struct isis_lan_hello_pkt_hdr_ {

    uint8_t circuit_type;
    isis_system_id_t source_id;
    uint16_t hold_time;
    uint16_t pdu_len;
    uint8_t priority;
    isis_lan_id_t lan_id;
} isis_lan_hello_pkt_hdr_t;

typedef struct isis_lsp_hdr_ {

    uint16_t pdu_len;
    uint16_t rem_time;
    isis_lsp_id_t lsp_id;
    uint32_t seq_no;
    uint16_t checksum;
    #define LSP_HDR_P_BIT   (1 << 7)
    #define LSP_HDR_ATT_ERROR_BIT (1 << 6)
    #define LSP_HDR_ATT_EXPENSE_BIT (1 << 5)
    #define LSP_HDR_ATT_DELAY_BIT (1 << 4)
    #define LSP_HDR_ATT_DEFAULT_BIT (1 << 3)
    #define LSP_HDR_OL_BIT (1 << 2)
    #define LSP_HDR_IS_TYPE_BIT1 (1 << 1)
    #define LSP_HDR_IS_TYPE_BIT0 (1)
    uint8_t attributes;
} isis_lsp_hdr_t;

#pragma pack(pop)

isis_common_hdr_t *
isis_init_common_hdr (isis_common_hdr_t *hdr, uint8_t pdu_type);

isis_p2p_hello_pkt_hdr_t *
isis_init_p2p_hello_pkt_hdr (isis_p2p_hello_pkt_hdr_t *hdr, Interface *intf);

isis_lan_hello_pkt_hdr_t *
isis_init_lan_hello_pkt_hdr (isis_lan_hello_pkt_hdr_t *hdr, Interface *intf);

byte *
isis_get_pkt_tlv_buffer (isis_common_hdr_t *cmn_hdr, uint16_t *tlv_size);

/* LSP Hdr processing fns */
static inline ISIS_LVL
isis_rtr_is_type ( isis_lsp_hdr_t *lsp_hdr) {

    if (IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT0) &&
        !IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT1)) {
        
        return  isis_level_1;
    }

    if (!IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT0) &&
        IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT1)) {
        
        return  isis_level_2;
    }

    if (IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT0) &&
        IS_BIT_SET (lsp_hdr->attributes, LSP_HDR_IS_TYPE_BIT1)) {
        
        return  isis_level_12;
    }

    assert(0);
}

#endif // !__ISIS_PKT__
