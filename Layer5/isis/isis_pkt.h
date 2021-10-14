#ifndef __ISIS_PKT__
#define __ISIS_PKT__

#include "isis_events.h"
#include "isis_const.h"

typedef uint16_t isis_pkt_type_t;

typedef struct isis_pkt_ {

    /* The wired form of pkt */
    byte *pkt;
    /* pkt size, including eithernet hdr */
    size_t pkt_size;
    
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
} isis_lsp_pkt_t;

/*LSP Flags in lsp pkts*/

#define ISIS_LSP_PKT_F_OVERLOAD_BIT 1
#define ISIS_LSP_PKT_F_PURGE_BIT    (1 << 1)

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
    isis_pkt_hdr_flags_t flags;
} isis_pkt_hdr_t;
#pragma pack(pop)

bool
isis_lsp_pkt_trap_rule(char *pkt, size_t pkt_size);

void
isis_pkt_recieve(void *arg, size_t arg_size);

void
isis_schedule_lsp_pkt_generation(node_t *node, isis_event_type_t event_type);

void
isis_cancel_lsp_pkt_generation_task(node_t *node);

byte *
isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size);

void
isis_print_pkt(void *arg, size_t arg_size);

void
isis_generate_lsp_pkt(void *arg, uint32_t arg_size_unused);

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt) ;

uint32_t *
isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt);

isis_pkt_hdr_flags_t
isis_lsp_pkt_get_flags(isis_lsp_pkt_t *lsp_pkt);

uint32_t
isis_deref_isis_pkt(isis_lsp_pkt_t *lsp_pkt);

void
isis_ref_isis_pkt(isis_lsp_pkt_t *lsp_pkt);

uint16_t
isis_count_tlv_occurrences (byte *tlv_buffer,
                                              uint16_t tlv_buff_size, uint8_t tlv_no) ;

#endif // !__ISIS_PKT__
