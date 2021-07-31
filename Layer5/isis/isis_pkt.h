#ifndef __ISIS_PKT__
#define __ISIS_PKT__

#include "isis_events.h"
#include "isis_const.h"

typedef uint16_t isis_pkt_type_t;

typedef struct isis_pkt_ {

    isis_pkt_type_t isis_pkt_type;
    byte *pkt;
    size_t pkt_size;
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
} isis_pkt_t;

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size);

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

#define ISIS_PKT_TYPE(pkt_ptr)   (*((isis_pkt_type_t *)pkt_ptr))

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_pkt_t *lsp_pkt) ;

uint32_t *
isis_get_lsp_pkt_seq_no(isis_pkt_t *lsp_pkt);

uint32_t
isis_deref_isis_pkt(isis_pkt_t *lsp_pkt);

void
isis_ref_isis_pkt(isis_pkt_t *lsp_pkt);

#endif // !__ISIS_PKT__
