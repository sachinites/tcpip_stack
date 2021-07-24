#ifndef __ISIS_PKT__
#define __ISIS_PKT__

#include "isis_events.h"
#include "isis_const.h"

typedef uint16_t isis_pkt_type_t;

typedef struct isis_pkt_ {
    isis_pkt_type_t isis_pkt_type;
    unsigned char *pkt;
    size_t pkt_size;

    /* increase this counter whenever this LSP pkt
       is Queued for transmission out of an interface */
    uint16_t ref_count;
    bool flood_eligibility;
} isis_pkt_t;

static inline uint32_t
isis_deref_isis_pkt(isis_pkt_t *isis_pkt) {
    
    uint32_t rc;

    assert(isis_pkt->pkt && 
           isis_pkt->pkt_size &&
           isis_pkt->ref_count);

    isis_pkt->ref_count--;

    rc = isis_pkt->ref_count;

    if (isis_pkt->ref_count == 0) {

        tcp_ip_free_pkt_buffer(isis_pkt->pkt, isis_pkt->pkt_size);
        free(isis_pkt);
    }    

    return rc;
}

static inline void
isis_ref_isis_pkt(isis_pkt_t *isis_pkt) {

    assert(isis_pkt->pkt && 
           isis_pkt->pkt_size);

    isis_pkt->ref_count++;
}

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size);

void
isis_pkt_recieve(void *arg, size_t arg_size);

void
isis_schedule_lsp_pkt_generation(node_t *node, isis_events_t event_type);

void
isis_cancel_lsp_pkt_generation_task(node_t *node);

char *
isis_get_hello_pkt(interface_t *intf, size_t *hello_pkt_size);

void
isis_print_pkt(void *arg, size_t arg_size);

void
isis_generate_lsp_pkt(void *arg, uint32_t arg_size_unused);

typedef struct isis_pkt_meta_data_ {

    node_t *node;
    interface_t *intf;
    char *pkt;
    size_t pkt_size;
} isis_pkt_meta_data_t;

#define ISIS_PKT_TYPE(pkt_ptr)   (*((isis_pkt_type_t *)pkt_ptr))

#endif // !__ISIS_PKT__