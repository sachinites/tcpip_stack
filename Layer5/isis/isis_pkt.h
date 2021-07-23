#ifndef __ISIS_PKT__
#define __ISIS_PKT__

#include "isis_events.h"

typedef uint16_t isis_pkt_type_t;

typedef struct isis_pkt_ {
    isis_pkt_type_t isis_pkt_type;
    unsigned char *pkt;
    size_t pkt_size;
} isis_pkt_t;

static inline void
isis_free_isis_pkt(isis_pkt_t *isis_pkt) {
    
    if (!isis_pkt->pkt || !isis_pkt->pkt_size) return;

    tcp_ip_free_pkt_buffer(isis_pkt->pkt, isis_pkt->pkt_size);
    isis_pkt->pkt = 0;
    isis_pkt->pkt_size = 0;
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
isis_print_hello_pkt(void *arg, size_t arg_size);

typedef struct isis_pkt_meta_data_ {

    node_t *node;
    interface_t *intf;
    char *pkt;
    size_t pkt_size;
} isis_pkt_meta_data_t;

#define ISIS_PKT_TYPE(pkt_ptr)   (*((isis_pkt_type_t *)pkt_ptr))

#endif // !__ISIS_PKT__