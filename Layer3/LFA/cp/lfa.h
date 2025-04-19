#ifndef __LFA__
#define __LFA__

#include <stdbool.h>
#include "../../../ted/ted.h"
#include "lfaconst.h"

typedef struct tracer_ tracer_t;

typedef struct lfa_config_ {

    union {

        struct {


        } ospf;

        struct {

            ted_db_t topo;
            void (*lfa_data_cleanup_fn)(ted_node_t *);
            uint32_t lsp_add_update_recvd;
            uint32_t lsp_del_recvd;

        } isis;

        struct {


        } ldp;


        struct {


        }rsvp;

    } u;

} lfa_config_t;


typedef struct lfa_ {

    bool enable;
    char padding[7];
    
    tracer_t *tr;
    lfa_config_t lfa_config[MAX_LFA_INDEX];

} lfa_t;


void lfa_init (node_t *node, lfa_t **lfa);

void lfa_deinit (node_t *node, lfa_t **lfa) ;

void lfa_cleanup (node_t *node, uint8_t index);

bool lfa_is_enabled (node_t *node);

lfa_config_t *
lfa_get_config (node_t *node, uint8_t prot_index);

#endif 
