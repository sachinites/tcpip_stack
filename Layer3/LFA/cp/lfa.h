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

            bool enable;
            ted_db_t topo;
            char padding[7];

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

void lfa_cleanup (node_t *node, lfa_config_t *lfa_config, uint8_t index);

#endif 
