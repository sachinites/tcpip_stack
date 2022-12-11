#ifndef __PKT_TRACER__
#define __PKT_TRACER__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "pkt_tracer_enum.h"
#include "../gluethread/glthread.h"

#define PKT_TRACER_PHASE_CONFIG_N 4
#define PKT_TRACER_PHASE_CONFIG_LEN   128
#define PKT_TRACER_PHASE_INFO_LEN   256

class Interface;

typedef struct pkt_tracer_phase_ {

    uint8_t phase_no;
    pkt_tracer_type_t type;
    pkt_tracer_subtype_t subtype;
    pkt_tracer_result_t res;
    uint8_t config_no;
    unsigned char config[PKT_TRACER_PHASE_CONFIG_N][PKT_TRACER_PHASE_CONFIG_LEN];
    unsigned char info[PKT_TRACER_PHASE_INFO_LEN];
    glthread_t glue;
} pkt_tracer_phase_t;
GLTHREAD_TO_STRUCT(glthread_glue_to_pkt_tracer, pkt_tracer_phase_t, glue);

typedef struct pkt_tracer_ {

    uint8_t phase_no;
    glthread_t head;
    bool enable;
    Interface *ingress_intf;
    Interface *egress_intf;
    time_t start_time;
    time_t end_time;
} pkt_tracer_t;

void
pkt_tracer_init (pkt_tracer_t **pkt_tracer);

void
pkt_tracer_logging_enable (pkt_tracer_t *pkt_tracer, bool enable);

void
pkt_tracer_add_phase (pkt_tracer_t *pkt_tracer,
                                     pkt_tracer_type_t type,
                                     pkt_tracer_subtype_t subtype,
                                     pkt_tracer_result_t res,
                                     uint8_t n_configs,
                                     const unsigned char config[][128],
                                     const unsigned char *info);

uint32_t
pkt_tracer_print_phase (char *out_buff, 
                                       uint16_t fd,
                                       pkt_tracer_phase_t *phase);

uint32_t
pkt_tracer_print (pkt_tracer_t*pkt_tracer, char *out_buff,  uint16_t fd);

void
pkt_tracer_destroy_internal (pkt_tracer_t *pkt_tracer);

#endif
