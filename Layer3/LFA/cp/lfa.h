#ifndef __LFA__
#define __LFA__

#include <stdbool.h>
#include "../../../ted/ted.h"
#include "lfaconst.h"

typedef struct tracer_ tracer_t;


typedef struct lfa_protected_resource_ {

    bool link_protection;
    bool node_protection;
    bool srlg_protection;

    union {

        uint32_t ifindex;
        
        struct {
            uint32_t rtr_id;
            uint8_t pn_no;
        } node;

    } u;

} lfa_protected_resource_t;


typedef struct lfa_config_ {

    union {

        struct {


        } ospf;

        struct {

            bool enable;
            ted_db_t topo;
            void (*lfa_data_cleanup_fn)(ted_node_t *);
            uint32_t lsp_add_update_recvd;
            uint32_t lsp_del_recvd;
            lfa_protected_resource_t prot_db[LFA_MAX_PROTECTION ];
            
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

lfa_protected_resource_t *
lfa_get_available_protected_resource_slot (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION]);



lfa_protected_resource_t *
lfa_get_link_protection_resource (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t ifindex);

lfa_protected_resource_t *
lfa_enable_link_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t ifindex);

void
lfa_disable_link_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t ifindex) ;

lfa_protected_resource_t *
lfa_get_node_protection_resource (
        lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], 
        uint32_t rtr_id, uint8_t pn_no) ;

lfa_protected_resource_t *
lfa_enable_node_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t rtr_id, uint8_t pn_no) ;

void
lfa_disable_node_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t rtr_id, uint8_t pn_no) ;

#endif 
