#ifndef __ISIS_LFA__H__
#define __ISIS_LFA__H__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct lfa_  lfa_t;

void 
lfa_isis_init (node_t *node, lfa_t *lfa, uint8_t level) ;

void 
lfa_isis_deinit (node_t *node, lfa_t *lfa, uint8_t level) ;

void 
 lfa_isis_cleanup(node_t *node, lfa_config_t *lfa_config);

#endif 