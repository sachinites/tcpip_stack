#ifndef __ISIS_PN__
#define __ISIS_PN__

#include <stdint.h>

typedef uint8_t pn_id_t;

typedef struct node_ node_t;

pn_id_t
isis_reserve_new_pn_id (node_t *node, bool *found);

#endif 