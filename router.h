#ifndef __ROUTER_GL__
#define __ROUTER_GL__

#include <stdbool.h>

typedef struct node_ node_t;

bool
rtr_eligible_to_remove_rtr_id(node_t *node);

#endif 