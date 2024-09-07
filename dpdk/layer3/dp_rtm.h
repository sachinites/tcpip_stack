#ifndef __NP_RT_TABLE__
#define __NP_RT_TABLE__

typedef struct dp_msg_ dp_msg_t;
typedef struct node_ node_t;

#include <stdint.h>

void 
np_rt_table_process_msg(node_t *node, dp_msg_t *dp_msg);

#endif 