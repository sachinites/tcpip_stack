#ifndef __CP2DP_INTF_UPDATE__
#define __CP2DP_INTF_UPDATE__

#include <stdint.h>

typedef struct node_ node_t;
class Interface;

void 
cp2dp_interface_create (node_t *node, Interface *intf);

void 
cp2dp_interface_delete (node_t *node, Interface *intf);


#endif 