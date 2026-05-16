#ifndef __IFM__
#define __IFM__

#pragma pack(push, 8)

typedef struct node_ node_t;

typedef struct ifm_ {

    node_t *node;

} ifm_t;

#pragma pack(pop)

void 
ifm_init(node_t *node);

#endif 