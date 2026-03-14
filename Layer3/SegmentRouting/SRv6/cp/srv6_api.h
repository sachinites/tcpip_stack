#ifndef __SRV6_API__
#define __SRV6_API__

#include <stdbool.h>
typedef struct node_ node_t;
typedef struct vrf_ vrf_t;


#define SRV6_NODE_INFO(vrf_ptr) \
    (vrf_ptr->srv6_node_info)

bool 
srv6_is_enable (vrf_t *vrf);

void 
srv6_init (vrf_t *vrf);

void 
srv6_de_init (vrf_t *vrf);

uint32_t 
srv6_delete_all_pfx_sids (vrf_t *vrf) ;

uint32_t 
srv6_delete_all_adj_sids (vrf_t *vrf) ;

#endif 