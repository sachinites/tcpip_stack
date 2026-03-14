#ifndef __ISIS_UTILS__
#define __ISIS_UTILS__

#include <stdbool.h>
#include "../../utils.h"
#include "../../vrf/vrf.h"

typedef struct isis_lan_id_ isis_lan_id_t;
typedef struct isis_lsp_id_ isis_lsp_id_t;
typedef struct isis_system_id_ isis_system_id_t;

/* Get isis_node_info_t from node_t (e.g. in callbacks that receive node) */
#define ISIS_NODE_INFO(node_ptr) (NODE_DEF_VRF(node_ptr)->isis_node_info)

const c_string
isis_lan_id_tostring (isis_lan_id_t *sys_id, const c_string buffer);

int
isis_lan_id_compare (isis_lan_id_t *sys_id1,
                                          isis_lan_id_t *sys_id2);

const c_string
isis_lsp_id_tostring (isis_lsp_id_t *lsp_id, const c_string buffer);

int
isis_lsp_id_compare (isis_lsp_id_t *lsp_id1,
                                    isis_lsp_id_t *lsp_id2);

const c_string
isis_system_id_tostring (isis_system_id_t *sys_id, const c_string buffer);

int
isis_system_id_compare (isis_system_id_t *sys_id1,
                                         isis_system_id_t *sys_id2);

void
isis_show_traceoptions (isis_node_info_t *node_info) ;


#define ISIS_CTX_INTF(intf_ptr) (intf_ptr->vrf->isis_node_info)
#define ISIS_CTX_ADJ(adj_ptr) \
    (adjacency->intf->vrf->isis_node_info)
    
#define ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf_ptr)      \
{                                                                    \
    intf_ptr = NULL;                                                 \
    vrf_t *__vrf = node_info->vrf;                                   \
    if (__vrf->intf_by_name) {                                       \
        for (auto _it = __vrf->intf_by_name->begin();                \
             _it != __vrf->intf_by_name->end(); _it++) {             \
            intf_ptr = _it->second.get();                            \
            if(!intf_ptr) continue;

#define ITERATE_NODE_ISIS_INTERFACES_END                             \
        }                                                            \
    }                                                                \
}


#endif
