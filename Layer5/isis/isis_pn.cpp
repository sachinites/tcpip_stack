#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_pn.h"
#include "isis_rtr.h"

pn_id_t
isis_reserve_new_pn_id (node_t *node, bool *found) {

    pn_id_t pn_id;
    *found = false;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    for (pn_id = 0; pn_id < ISIS_MAX_PN_SUPPORTED; pn_id++) {

        if (node_info->advt_db[pn_id] ) continue;
        *found = true;
        return pn_id;
    }
    
    return 0;
}