#include "../../../../tcp_public.h"
#include "srv6_rtr.h"
#include "srv6_struct.h"

void 
srv6_mem_init () {

    MM_REG_STRUCT(0, srv6_locator_t); 
    MM_REG_STRUCT(0, srv6_pfxsid_t);
    MM_REG_STRUCT(0, srv6_adjsid_t); 
    MM_REG_STRUCT(0, srv6_node_info_t);
}