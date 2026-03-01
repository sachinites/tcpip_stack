
#include "dp_utils.h"
#include "Vrfs/dp_vrf.h"
#include "FIB/fib_nh.h"

/*Returns the local interface of the node which is configured 
 * with subnet in which 'ip_addr' lies
 * */
dp_intf_t *
dp_intf_get_matching_subnet_interface(dp_ctx_t *dp_ctx, 
                                      dp_vrf_t *vrf, 
                                      uint32_t ip_addr){

    uint8_t mask;
    dp_intf_t *intf;
    cmn_prefix_t prefix;
    
    cmn_prefix_initialize_v4(&prefix, ip_addr, 32);

    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        return NULL;
    }   

    if (nh->fwd_info->fwd_flags & 
        (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_LOCAL)) {
        
        return nh->fwd_info->oif;
    }

    return NULL;
}
