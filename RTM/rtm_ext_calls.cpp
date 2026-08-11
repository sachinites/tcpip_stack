#include <stdint.h>

extern char *
cp_get_intf_name_from_ifindex(void *ctx, uint32_t ifindex, char *buffer);

char * (*rtm_get_intf_name) (void *ctx, uint32_t ifindex, char *buffer) = 
    cp_get_intf_name_from_ifindex;


extern char *
cp_get_vrf_name_from_vrf_id(void *ctx, uint8_t vrf_id);

char * (*rtm_get_vrf_name) (void *ctx, uint8_t vrf_id) = 
    cp_get_vrf_name_from_vrf_id;
