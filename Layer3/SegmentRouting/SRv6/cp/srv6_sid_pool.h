
#ifndef  __SRV6_SID_POOL__
#define __SRV6_SID_POOL__

#include <stdint.h>

typedef struct srv6_sid_pools_  srv6_sid_pools_t;
typedef struct ipv6_addr_ ipv6_addr_t;

typedef enum srv6_sid_client_{

    srv6_sid_client_isis,
    srv6_sid_client_srv6,
    srv6_sid_client_bgp,
    srv6_sid_client_ospfv3,
    srv6_sid_client_max

} srv6_sid_client_t;

typedef enum pool_error_codes_ {

    SRv6_POOL_OK,
    SRv6_POOL_ERR_DUP_LOCATOR,
    SRv6_POOL_ERR_LOCATOR_NOT_FOUND,
    SRv6_POOL_ERR_LOCATOR_NAME_CONFLICT,
    SRv6_POOL_ERR_LOCATOR_LPM_CONFLICT,
    SRv6_POOL_ERR_LOCATOR_IN_USE

} pool_error_codes_t;

void 
srv6_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) ;

pool_error_codes_t
srv6_create_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            ipv6_addr_t *loc_prefix, 
                            uint8_t prefix_len, 
                            char *loc_name,
                            char* err_msg_out) ;

pool_error_codes_t
srv6_delete_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            char* err_msg_out) ;

pool_error_codes_t
srv6_alloc_available_pfx_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name ,
                                    srv6_sid_client_t sid_client,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out) ;

pool_error_codes_t
srv6_release_pfx_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    ipv6_addr_t *sid,
                                    char *err_msg_out);

pool_error_codes_t
srv6_reserve_pfx_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    ipv6_addr_t *sid,
                                    char *err_msg_out);

#endif // ! __SRV6_SID_POOL__