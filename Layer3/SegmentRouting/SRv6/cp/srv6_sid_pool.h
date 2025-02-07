
#ifndef  __SRV6_SID_POOL__
#define __SRV6_SID_POOL__

#include <stdint.h>

typedef struct srv6_sid_pools_  srv6_sid_pools_t;
typedef struct ipv6_addr_ ipv6_addr_t;

typedef enum srv6_sid_client_{

    srv6_sid_client_isis = 1,
    srv6_sid_client_srv6 = 2,
    srv6_sid_client_bgp = 4,
    srv6_sid_client_ospfv3 = 8,
    srv6_sid_client_max = 16

} srv6_sid_client_t;

typedef enum pool_error_codes_ {

    SRv6_POOL_OK,
    SRv6_POOL_ERR_DUP_LOCATOR,
    SRv6_POOL_ERR_LOCATOR_NOT_FOUND,
    SRv6_POOL_ERR_LOCATOR_NAME_CONFLICT,
    SRv6_POOL_ERR_LOCATOR_LPM_CONFLICT,
    SRv6_POOL_ERR_LOCATOR_IN_USE,
    SRv6_POOL_ERR_LOCATOR_NO_DYN_SID_AVAIL,
    SRv6_POOL_ERR_LOCATOR_NO_STATIC_SID_AVAIL,
    SRv6_POOL_ERR_LOCATOR_INVALID,
    SRv6_POOL_ERR_SID_NOT_FOUND,
    SRv6_POOL_ERR_INVALID_SID_REQUEST,
    SRv6_POOL_ERR_SID_IN_USE

} pool_error_codes_t;

void 
srv6_pool_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) ;

/* Used when user configure locator */
pool_error_codes_t
srv6_pool_create_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            ipv6_addr_t *loc_prefix, 
                            uint8_t prefix_len, 
                            char *loc_name,
                            char* err_msg_out) ;

/* Used when user unconfigure locator. Should be done when all pfx-sids and adj-sids
    is already related under this locator */
pool_error_codes_t
srv6_pool_delete_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            char* err_msg_out) ;

pool_error_codes_t
srv6_pool_client_borrow_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            srv6_sid_client_t client,
                            char *err_msg_out);

pool_error_codes_t
srv6_pool_client_unborrow_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            srv6_sid_client_t client,
                            char *err_msg_out);

bool 
srv6_pool_is_locator_being_used_by_any_client (
                                    srv6_sid_pools_t *srv6_sid_pools,
                                    char *loc_name);
 
/* Used by clients to claim a dynamic sid under locator from the pool. 
    ifindex and gw_addr are required if client request adj sid, 
    else pass 0 and NULL if pfx sid is requested
*/
pool_error_codes_t
srv6_pool_alloc_dynamic_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name ,
                                    srv6_sid_client_t sid_client,
                                    uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out);

/* Used by clients to claim a static sid under locator from the pool. 
    ifindex and gw_addr are required if client request adj sid, 
    else pass 0 and NULL if pfx sid is requested
*/
pool_error_codes_t
srv6_pool_alloc_static_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    ipv6_addr_t *sid,
                                    srv6_sid_client_t sid_client,
                                    uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    char *err_msg_out);

/* Used by the clients to release the given sid. It could be pfxsid or adjsid */
pool_error_codes_t
srv6_release_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    ipv6_addr_t *sid,
                                    char *err_msg_out);

/* Used by clients after RED-SWO when adj comes up, claim the same adj sid
    as before red-swo for this adjacency. This fn do not change the  pool state */
pool_error_codes_t
srv6_pool_lookup_adj_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name,
                                   uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    srv6_sid_client_t sid_client,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out);

void 
srv6_show_locator (srv6_sid_pools_t *srv6_sid_pools, char *loc_name) ;


#endif // ! __SRV6_SID_POOL__