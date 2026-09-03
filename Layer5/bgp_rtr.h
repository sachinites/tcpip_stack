#ifndef __BGP_RTR__
#define __BGP_RTR__

typedef struct tracer_ tracer_t;
typedef struct bgp_inst_ bgp_inst_t;

#include "bgp_config.h"


#pragma pack(push, 8)

typedef struct bgp_inst_ {

    /* Holds all config*/
    bgp_node_config_t bgp_config;

    /* GoBGP gRPC Client*/
    void *bgp_grpc_client;

    /* Tracefile */
    tracer_t *tr;

    /* Task to process recvd route updated from GoBGP */
    task_t *recvd_route_processing_task;
    Fglthread_t pending_routes_list;

} bgp_inst_t;

#pragma pack(pop)

bgp_inst_t *bgp_init(node_t *node);
void bgp_deinit (bgp_inst_t *bgp_inst);
void bgp_inst_check_and_delete (bgp_inst_t *bgp_inst);

bgp_inst_t *bgp_get_instance(node_t *node);

#define BGP_INST(node_ptr) ((def_vrf_t *)NODE_DEF_VRF(node_ptr))->bgp_inst
#endif /* __BGP_RTR__ */