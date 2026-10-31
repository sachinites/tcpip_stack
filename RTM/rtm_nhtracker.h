#ifndef __RTM_NHTRACKER_H__
#define __RTM_NHTRACKER_H__

#include <stdint.h>
#include <stdbool.h>
#include "rtm_enums.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "../libs/common/cmn_prefix.h"
#include "../libs/Tree/libtree.h"
#include "../libs/gluethread/glthread.h"
typedef struct rtm_ rtm_t;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;
typedef struct rtm_presentation_data_ rtm_presentation_data_t;

typedef struct rtm_tracker_client_id_ {

    RTM_PROTO_T proto;
    uint16_t vrf_id;
    uint16_t instance_no;

} rtm_tracker_client_id_t;

typedef struct rtm_tracker_client_data_ {

    cmn_prefix_t tracked_prefix; // tracked prefix
    cmn_prefix_t route;
    uint32_t dnhidx;
    bool add;

} rtm_tracker_client_data_t;

typedef void (*rtm_tracker_client_callback_t) (cmn_prefix_t *prefix, rtm_tracker_client_id_t *client_id, rtm_tracker_client_data_t *client_data);

uintptr_t
rtm_tracker_register_client (rtm_t *rtm, rtm_tracker_client_id_t *client_id, rtm_tracker_client_callback_t callback);

void
rtm_tracker_unregister_client (rtm_t *rtm, uintptr_t registration_id);

void
rtm_track (rtm_t *rtm, cmn_prefix_t *prefix_to_track, uintptr_t registration_id);

void
rtm_untrack (rtm_t *rtm, cmn_prefix_t *prefix_to_track, uintptr_t registration_id);

uintptr_t
rtm_tracker_reg_id_from_nh_proto (rtm_t *rtm, rtm_nh_proto_t *nh_proto);

typedef struct rtm_tracker_client_db_ {

    uintptr_t reg_id;                  //allocated reg id
    rtm_tracker_client_id_t client_id; //key
    rtm_tracker_client_callback_t callback;
    avltree_node_t avlnode_glue_client_id;
    avltree_node_t avlnode_glue_reg_id;

} rtm_tracker_client_db_t;

typedef struct rtm_tracker_ {

    /* Tree of rtm_tracker_client_db_t keyed by rtm_tracker_client_id_t */
    avltree_t client_db_by_client_id; 
    /* Tree of rtm_tracker_client_db_t keyed by uintptr_t reg_id */
    avltree_t client_db_by_reg_id; 

} rtm_tracker_t;

void 
rtm_tracker_init (rtm_tracker_t **rtm_tracker);

void 
rtm_tracker_deinit (rtm_tracker_t **rtm_tracker);

void 
show_rtm_tracker_client_db (rtm_tracker_client_db_t *client_db);

void rtm_publish_to_nhtracker (rtm_t *rtm, 
                               rtm_presentation_data_t *presentation_data);

#ifdef __cplusplus
}
#endif

#endif 