#ifndef __RTM_SHOW__
#define __RTM_SHOW__

#include <stddef.h>
#include <stdint.h>
#include "rtm_enums.h"
#include "../CLIBuilder/libcli.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rtm_  rtm_t;
typedef struct cmn_prefix_ cmn_prefix_t;
typedef struct dist_mgr_ dist_mgr_t;

/* Format client key as "<vrf>.<proto>.<instance>" */
void rtm_format_redist_target_client_id(
    RTM_PROTO_T proto,
    const char *vrf_str,
    uint32_t instance_no,
    char *buf,
    size_t buflen);

void rtm_show_rib (rtm_t *rtm);
void rtm_show_rib_standard(rtm_t *rtm, char *prefix_filter);
void rtm_show_rib_detail (rtm_t *rtm, const char *prefix_filter);
void rtm_show_nh_proto_info (rtm_t *rtm);
void rtm_show_unresolvable_routes(rtm_t *rtm);
void rtm_show_presentation_db(rtm_t *rtm, char *prefix_filter);
void rtm_show_dist_mgr_database (dist_mgr_t *dist_mgr);
void rtm_show_dist_mgr_policies (dist_mgr_t *dist_mgr);
void rtm_show_dist_mgr_targets (dist_mgr_t *dist_mgr, 
        char *vrf_name, char *proto_name, uint32_t instance_no);

void rtm_show_dist_mgr_target_route (dist_mgr_t *dist_mgr,
        const char *prefix_str);

void rtm_show_tracker_db (rtm_t *rtm);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
int rtm_show_tracker_db_handler (int64_t cmdcode, Stack_t *tlv_stack,
                                 op_mode enable_or_disable);
#endif

#endif // !__RTM_SHOW__

