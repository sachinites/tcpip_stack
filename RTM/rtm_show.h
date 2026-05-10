#ifndef __RTM_SHOW__
#define __RTM_SHOW__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rtm_  rtm_t;
typedef struct cmn_prefix_ cmn_prefix_t;
typedef struct dist_mgr_ dist_mgr_t;

void rtm_show_rib (rtm_t *rtm);
void rtm_show_rib_standard(rtm_t *rtm, char *prefix_filter);
void rtm_show_rib_detail (rtm_t *rtm, const char *prefix_filter);
void rtm_show_nh_proto_info (rtm_t *rtm);
void rtm_show_proto_info(rtm_t *rtm);
void rtm_show_protocol_subscriptions(rtm_t *rtm);
void rtm_show_unresolvable_routes(rtm_t *rtm);
void rtm_show_presentation_db(rtm_t *rtm, char *prefix_filter);
void rtm_show_dist_mgr_database (dist_mgr_t *dist_mgr);
void rtm_show_dist_mgr_policies (dist_mgr_t *dist_mgr);
void rtm_show_dist_mgr_targets (dist_mgr_t *dist_mgr, 
        char *vrf_name, char *proto_name, uint32_t instance_no);

void rtm_show_dist_mgr_target_route (dist_mgr_t *dist_mgr,
        const char *prefix_str);

#ifdef __cplusplus
}
#endif

#endif // !__RTM_SHOW__

