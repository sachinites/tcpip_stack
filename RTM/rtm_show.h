#ifndef __RTM_SHOW__
#define __RTM_SHOW__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rtm_  rtm_t;
typedef struct rtm_prefix_ rtm_prefix_t;

void rtm_show_rib (rtm_t *rtm);
void rtm_show_rib_detail (rtm_t *rtm, const char *prefix_filter);
void rtm_show_nh_proto_info (rtm_t *rtm);
void rtm_show_proto_info(rtm_t *rtm);
void rtm_show_protocol_subscriptions(rtm_t *rtm);
void rtm_show_unresolvable_routes(rtm_t *rtm);

#ifdef __cplusplus
}
#endif

#endif // !__RTM_SHOW__

