#ifndef __RTM_SHOW__
#define __RTM_SHOW

typedef struct rtm_  rtm_t;

void rtm_show_rib (rtm_t *rtm);
void rtm_show_rib_detail (rtm_t *rtm);
void rtm_show_nh_proto_info (rtm_t *rtm);
void rtm_show_fib(rtm_t *rtm);
void rtm_show_proto_info(rtm_t *rtm);
void rtm_show_unresolvable_lnhs(rtm_t *rtm);

#endif // !__RTM_SHOW__

