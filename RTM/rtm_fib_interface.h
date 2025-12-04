typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_ rtm_t;

void 
rtm_fib_install (rtm_t *rtm, rtm_route *route, rtm_nh *nh) ;

void 
rtm_fib_uninstall (rtm_t *rtm, rtm_route *route, rtm_nh *nh) ;