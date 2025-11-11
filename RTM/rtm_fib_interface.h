typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_ rtm_nh;

void 
rtm_fib_install (rtm_route *route, rtm_nh *nh) ;

void 
rtm_fib_uninstall (rtm_route *route, rtm_nh *nh) ;