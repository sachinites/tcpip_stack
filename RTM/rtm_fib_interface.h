#ifndef __RTM_FIB_INTF__
#define __RTM_FIB_INTF__

typedef struct rtm_ rtm_t;
typedef struct rtm_presentation_data_ rtm_presentation_data_t;

void 
rtm_fib_update(rtm_t *rtm, rtm_presentation_data_t *presentation_data);

void 
rtm_l2_fib_update(rtm_t *rtm, rtm_presentation_data_t *presentation_data);

#endif /* __RTM_FIB_INTF__ */