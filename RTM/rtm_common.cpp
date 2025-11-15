#ifndef __RTM_COMMON__
#define __RTM_COMMON__


#include "rtm_common.h"

bool rtm_prefix_is_null (rtm_prefix_t *prefix) {

    if  (prefix->prefix_len == 0) return true;
}

#endif 