#ifndef __RTM_API__
#define __RTM_API__

#include <stdbool.h>
#include "rtm_common.h"

typedef struct rtm_ rtm_t;

rtm_t *
rtm_init (uint8_t vrf, RTM_AFI_T afi);

#endif 