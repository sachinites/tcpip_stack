#ifndef __EVPN_PRIV__
#define __EVPN_PRIV__

#include <stdint.h>
typedef struct rtm_ rtm_t;

uint32_t 
evpn_bd_install_local_label (rtm_t *rtm, uint32_t mpls_label);

void 
evpn_bd_uninstall_local_label (rtm_t *rtm, uint32_t mpls_label);


#endif /* __EVPN_PRIV__ */