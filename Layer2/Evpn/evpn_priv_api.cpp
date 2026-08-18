#include "evpn_priv_api.h"

uint32_t
evpn_bd_install_local_label (rtm_t *rtm, uint32_t mpls_label)
{
    (void)rtm;
    (void)mpls_label;
    return 0;
}

void
evpn_bd_uninstall_local_label (rtm_t *rtm, uint32_t mpls_label)
{
    (void)rtm;
    (void)mpls_label;
}
