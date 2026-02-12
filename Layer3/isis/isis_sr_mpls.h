#ifndef __ISIS_SR_MPLS__
#define __ISIS_SR_MPLS__

typedef struct vrf_ vrf_t;

void isis_enable_sr_mpls(vrf_t *vrf);
void isis_disable_sr_mpls(vrf_t *vrf);

#endif