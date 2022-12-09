#ifndef __INTERFACE_UAPI__
#define __INTERFACE_UAPI__

#include "Interface.h"

/* Access Macros */
static inline void 
IntfSetMacAddress (Interface *Intf, mac_addr_t *mac_addr) {

    PhysicalInterface *phyIntf = dynamic_cast<PhysicalInterface *>(Intf);
    phyIntf->SetMacAddr(mac_addr);    
}

static inline void
IntfSetIpAddressMask (Interface *Intf, uint32_t ip_addr, uint8_t mask) {

    PhysicalInterface *phyIntf = dynamic_cast<PhysicalInterface *>(Intf);
    phyIntf->InterfaceSetIpAddressMask(ip_addr, mask);
}

#endif 