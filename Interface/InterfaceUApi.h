#ifndef __INTERFACE_UAPI__
#define __INTERFACE_UAPI__

#include "InterfacEnums.h"
#include "Interface.h"
#include "../utils.h"
#include "../CLIBuilder/libcli.h"

typedef struct node_ node_t;

void
interface_set_ip_addr (node_t *node, Interface *intf, 
                                    c_string intf_ip_addr, uint8_t mask) ;

void
interface_unset_ip_addr (node_t *node, Interface *intf);                                  

void interface_loopback_create (node_t *node, uint8_t lono);
void interface_loopback_delete (node_t *node, uint8_t lono) ;

#define IF_MAC(intf)    (intf->GetMacAddr()->mac)

static inline uint32_t 
IF_IP(Interface *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    if (!intf->IsIpConfigured()) assert(0);
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    return ip_addr;
}

static inline uint32_t 
IF_MASK(Interface *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    if (!intf->IsIpConfigured()) assert(0);
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    return mask;
}

void
display_node_interfaces(param_t *param, Stack_t *tlv_stack);

#endif 
