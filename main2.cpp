
#include <stdio.h>
#include <memory>
#include <unistd.h>
#include <iostream>
#include "Interface/Interface.h"

using InterfaceP = std::shared_ptr<Interface>;

graph_t *topo = NULL;

int 
main (int argc, char **argv) {

    InterfaceP interface = std::make_shared<PhysicalInterface>("eth0", INTF_TYPE_PHY, nullptr);
       printf("%s   ::  PktTx : %u, PktRx : %u, Pkt Egress Dropped : %u\n",
            interface->if_name.c_str(), interface->pkt_sent,
            interface->pkt_recv,
            interface->xmit_pkt_dropped);
        fflush(stdout);
        
        return 0;
}