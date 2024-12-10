
#include <stdio.h>
#include <memory>
#include <unistd.h>
#include "Interface/Interface.h"
graph_t *topo = NULL;

int 
main (int argc, char **argv) {

    GRETunnelInterfaceP gre_shared_ptr  = std::make_shared<GRETunnelInterface>(1);
    gre_shared_ptr->SetSharedPtr(gre_shared_ptr);
    printf ("shared_ptr count = %lu\n", gre_shared_ptr.use_count());

    return 0;
}