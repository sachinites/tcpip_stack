#ifndef __FWALL_TRACES__
#define __FWALL_TRACES__

#define FWALL_OBJGRP_UPDATE " OBJ-GRP-UPDATE"
#define FWALL_ACL   " ACL"

#define ACL_TR(node_ptr)    (node_ptr->acl_cptr)

/* Tracer Code Points for ACL/NAT/OBJECT-G */

#define TR_ACL_ADD (1)
#define TR_ACL_DEL (1 << 2)

#endif