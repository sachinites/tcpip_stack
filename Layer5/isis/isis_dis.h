#ifndef __ISIS_PN__
#define __ISIS_PN__

#include <stdint.h>
#include "isis_struct.h"

class Interface;
typedef struct node_ node_t;

pn_id_t
isis_reserve_new_pn_id (node_t *node, bool *found);

void
isis_intf_allocate_lan_id (Interface *intf);

void
isis_intf_deallocate_lan_id (Interface *intf);

/* DIS Mgmt Functions */

/* Deletet the Current DIS*/
void  isis_intf_resign_dis (Interface *intf);

/* Trigger DIS Re-election, return LAN-ID of the DIS*/
isis_lan_id_t isis_intf_reelect_dis (Interface *intf);

void
isis_intf_assign_new_dis (Interface *intf, isis_lan_id_t new_dis_id);

bool
isis_am_i_dis (Interface *intf) ;

#endif 