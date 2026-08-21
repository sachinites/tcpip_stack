/*
 * =====================================================================================
 *
 *       Filename:  layer2.c
 *
 *    Description:  This file implements all the Data link Layer functionality
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 05:15:51  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <string>
#include "../router_init.h"
#include "layer2.h"
#include "../tcp_ip_trace.h"
#include "../libs/libtimer/WheelTimer.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../Interface/InterfaceUApi.h"
#include "transport_svc.h"
#include "../libs/Tracer/tracer.h"
#include "../dpal/cp2dp.h"
#include "../datapath/enums/l2_enums.h"
#include "../tcpconst.h"
#include "../cp_limits.h"

/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node,
                                      const char *intf_name, 
                                      IntfL2Mode intf_l2_mode){

    Interface *interface = node_interface_lookup_by_name(node, intf_name);
    assert(interface);
    interface->SetL2Mode(intf_l2_mode);
}

void
node_set_intf_switchport(node_t *node,
                                         const char *intf_name) {

    Interface *interface = node_interface_lookup_by_name(node, intf_name);
    assert(interface);
    interface->SetSwitchport(true);
}

void
node_set_intf_vlan_membership(node_t *node, 
                                                     const char *intf_name, 
                                                     vlan_id_t vlan_id,
                                                     bool Trunk){

    Interface *interface = node_interface_lookup_by_name(node, intf_name);
    assert(interface);

    if (interface->GetL2Mode() == LAN_ACCESS_MODE &&
            Trunk == true) {
         cprintf ("Error : Interface %s already in Access mode, cannot be trunked\n", intf_name);
        return;
    }

    if (interface->GetL2Mode() == LAN_TRUNK_MODE &&
            Trunk == false) {
         cprintf ("Error : Interface %s already in Trunk mode, cannot be accessed\n", intf_name);
        return;
    }

    if (interface->GetSwitchport() == false) {
         cprintf ("Error : Interface %s is not switchport enabled\n", intf_name);
        return;
    }

    if (!CP_VLAN_ID_VALID(vlan_id)) {
        cprintf("Error : Invalid VLAN ID %u (1-%u)\n",
                vlan_id, MAX_VLAN_SUPPORTED - 1);
        return;
    }

    /* Create VLAN also*/
    VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp(node, vlan_id);
    VlanInterfaceP vlan_intfP;

    if(!vlan_intf) {

        vlan_intfP = std::make_shared<VlanInterface>(vlan_id);
        vlan_intfP->SetSharedPtr(vlan_intfP);
        vlan_intf = vlan_intfP.get();
        vlan_intf->att_node = node;
        vlan_intf->ifindex = interface_get_new_ifindex(node);
        
        if (!node->vlan_intf_db) {
            node->vlan_intf_db = new std::unordered_map<uint16_t, VlanInterfaceP>;
        }
        node->vlan_intf_db->insert(std::make_pair(vlan_id, vlan_intfP));
        vlan_intf->vrf = NODE_DEF_VRF(node);
        
        cp2dp_interface_create(node, vlan_intf);
        cp2dp_vrf_add_interface (node, vlan_intf->vrf->vrf_id,  vlan_intf->ifindex);
        cp2dp_send_intf_admin_status_update(node, vlan_intf->ifindex, false);
        cp2dp_mac_table_entry_add (node, (uint8_t *)BROADCAST_MAC, 
                        vlan_id, 
                        VLAN_FLOOD_INDEX, MAC_STATIC, true, 0);
    }

    if (Trunk) {
        std::string def_tsp_name(std::string(reinterpret_cast<const char *>(DEFAULT_TSP)));
        TransportService *tsp = TransportServiceCreate(node, def_tsp_name);
        tsp->AddVlan(vlan_id);
        tsp->AttachInterface(interface);
    }
    else {
        interface->IntfConfigVlan (vlan_id, true);
    }

}





