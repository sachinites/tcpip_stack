#ifndef __TRANSPORT_SVC__
#define __TRANSPORT_SVC__

#include <string>
#include <unordered_set>
#include <stdbool.h>
#include <vector>
#include "../BitOp/bitmap.h"

#define DEFAULT_TSP "DEFAULT_TSP"


class Interface;
typedef struct node_ node_t;

class TransportService {

    private:

    public:
        std::string trans_svc;
        std::unordered_set<int> vlanSet;
        bitmap_t vlan_bitmap;
        std::unordered_set<int> ifSet;
        int ref_count;  // how many L2 interface it is attached         
        TransportService(std::string& svc_name);
        ~TransportService();
        bool AddVlan(int vlan_id);
        bool RemoveVlan(int vlan_id);
        bool AttachInterface(Interface *intf);
        bool DeAttachInterface(Interface *intf);
        bool InUse();
};

TransportService *
TransportServiceLookUp (std::unordered_map<std::string , TransportService *> *TransPortSvcDB, std::string& svc_name);

TransportService *
TransportServiceCreate (node_t *node, std::string& svc_name);

bool 
TransportServiceDelete (std::unordered_map<std::string , TransportService *> *TransPortSvcDB, 
std::string& svc_name);

/* Macro to iterate over all vlan member ports */
#define ITERATE_VLAN_MEMBER_PORTS_TRUNK_BEGIN(vlan_intf_ptr, member_intf) \
do { \
    node_t *_node = vlan_intf_ptr->att_node;    \
    VlanInterface *_vlan_intf = dynamic_cast<VlanInterface *>(vlan_intf_ptr);    \
    std::unordered_map<std::string , TransportService *> *_TransPortSvcDB = \
        _node->TransPortSvcDB;   \
    if (!_TransPortSvcDB) break; \
    for (auto _it1 = _TransPortSvcDB->begin(); _it1 != _TransPortSvcDB->end(); ++_it1) { \
        TransportService *_tsp = _it1->second; \
        if (_tsp->vlanSet.find(_vlan_intf->vlan_id) == _tsp->vlanSet.end()) continue; \
        for (auto _it2 = _tsp->ifSet.begin(); _it2 != _tsp->ifSet.end(); ++_it2) { \
                member_intf = node_get_intf_by_ifindex(_node, *_it2);

#define ITERATE_VLAN_MEMBER_PORTS_TRUNK_END }}}while(0);

#define ITERATE_VLAN_MEMBER_PORTS_ACCESS_BEGIN(vlan_intf_ptr, member_intf) \
{   \
    VlanInterface *_vlan_intf = dynamic_cast<VlanInterface *>(vlan_intf_ptr);    \
    for (auto _it = _vlan_intf->access_member_intf_lst.begin(); _it != _vlan_intf->access_member_intf_lst.end(); ++_it) { \
        member_intf = (*_it).get(); \
        assert(member_intf->GetL2Mode() == LAN_ACCESS_MODE);


#define ITERATE_VLAN_MEMBER_PORTS_ACCESS_END  }}

#endif 