#ifndef __TRANSPORT_SVC__
#define __TRANSPORT_SVC__

#include <string>
#include <unordered_set>
#include <stdbool.h>

class Interface;

class TransportService {

    private:
        std::string trans_svc;
        std::unordered_set<int> vlanSet;
        std::unordered_set<int> ifSet;
        int ref_count;  // how many L2 interface it is attached

    public:
        TransportService(std::string& svc_name);
        ~TransportService();
        bool AddVlan(int vlan_id);
        bool RemoveVlan(int vlan_id);
        bool AttachInterface(Interface *intf);
        bool DeAttachInterface(Interface *intf);
        bool InUse();
};

TransportService *
TransportServiceLookUp (std::string& svc_name);

bool
TransportServiceCreate (std::string& svc_name);

bool 
TransportServiceDelete (std::string& svc_name);

#endif 