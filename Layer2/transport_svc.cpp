#include <assert.h>
#include <stdint.h>
#include <unordered_map>
#include "transport_svc.h"
#include "../Interface/Interface.h"
#include "../CLIBuilder/libcli.h"
#include "../cmdcodes.h"

static std::unordered_map<std::string , TransportService *> TransPortSvcDB;

TransportService::TransportService(std::string& svc_name) {

    this->trans_svc = svc_name;
}

TransportService::~TransportService() {

    /* Remove all Vlans from vlanSet if any*/
    this->vlanSet.clear();
    assert (this->ifSet.empty());
    assert (!this->ref_count);
}

bool
TransportService::AddVlan(int vlan_id) {

    auto it = this->vlanSet.find( vlan_id );

    if (it != this->vlanSet.end()) {
        return false;
    }

    this->vlanSet.insert ( vlan_id );
    return true;
}

bool
TransportService::RemoveVlan(int vlan_id) {

    auto it = this->vlanSet.find( vlan_id );

    if (it == this->vlanSet.end()) {
        return false;
    }

    this->vlanSet.erase ( vlan_id );
    return true;
}

bool 
TransportService::AttachInterface(Interface *intf) {

    IntfL2Mode l2_mode;

    if  (!intf->GetSwitchport() ) {
        cprintf ("Error : Interface %s is not L2 interface\n", intf->if_name.c_str());
        return false;
    }

    l2_mode = intf->GetL2Mode();

    if ( l2_mode == LAN_ACCESS_MODE ) {

        cprintf ("Error : Interface %s is not Operating in Trunk Mode\n", intf->if_name.c_str());
        return false;
    }

    uint32_t ifindex = intf->ifindex;
    auto it = this->ifSet.find ( ifindex );

    if ( it != this->ifSet.end() ) {
        return true;
    }

    this->ifSet.insert (ifindex);
    this->ref_count++;
    return true;
}

bool 
TransportService::DeAttachInterface (Interface *intf) {

    PhysicalInterface *phy_intf = dynamic_cast<PhysicalInterface *> (intf);
    assert (phy_intf);
    TransportService *trans_svc = phy_intf->trans_svc;
    if (!trans_svc) return true;
    if (this != trans_svc) return true;
    trans_svc->ifSet.erase (intf->ifindex);
    phy_intf->trans_svc = NULL;
    trans_svc->ref_count--;
    return true;
}


bool 
TransportService::InUse() {

    return !(this->ref_count == 0);
}




/* Global Functions */

TransportService *
TransportServiceLookUp (std::string& svc_name) {

    auto it = TransPortSvcDB.find ( svc_name );

    if (it == TransPortSvcDB.end()) {
        return NULL;
    }

    return it->second;
}

bool
TransportServiceCreate (std::string& svc_name) {

    if (TransportServiceLookUp (svc_name)) return true;

    TransportService *trans_svc = new TransportService (svc_name);

    TransPortSvcDB.insert (std::make_pair (svc_name, trans_svc));

    return true;
}

bool 
TransportServiceDelete (std::string& svc_name) {

    auto it = TransPortSvcDB.find ( svc_name );

    if (it == TransPortSvcDB.end()) {
        return true;
    }     

    TransportService *trans_svc = it->second;

    /* Transport Svc must not be applied to any interface*/
    if (trans_svc->InUse()) {
        cprintf ("Error : Transport Svc in Use, Cannot delete\n");
        return false;
    }

    delete trans_svc;   
    TransPortSvcDB.erase(it);
    return true;
}

int
transport_svc_config_handler (int cmdcode, 
                                                  Stack_t *tlv_stack,
                                                  op_mode enable_or_disable) {

    return 0;
}


#if 0 

config node <node-name> transport-service-profile <transport-service-name>
config node <node-name> transport-service-profile <transport-service-name> vlan add <vlan-id>
config node <node-name> transport-service-profile <transport-service-name> vlan del <vlan-id>
config node <node-name> transport-service-profile <transport-service-name> vlan del all
config node <node-name> interface ethernet <if-name>  transport-service-profile <transport-service-name>

#endif 

int
config_node_build_transport_svc_cli_tree (param_t *param) {

    {
        /* transport-service-profile <ransport-service-profile-name>*/
        static param_t transport_svc;
        init_param(&transport_svc, CMD, "transport-service-profile", 0, 0, INVALID, 0, "transport-service-profile");
        libcli_register_param(param, &transport_svc);
        {
            static param_t transport_svc_name;
            init_param(&transport_svc_name,
                                LEAF,
                                0, transport_svc_config_handler, 0, STRING, "transport-service-profile", "Transport Svc Profile Name");
            libcli_register_param(&transport_svc, &transport_svc_name);
            libcli_set_param_cmd_code(&transport_svc_name, CMDCODE_CONFIG_NODE_TRANSPORT_SVC);
            {
                /* vlan add <vlan-id>*/
                static param_t vlan;
                init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "vlan");
                libcli_register_param(&transport_svc_name, &vlan);
                {
                    static param_t add;
                    init_param(&add, CMD, "add", 0, 0, INVALID, 0, "add vlan to Transport Service profile");
                    libcli_register_param(&vlan, &add);
                    {
                        static param_t vlan_id;
                        init_param(&vlan_id, LEAF, 0, transport_svc_config_handler, 0, INT, "vlan-id", "vlan id");
                        libcli_register_param(&add, &vlan_id);
                        libcli_set_param_cmd_code(&vlan_id, CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_ADD);
                        libcli_set_tail_config_batch_processing(&vlan_id);
                    }
                }
            }


            {
                /* vlan del <vlan-id>*/
                static param_t vlan;
                init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "vlan");
                libcli_register_param(&transport_svc_name, &vlan);
                {
                    static param_t del;
                    init_param(&del, CMD, "del", 0, 0, INVALID, 0, "del vlan from Transport Service profile");
                    libcli_register_param(&vlan, &del);
                    {
                        static param_t vlan_id;
                        init_param(&vlan_id, LEAF, 0, transport_svc_config_handler, 0, INT, "vlan-id", "vlan id");
                        libcli_register_param(&del, &vlan_id);
                        libcli_set_param_cmd_code(&vlan_id, CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_DEL);
                        libcli_set_tail_config_batch_processing(&vlan_id);
                    }
                }
            }


            {
                /* vlan del all*/
                static param_t vlan;
                init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "vlan");
                libcli_register_param(&transport_svc_name, &vlan);
                {
                    static param_t del;
                    init_param(&del, CMD, "del", 0, 0, INVALID, 0, "del vlan from Transport Service profile");
                    libcli_register_param(&vlan, &del);
                    {
                        static param_t all;
                        init_param(&all, CMD, "all", transport_svc_config_handler, 0, INVALID, 0, "Del all Vlans from Transport Svc Profile");
                        libcli_register_param(&del, &all);
                        libcli_set_param_cmd_code(&all, CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_DEL_ALL);
                        libcli_set_tail_config_batch_processing(&all);
                    }
                }
            }


        }
    }

    return 0;
}