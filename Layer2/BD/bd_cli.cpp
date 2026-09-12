#include <assert.h>
#include "../../CLIBuilder/libcli.h"
#include "../../utils.h"
#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../tcpip_notif.h"
#include "../../dpal/cp2dp.h"
#include "../../libs/BitOp/bitsop.h"
#include "../../cmdcodes.h"
#include "../../cp_limits.h"
#include "../../LabelMgr/label_mgr.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../vrf/mac_vrf.h"

extern graph_t *topo;

/* config node <node-name> [no] bridge-domain x */
#define CMD_CODE_BD_CREATE 1
/* config node <node-name> [no] bridge-domain x <member-if> */
#define CMD_CODE_BD_MEMBER_ADD 2
/* show node <node-name> bridge-domain <x> */
#define CMD_CODE_BD_SHOW 3
/* config node <node-name> [no] bridge-domain x member <if> encapsulation dot1q <vlan-id> */
#define CMD_CODE_BD_AC_ENCAP_8021Q 4
/* clear node <node-name> bridge-domain <bd-id> mac-address */
#define CMD_CODE_BD_MAC_CLEAR 5


static int
bd_config_handler(int64_t cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable) {

    node_t *node = NULL;
    c_string node_name = NULL;
    c_string member_name = NULL;
    uint16_t bd_id = 0;
    uint16_t vlan_id = 0;
    tlv_struct_t *tlv;
    char intf_name[IF_NAME_SIZE];

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bd-id"))
            bd_id = (uint16_t)atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "bd-member"))
            member_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vlan-id"))
            vlan_id = (uint16_t)atoi((const char *)tlv->value);

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    snprintf(intf_name, IF_NAME_SIZE, "bd%u", bd_id);

    switch (cmdcode) {

        case CMD_CODE_BD_CREATE:
            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    Interface *intf = node_interface_lookup_by_name(node, intf_name);

                    if (intf) {
                        return 0;
                    }

                    if (cp_node_count_bridge_domains(node) >= MAX_BD_SUPPORT) {
                        cprintf("Error : Maximum bridge-domains (%u) reached\n",
                                MAX_BD_SUPPORT);
                        return -1;
                    }

                    if (bd_id > (MAX_BD_SUPPORT - 1)) {
                        cprintf("Error : BD ID must be [0, %u]\n",
                                MAX_BD_SUPPORT - 1);
                        return -1;
                    }

                    std::shared_ptr<BDInterface> bdP =
                        std::make_shared<BDInterface>(std::string(intf_name),
                                                      INTF_TYPE_BD, node);
                    bdP->SetSharedPtr(bdP);
                    bdP->att_node = node;
                    bdP->ifindex = interface_get_new_ifindex(node);
                    bdP->bd_id = bd_id;

                    if (!node_global_intf_map_insert(node, bdP.get())) {
                        cprintf("Error : Failed to insert bridge-domain interface %s\n",
                                intf_name);
                        return -1;
                    }

                    cp2dp_interface_create(node, bdP.get());
                    if (!vrf_add_interface(NODE_DEF_VRF(node), bdP.get())) {
                        cprintf("Error : Failed to add bridge-domain %s to default VRF\n",
                                intf_name);
                        node_global_intf_map_delete_by_ifindex(node, bdP->ifindex);
                        return -1;
                    }
                    cp2dp_send_intf_admin_status_update(node, bdP->ifindex, false);
                    /* Assign Service L2 VPN label to BD */
                    assert (label_mgr_block_alloc_label(
                        node->l2vpn_lbl_block, &bdP->vpn_svc_label) == LABEL_MGR_OK);
                    /* Install the Service L2 EVPN label in 0.mpls.0 with Xconnect to BD*/
                    rtm_install_mpls_xconnect_bd_evpn_local_route (bdP.get(), true);
                }
                break;

                case CONFIG_DISABLE:
                {
                    uint32_t if_change_flags = 0;
                    intf_prop_changed_t intf_prop_changed;
                    memset(&intf_prop_changed, 0, sizeof(intf_prop_changed_t));

                    Interface *intf = node_interface_lookup_by_name(node, intf_name);

                    if (!intf) {
                        cprintf("Error : Bridge-domain %s does not exist\n", intf_name);
                        return -1;
                    }

                    if (intf->iftype != INTF_TYPE_BD) {
                        cprintf("Error : %s is not a bridge-domain interface\n", intf_name);
                        return -1;
                    }

                    BDInterface *bd = dynamic_cast<BDInterface *>(intf);
                    if (bd && !bd->member_ac.empty()) {
                        cprintf("Error : Remove member interfaces first\n");
                        return -1;
                    }

                    if (intf->IsCrossReferenced()) {
                        cprintf("Error : Bridge-domain interface %s is in use, cannot delete\n",
                                intf->if_name.c_str());
                        return -1;
                    }

                    if (intf->HasL3Config(false)) {
                        cprintf("Error : Remove L3 config from bridge-domain %s first\n",
                                intf_name);
                        return -1;
                    }

                    if (intf->vrf) {
                        if (!vrf_del_interface(intf->vrf, intf)) {
                            cprintf("Error : Failed to remove bridge-domain %s from VRF\n",
                                    intf_name);
                            return -1;
                        }
                    }

                    SET_BIT(if_change_flags, IF_DELETE_F);
                    nfc_intf_invoke_notification_to_sbscribers(
                        intf, &intf_prop_changed, if_change_flags);

                    node_global_intf_map_delete_by_ifindex(node, intf->ifindex);

                }
                break;

                default:
                    break;
            }
            break;

        case CMD_CODE_BD_MEMBER_ADD:
        {
            Interface *bd_base = node_interface_lookup_by_name(node, intf_name);
            if (!bd_base || bd_base->iftype != INTF_TYPE_BD) {
                cprintf("Error : Bridge-domain %s does not exist\n", intf_name);
                return -1;
            }

            BDInterface *bd = dynamic_cast<BDInterface *>(bd_base);
            if (!bd) {
                cprintf("Error : %s is not a bridge-domain interface\n", intf_name);
                return -1;
            }

            if (!member_name || !member_name[0]) {
                cprintf("Error : Member interface name required\n");
                return -1;
            }

            Interface *phy = node_interface_lookup_by_name(
                node, (const char *)member_name);

            if (!phy || phy->iftype != INTF_TYPE_PHY) {
                cprintf("Error : Physical interface %s does not exist\n",
                        member_name);
                return -1;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    if (phy->HasL3Config(false)) {
                        cprintf("Error : Remove L3 config from %s first\n",
                                phy->if_name.c_str());
                        return -1;
                    }

                    if (!phy->GetSwitchport()) {
                        cprintf("Error : %s is not a switchport\n",
                                phy->if_name.c_str());
                        return -1;
                    }

                    if (phy->GetAccessVlanIntf()) {
                        cprintf("Error : %s is already a VLAN access member\n",
                                phy->if_name.c_str());
                        return -1;
                    }

                    PhysicalInterface *phy_if =
                        dynamic_cast<PhysicalInterface *>(phy);
                    if (phy_if && phy_if->trans_svc) {
                        cprintf("Error : %s has a transport service profile attached\n",
                                phy->if_name.c_str());
                        return -1;
                    }

                    if (phy->GetL2Mode() == LAN_TRUNK_MODE) {
                        cprintf("Error : %s is already a VLAN trunk port\n",
                                phy->if_name.c_str());
                        return -1;
                    }

                    if (bd->FindMemberAC(phy)) {
                        return 0;
                    }

                    if (bd->member_ac.size() >= MAX_BD_MEMBERPORTS) {
                        cprintf("Error : Maximum BD member ports (%u) reached on %s\n",
                                MAX_BD_MEMBERPORTS, bd->if_name.c_str());
                        return -1;
                    }

                    std::string ac_name = std::string("ac-") + phy->if_name;
                    ACInterfaceP acP =
                        std::make_shared<ACInterface>(ac_name, INTF_TYPE_AC);
                    acP->SetSharedPtr(acP);
                    acP->att_node = node;

                    /* AC does not consume a new ifindex; it borrows the
                       physical port's ifindex for datapath lookup. */
                    if (acP->ifindex) {
                        interface_release_index(node, acP->ifindex);
                    }
                    acP->ifindex = phy->ifindex;

                    if (!acP->SetUnderlyingInterface(phy->GetSharedPtr())) {
                        cprintf("Error : Failed to bind AC to %s\n",
                                phy->if_name.c_str());
                        acP->ifindex = 0;
                        return -1;
                    }

                    if (!acP->SetBdInterface(
                            std::dynamic_pointer_cast<BDInterface>(bd->GetSharedPtr()))) {
                        cprintf("Error : Failed to bind AC to %s\n",
                                bd->if_name.c_str());
                        acP->UnSetUnderlyingInterface();
                        acP->ifindex = 0;
                        return -1;
                    }

                    if (!bd->AddMemberAC(acP)) {
                        cprintf("Error : Failed to add member %s to %s\n",
                                phy->if_name.c_str(), bd->if_name.c_str());
                        acP->UnSetUnderlyingInterface();
                        acP->UnSetBdInterface();
                        acP->ifindex = 0;
                        return -1;
                    }

                    cp2dp_bd_ac_bind(node, bd->ifindex, acP->ifindex, true);
                }
                break;

                case CONFIG_DISABLE:
                {
                    ACInterfaceP acP = bd->FindMemberAC(phy);
                    
                    if (!acP) {
                        cprintf("Error : %s is not a member of %s\n",
                                phy->if_name.c_str(), bd->if_name.c_str());
                        return -1;
                    }

                    cp2dp_bd_ac_bind(node, bd->ifindex, acP->ifindex, false);
                    acP->ifindex = 0;
                    bd->DelMemberAC(acP);
                }
                break;

                default:
                    break;
            }
        }
        break;

        case CMD_CODE_BD_AC_ENCAP_8021Q:
        {
            Interface *bd_base = node_interface_lookup_by_name(node, intf_name);
            if (!bd_base || bd_base->iftype != INTF_TYPE_BD) {
                cprintf("Error : Bridge-domain %s does not exist\n", intf_name);
                return -1;
            }

            BDInterface *bd = dynamic_cast<BDInterface *>(bd_base);
            if (!bd) {
                cprintf("Error : %s is not a bridge-domain interface\n", intf_name);
                return -1;
            }

            if (!member_name || !member_name[0]) {
                cprintf("Error : Member interface name required\n");
                return -1;
            }

            Interface *phy = node_interface_lookup_by_name(
                node, (const char *)member_name);
            if (!phy || phy->iftype != INTF_TYPE_PHY) {
                cprintf("Error : Physical interface %s does not exist\n",
                        member_name);
                return -1;
            }

            ACInterfaceP acP = bd->FindMemberAC(phy);
            if (!acP) {
                cprintf("Error : %s is not a member of %s\n",
                        phy->if_name.c_str(), bd->if_name.c_str());
                return -1;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    if (!CP_VLAN_ID_VALID(vlan_id)) {
                        cprintf("Error : Invalid VLAN ID %u (1-%u)\n",
                                vlan_id, MAX_VLAN_SUPPORTED - 1);
                        return -1;
                    }

                    /* Allow replace of an existing tag. */
                    if (acP->GetEncap_tag_8021q() != vlan_id) {
                        if (acP->GetEncap_tag_8021q())
                            acP->UnSetEncap_tag_8021q(acP->GetEncap_tag_8021q());
                        acP->SetEncap_tag_8021q(vlan_id);
                    }
                }
                break;

                case CONFIG_DISABLE:
                {
                    acP->UnSetEncap_tag_8021q(vlan_id);
                }
                break;

                default:
                    break;
            }
        }
        break;

        default:
            break;
    }

    return 0;
}

/* Disable this call from the show handler when sanity is no longer needed. */
static bool
bd_sanity_check_linkages(BDInterface *bd)
{
    bool ok = true;
    node_t *node;

    if (!bd) {
        cprintf("SANITY: BD pointer is null\n");
        return false;
    }

    node = bd->att_node;
    if (!node) {
        cprintf("SANITY: BD %s has no attached node\n", bd->if_name.c_str());
        return false;
    }

    if (bd->iftype != INTF_TYPE_BD) {
        cprintf("SANITY: %s iftype is not BD\n", bd->if_name.c_str());
        ok = false;
    }

    if (node_interface_lookup_by_name(node, bd->if_name.c_str()) != bd) {
        cprintf("SANITY: BD %s missing from global name map\n",
                bd->if_name.c_str());
        ok = false;
    }

    if (node_get_intf_by_ifindex(node, bd->ifindex) != bd) {
        cprintf("SANITY: BD %s missing from global ifindex map\n",
                bd->if_name.c_str());
        ok = false;
    }

    for (auto &ac : bd->member_ac) {

        if (!ac) {
            continue;
        }

        if (ac->iftype != INTF_TYPE_AC) {
            cprintf("SANITY: %s iftype is not AC\n", ac->if_name.c_str());
            ok = false;
        }

        if (ac->att_node != node) {
            cprintf("SANITY: AC %s att_node mismatch\n", ac->if_name.c_str());
            ok = false;
        }

        if (ac->GetBdInterface().get() != bd) {
            cprintf("SANITY: AC %s does not point back to BD %s\n",
                    ac->if_name.c_str(), bd->if_name.c_str());
            ok = false;
        }

        InterfaceP phyP = ac->GetUnderlyingInterface();
        if (!phyP || phyP->iftype != INTF_TYPE_PHY) {
            cprintf("SANITY: AC %s has no physical underlying interface\n",
                    ac->if_name.c_str());
            ok = false;
            continue;
        }

        PhysicalInterface *phy = dynamic_cast<PhysicalInterface *>(phyP.get());
        if (!phy) {
            cprintf("SANITY: AC %s underlying is not a PhysicalInterface\n",
                    ac->if_name.c_str());
            ok = false;
            continue;
        }

        if (ac->ifindex != phy->ifindex) {
            cprintf("SANITY: AC %s ifindex %u != phy %s ifindex %u\n",
                    ac->if_name.c_str(), ac->ifindex,
                    phy->if_name.c_str(), phy->ifindex);
            ok = false;
        }

        Interface *mapped = node_get_intf_by_ifindex(node, ac->ifindex);
        if (mapped != phy) {
            cprintf("SANITY: global ifindex %u maps to %s, expected phy %s\n",
                    ac->ifindex,
                    mapped ? mapped->if_name.c_str() : "null",
                    phy->if_name.c_str());
            ok = false;
        }

        if (phy->bd_ac.get() != ac.get()) {
            cprintf("SANITY: phy %s bd_ac does not point back to AC %s\n",
                    phy->if_name.c_str(), ac->if_name.c_str());
            ok = false;
        }

        if (!interface_is_bd_member(phy)) {
            cprintf("SANITY: phy %s is not reported as a BD member\n",
                    phy->if_name.c_str());
            ok = false;
        }

        if (!phy->GetSwitchport()) {
            cprintf("SANITY: phy %s is not switchport\n", phy->if_name.c_str());
            ok = false;
        }

        if (bd->FindMemberAC(phy).get() != ac.get()) {
            cprintf("SANITY: BD %s FindMemberAC(%s) does not return AC %s\n",
                    bd->if_name.c_str(), phy->if_name.c_str(),
                    ac->if_name.c_str());
            ok = false;
        }

        Interface *by_name =
            node_interface_lookup_by_name(node, ac->if_name.c_str());
        if (by_name) {
            cprintf("SANITY: AC %s unexpectedly present in global name map\n",
                    ac->if_name.c_str());
            ok = false;
        }
    }

    return ok;
}

static int
bd_show_handler(int64_t cmdcode,
                Stack_t *tlv_stack,
                op_mode enable_or_disable) {

    node_t *node = NULL;
    c_string node_name = NULL;
    uint16_t bd_id = 0;
    tlv_struct_t *tlv;
    char intf_name[IF_NAME_SIZE];

    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bd-id"))
            bd_id = (uint16_t)atoi((const char *)tlv->value);

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    snprintf(intf_name, IF_NAME_SIZE, "bd%u", bd_id);

    switch (cmdcode) {

        case CMD_CODE_BD_SHOW:
        {
            Interface *intf = node_interface_lookup_by_name(node, intf_name);
            if (!intf || intf->iftype != INTF_TYPE_BD) {
                cprintf("Error : Bridge-domain %s does not exist\n", intf_name);
                return -1;
            }

            BDInterface *bd = dynamic_cast<BDInterface *>(intf);
            if (!bd) {
                cprintf("Error : %s is not a bridge-domain interface\n", intf_name);
                return -1;
            }

            /* Comment out this call to disable BD/AC/phy linkage sanity. */
            if (!bd_sanity_check_linkages(bd))
                assert(0);

            cprintf("\nBridge-domain %u  (%s)  ifindex %u\n",
                    bd->bd_id, bd->if_name.c_str(), bd->ifindex);
            cprintf("%-16s %-16s %-10s %-8s %-12s %-12s\n",
                    "AC", "Physical", "Ifindex", "Status", "Switchport", "Encap");
            cprintf("%-16s %-16s %-10s %-8s %-12s %-12s\n",
                    "----------------", "----------------",
                    "----------", "--------", "------------", "------------");

            uint32_t count = 0;
            for (auto &ac : bd->member_ac) {
                if (!ac)
                    continue;
                InterfaceP phyP = ac->GetUnderlyingInterface();
                const char *phy_name = phyP ? phyP->if_name.c_str() : "-";
                const char *status =
                    (phyP && phyP->IsInterfaceUp(0)) ? "UP" : "DOWN";
                const char *sw = (phyP && phyP->GetSwitchport()) ? "Yes" : "No";
                uint16_t encap = ac->GetEncap_tag_8021q();
                char encap_str[16];
                if (encap)
                    snprintf(encap_str, sizeof(encap_str), "dot1q %u", encap);
                else
                    snprintf(encap_str, sizeof(encap_str), "none");
                cprintf("%-16s %-16s %-10u %-8s %-12s %-12s\n",
                        ac->if_name.c_str(),
                        phy_name,
                        ac->ifindex,
                        status,
                        sw,
                        encap_str);
                count++;
            }

            if (!count)
                cprintf("(no attachment circuits)\n");
            cprintf("Total ACs: %u\n", count);
        }
        break;

        default: 
            break;
    }

    return 0;
}

static int
bd_clear_handler(int64_t cmdcode,
                 Stack_t *tlv_stack,
                 op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    uint16_t bd_id = 0;
    tlv_struct_t *tlv;
    char intf_name[IF_NAME_SIZE];

    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bd-id"))
            bd_id = (uint16_t)atoi((const char *)tlv->value);

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    if (!node) {
        cprintf("Error : Node not found\n");
        return -1;
    }

    snprintf(intf_name, IF_NAME_SIZE, "bd%u", bd_id);

    switch (cmdcode) {

        case CMD_CODE_BD_MAC_CLEAR:
        {
            Interface *intf = node_interface_lookup_by_name(node, intf_name);

            if (!intf || intf->iftype != INTF_TYPE_BD) {
                cprintf("Error : Bridge-domain %s does not exist\n", intf_name);
                return -1;
            }

            cp2dp_bd_mac_table_clear(node, intf->ifindex, true);
        }
        break;

        default:
            break;
    }

    return 0;
}

void
bd_clear_cli_tree(param_t *mount_point)
{
    static param_t bd;
    init_param(&bd, CMD, "bridge-domain", 0, 0, INVALID, 0, "bridge-domain");
    libcli_register_param(mount_point, &bd);
    {
        static param_t bd_id;
        init_param(&bd_id, LEAF, NULL, 0, 0, INT, "bd-id",
                   "bridge-domain id");
        libcli_register_param(&bd, &bd_id);
        {
            static param_t mac_address;
            init_param(&mac_address, CMD, "mac-address", bd_clear_handler, 0, INVALID, 0,
                       "Clear dynamic MAC addresses (retain static)");
            libcli_register_param(&bd_id, &mac_address);
            libcli_set_param_cmd_code(&mac_address, CMD_CODE_BD_MAC_CLEAR);
        }
    }
}

void
bd_show_cli_tree (param_t *mount_point)
{
    static param_t bd;
    init_param(&bd, CMD, "bridge-domain", 0, 0, INVALID, 0, "bridge-domain");
    libcli_register_param(mount_point, &bd);
    {
        static param_t bd_id;
        init_param(&bd_id, LEAF, NULL, bd_show_handler, 0, INT, "bd-id", "bridge-domain id");
        libcli_register_param(&bd, &bd_id);
        libcli_set_param_cmd_code(&bd_id, CMD_CODE_BD_SHOW);
    }
}

void
bd_config_cli_tree (param_t *mount_point)
{

    static param_t bd;
    init_param(&bd, CMD, "bridge-domain", 0, 0, INVALID, 0, "bridge-domain");
    libcli_register_param(mount_point, &bd);
    {
        static param_t bd_id;
        init_param(&bd_id, LEAF, NULL, bd_config_handler, 0, INT, "bd-id", "bridge-domain id");
        libcli_register_param(&bd, &bd_id);
        libcli_set_param_cmd_code(&bd_id, CMD_CODE_BD_CREATE);

        {
            static param_t bd_member;
            init_param(&bd_member, CMD, "member", 0, 0, INVALID, 0, "BD member AC");
            libcli_register_param(&bd_id, &bd_member);
            {
                /* member <physical interface name >*/
                static param_t member;
                init_param(&member, LEAF, NULL, bd_config_handler, 0, STRING, "bd-member", "AC interface name");
                libcli_register_param(&bd_member, &member);
                libcli_set_param_cmd_code(&member, CMD_CODE_BD_MEMBER_ADD);

                {
                    /* encapsulation dot1q <vlan-id> */
                    static param_t encapsulation;
                    init_param(&encapsulation, CMD, "encapsulation", 0, 0, INVALID, NULL,
                               "Encapsulation");
                    libcli_register_param(&member, &encapsulation);
                    {
                        static param_t dot1q;
                        init_param(&dot1q, CMD, "dot1q", 0, 0, INVALID, NULL,
                                   "802.1Q encapsulation");
                        libcli_register_param(&encapsulation, &dot1q);
                        {
                            static param_t encapsulation_dot1q;
                            init_param(&encapsulation_dot1q, LEAF, NULL,
                                       bd_config_handler, 0, INT, "vlan-id",
                                       "VLAN ID");
                            libcli_register_param(&dot1q, &encapsulation_dot1q);
                            libcli_set_param_cmd_code(&encapsulation_dot1q,
                                                      CMD_CODE_BD_AC_ENCAP_8021Q);
                        }
                    }
                }
            }
        }
    }

    libcli_support_cmd_negation(&bd);

}
