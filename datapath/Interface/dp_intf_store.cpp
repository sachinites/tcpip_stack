#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../libs/BitOp/bitmap.h"
#include "../../utils.h"
#include "../../tcpconst.h"

#include "dp_intf.h"
#include "dp_intf_store.h"
#include "../Vrfs/dp_vrf.h"
#include "../dp_ctx.h"
#include "../Layer2/switching/mac_table.h"

#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"

#include "../classifier/pkt_classifier.h"
#include "../dp_const.h"
#include "../dp_uapi.h"
#include "../../libs/libtimer/WheelTimer.h"

typedef struct arp_table_ arp_table_t;

extern void
arp_entry_delete_by_interface(dp_ctx_t *dp_ctx,
                               arp_table_t *arp_table,
                               dp_intf_t *intf);

/* Hash function for uint32_t keys (used by VLAN interface hashtable) */
static inline uint32_t hash32(void *_x) {

    uint32_t x = *(uint32_t *)_x;
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

/* Equality function for uint32_t keys */
static int 
uint32_key_equal_function(void *key1, void *key2) {
    uint32_t *x1 = (uint32_t *)key1;
    uint32_t *x2 = (uint32_t *)key2;
    return (*x1 == *x2);
}

void
dp_insert_interface (dp_ctx_t *dp_ctx, dp_intf_t *intf) {

    assert(intf->port_id < DP_MAX_INTF);
    assert(!dp_ctx->intf_table[intf->port_id]);
    dp_ctx->intf_table[intf->port_id] = intf;
}

extern int cprintf (const char* format, ...);

void 
dp_check_and_free_interface (dp_intf_t *intf) {

    int i;

    assert(!intf->vrf);
    assert(!intf->vlan_intf);

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        assert(!intf->mports[i]);
    }

    assert(!intf->vlan_bitmap);
    assert(!intf->olay_tunnel_intf);
    assert(!intf->log_info.acc_lst_filter);
    assert (intf->if_type != DP_INTF_TYPE_PHY);

    for (i = 0; i < PROTO_IDX_MAX; i++) {
        assert (!intf->trap_rule_table[i]);
    }
    
    cprintf ("DP : intf %s deleted\n", intf->if_name);
    free(intf);
}

static void
dp_intf_de_init_logging(dp_intf_t *intf){
    
    log_t *log_info     = &intf->log_info;
    log_info->all       = false;
    log_info->recv      = false;
    log_info->send      = false;
    log_info->is_stdout = false;
    if (log_info->log_file) {
        fclose (log_info->log_file);
        log_info->log_file = NULL;
    }
}

static void
dp_intf_delete_timer_cbk (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    (void)ev_dis;
    (void)arg_size;

    dp_intf_t *intf = (dp_intf_t *)arg;
    dp_ctx_t *dp_ctx = intf->dp_ctx;

    assert(dp_ctx);
    dp_delete_interface(dp_ctx, intf);
}

void
dp_schedule_interface_delete (dp_ctx_t *dp_ctx, dp_intf_t *intf)
{
    assert(intf);
    assert(intf->port_id < DP_MAX_INTF);
    assert(dp_ctx->intf_table[intf->port_id] == NULL);
    assert(intf->dp_ctx == dp_ctx);

    timer_register_app_event(DP_TIMER(dp_ctx),
                             dp_intf_delete_timer_cbk,
                             intf,
                             sizeof(*intf),
                             DP_INTF_DELETE_GRACE_MS,
                             0);
}

void
dp_delete_interface (dp_ctx_t *dp_ctx, dp_intf_t *intf) {

    assert(intf);
    assert(intf->port_id < DP_MAX_INTF);
    assert(dp_ctx->intf_table[intf->port_id] == NULL);

    dp_intf_de_init_logging (intf);

    if (intf->vrf)
        arp_entry_delete_by_interface(dp_ctx, intf->vrf->arp_table, intf);

    intf->vrf = NULL;

    for (int i = 0; i < PROTO_IDX_MAX; i++) {

        trap_rule_t *trap_rule = intf->trap_rule_table[i];

        trap_rule_t *next_trap_rule;

        while (trap_rule) {

            next_trap_rule = trap_rule->next;
            free (trap_rule);
            trap_rule = next_trap_rule;
        }
        intf->trap_rule_table[i] = NULL;
    }

    /* If it is BD interface, then delete all Dynamic
        MAC table entries, and flood entry */
    if (intf->if_type == DP_INTF_TYPE_BD) {

        mac_table_t *mac_table = intf->mac_table;
        assert(mac_table);
        intf->mac_table = NULL;

        mac_table_delete_all_dynamic(dp_ctx, mac_table);

        mac_addr_t flood_mac;
        layer2_fill_with_broadcast_mac(flood_mac.mac);
        mac_table_entry_delete2(dp_ctx, mac_table,
                                DEFAULT_VLAN_ID, flood_mac.mac);
        assert(mac_table->entry_count == 0);
        destroy_mac_table(dp_ctx, mac_table);
    }

    dp_check_and_free_interface (intf);
}

dp_intf_t *
dp_create_interface (uint32_t port_id, uint32_t iftype, 
                     uint8_t (*mac_addr)[6], 
                     uint16_t vlan_id) {

    dp_intf_t *intf = (dp_intf_t *)calloc(1, sizeof(dp_intf_t));
    intf->port_id = port_id;
    intf->if_type = (DP_InterfaceType_t)iftype;
    intf->if_name[0] = '\0';
    intf->pkt_recv = 0;
    intf->pkt_sent = 0;
    intf->xmit_pkt_dropped = 0;
    intf->recvd_pkt_dropped = 0;
    intf->vrf = NULL;
    memset(intf->v6addr_link_local, 0, 16);
    memset(intf->v6addr, 0, 16);
    intf->v6mask = 0;
    intf->ip_addr = 0;
    intf->mask = 0;
    memcpy(&intf->mac_add, (void *)mac_addr, 6);
    intf->switchport = false;
    intf->vlan_intf = NULL;
    intf->vlan_id = vlan_id;
    intf->vni_id = 0;
    intf->l2_mode = DP_LAN_MODE_NONE;
    intf->is_up = false;
    intf->log_info.all = true;
    intf->log_info.recv = true;
    intf->log_info.send = true;
    intf->log_info.is_stdout = false;
    intf->log_info.acc_lst_filter = NULL;
    intf->dpdk_max_rx_queues = 0;
    intf->dpdk_max_tx_queues = 0;
    //intf->trap_rule_table[] = {0};
    intf->dp_ctx = NULL;
    intf->nbr_intf = NULL;
    return intf;
}


void 
dp_vlan_bind_port (dp_intf_t *vlan_intf, dp_intf_t *intf, DP_IntfL2Mode l2_mode) {

    dp_intf_t *mport;

    assert (intf->switchport);

    if (l2_mode == DP_LAN_ACCESS_MODE) {

        assert(!intf->vlan_intf);
        intf->vlan_intf = vlan_intf;
    }

    int i;

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i] == intf) assert(0);
    }

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i]) continue;
        break;
    }    

    assert (i != MAX_VLAN_MEMBER_PORTS);

    vlan_intf->mports[i] = intf;

    if (l2_mode == DP_LAN_TRUNK_MODE) {

        if (!intf->vlan_bitmap) {
            bitmap_init2(&intf->vlan_bitmap, DP_MAX_VLAN_SUPORT);
        }

        assert (!bitmap_at (intf->vlan_bitmap, vlan_intf->vlan_id));
        bitmap_set_bit_at(intf->vlan_bitmap, vlan_intf->vlan_id);
    }

    intf->l2_mode = l2_mode;
}

void 
dp_vlan_unbind_port (dp_intf_t *vlan_intf, 
                     dp_intf_t *intf, 
                     DP_IntfL2Mode l2_mode,
                     bool restore_intf_mode_to_none) {

    int i;

    assert (intf->switchport);

    /* In access mode, clear the vlan_intf pointer */
    if (l2_mode == DP_LAN_ACCESS_MODE) {
        
        assert(intf->vlan_intf == vlan_intf);
        intf->vlan_intf = NULL;
    }

    /* Find and remove the interface from vlan member ports */
    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i] == intf) {
            vlan_intf->mports[i] = NULL;
            break;
        }
    }

    /* Assert that we found and removed the interface */
    assert (i != MAX_VLAN_MEMBER_PORTS);

    /* In trunk mode, unset the vlan bit in bitmap */
    if (l2_mode == DP_LAN_TRUNK_MODE) {

        assert (intf->vlan_bitmap);
        assert (bitmap_at (intf->vlan_bitmap, vlan_intf->vlan_id));
        bitmap_unset_bit_at(intf->vlan_bitmap, vlan_intf->vlan_id);
    }

    if (!restore_intf_mode_to_none) return; 
    
    /* Reset L2 mode to none if no more VLANs are bound */
    if (l2_mode == DP_LAN_TRUNK_MODE) {

        /* Check if any VLAN bits are still set */
        bool has_vlans = false;
        for (i = 0; i < DP_MAX_VLAN_SUPORT; i++) {
            if (bitmap_at(intf->vlan_bitmap, i)) {
                has_vlans = true;
                break;
            }
        }
        if (!has_vlans) {
            intf->l2_mode = DP_LAN_MODE_NONE;
        }
    } else {
        /* In access mode, always reset to NONE when unbinding */
        intf->l2_mode = DP_LAN_MODE_NONE;
    }
}

bool
dp_is_vlan_member (bitmap_t *vlan_bitmap, uint16_t vlan_id) {

    /* VLAN IDs range from 0 to 4095 (12 bits) */
    if (!vlan_bitmap || vlan_id >= 4096) {
        return false;
    }
    
    /* Check if the vlan_id bit is set in the bitmap */
    return bitmap_at(vlan_bitmap, vlan_id);
}

void 
dp_init_vlan_intf_hashtable (hashtable_t **ht) {

    *ht = create_hashtable(32, hash32, uint32_key_equal_function);
}

dp_intf_t *
dp_look_up_interface_by_vlan_id (hashtable_t *ht, uint16_t vlan_id) {
    
    uint32_t vlan_key = (uint32_t )vlan_id;
    return (dp_intf_t *)hashtable_search(ht, (void *)&vlan_key);
}

void
dp_insert_vlan_interface (hashtable_t *ht, dp_intf_t *intf) {

    assert (intf->if_type == DP_INTF_TYPE_VLAN);

    uint32_t *key = (uint32_t *)malloc(sizeof(uint32_t));
    
    *key = (uint32_t)intf->vlan_id;

    if (!hashtable_insert(ht, (void *)key, (void *)intf)) {
        /* Insert failed - free the key we allocated */
        free(key);
    }

}

dp_intf_t *
dp_remove_vlan_interface (hashtable_t *ht, uint16_t vlan_id) {

    uint32_t vlan_id_key = (uint32_t )vlan_id;
    dp_intf_t *intf = (dp_intf_t *)hashtable_remove(ht, (void *)&vlan_id_key);
    return intf;
}

/* Caution : Use of this API should be Avoidded in DP as it is O(n) loop*/
dp_intf_t *
dp_lookup_gre_tunnel_intf (dp_ctx_t *dp_ctx, 
                           uint32_t tunnel_src, 
                           uint32_t tunnel_dst) {

    dp_intf_t * intf;

    DP_FOR_ALL_INTF(dp_ctx, intf) {

        if (intf->if_type != DP_INTF_TYPE_GRE_TUNNEL) continue;
        if (intf->gre_tunnel_src_ip != tunnel_src) continue;
        if (intf->gre_tunnel_dst_ip != tunnel_dst) continue;
        return intf;

    }DP_FOR_ALL_INTF_END;

    return NULL;
}

/* Create Fake Interfaces, Fake means these represent Algorithms which are
    disguised as dp_intf_t . This is done so that varieity of custom forwarding 
    behaviors can be represented using a unified API. For example, dp_intf_t can
    represent an interface which flood the frame in vlan , it can also represent
    an interface which perform Vxlan encap Or GRE encap Or Srv6 Or MPLS encap and
    many more.
    They are stateless and tied to customized forwarding 
    behavior depending on if_type. Because they are stateless, we create just one
    instance of them per device. Never put any field in them which tends to make
    them statefull  */
void 
dp_intf_create_fake_interfaces (dp_ctx_t *dp_ctx) {

    dp_intf_t *Fake_dp_intf;
    
    // Rmac Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[RMAC_INTF_INDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = RMAC_INTF_INDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_RMAC;
    strncpy (Fake_dp_intf->if_name, RMAC_INTF_NAME, strlen (RMAC_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (RMAC_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // BD RMAC Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[BD_RMAC_INTF_INDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = BD_RMAC_INTF_INDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_BD_RMAC;
    strncpy (Fake_dp_intf->if_name, BDRMAC_INTF_NAME, strlen (BDRMAC_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (BDRMAC_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // Vlan Flood Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[VLAN_FLOOD_INDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = VLAN_FLOOD_INDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_VLAN_FLOOD;
    strncpy (Fake_dp_intf->if_name, VLAN_FLOOD_INTF_NAME, strlen (VLAN_FLOOD_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (VLAN_FLOOD_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // BD Flood Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[BD_FLOOD_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = BD_FLOOD_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_BD_FLOOD;
    strncpy (Fake_dp_intf->if_name, BD_FLOOD_INTF_NAME, strlen (BD_FLOOD_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (BD_FLOOD_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // NVE Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[NVE_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = NVE_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_NVE;
    strncpy (Fake_dp_intf->if_name, NVE_INTF_NAME, strlen (NVE_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (NVE_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // Host Path Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[HOST_PATH_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = HOST_PATH_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_HOST_PATH;
    strncpy (Fake_dp_intf->if_name, HOST_PATH_INTF_NAME, strlen (HOST_PATH_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (HOST_PATH_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // MPLS to BD Steering Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[MPLS_TO_BD_INTF_STEER_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = MPLS_TO_BD_INTF_STEER_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_MPLS_TO_BD_STEER;
    strncpy (Fake_dp_intf->if_name, MPLS_TO_BD_STEER_INTF_NAME, strlen (MPLS_TO_BD_STEER_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (MPLS_TO_BD_STEER_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          

    // MPLS to VRF Steering Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[MPLS_TO_VRF_INTF_STEER_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = MPLS_TO_VRF_INTF_STEER_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_MPLS_TO_VRF_STEER;
    strncpy (Fake_dp_intf->if_name, MPLS_TO_VRF_STEER_INTF_NAME, strlen (MPLS_TO_VRF_STEER_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (MPLS_TO_VRF_STEER_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

    // SRv6 to BD Steering Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[SRv6_TO_BD_STEER_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = SRv6_TO_BD_STEER_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_SRV6_TO_BD_STEER;
    strncpy (Fake_dp_intf->if_name, SRv6_TO_BD_STEER_INTF_NAME, strlen (SRv6_TO_BD_STEER_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (SRv6_TO_BD_STEER_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          

    // SRv6 to VRF Steering Interface
    Fake_dp_intf = (dp_intf_t *)XCALLOC2(0, 1, dp_intf_t);
    dp_ctx->intf_table[SRv6_TO_VRF_INTF_STEER_IFINDEX] = Fake_dp_intf;
    Fake_dp_intf->port_id = SRv6_TO_VRF_INTF_STEER_IFINDEX;
    Fake_dp_intf->if_type = DP_INTF_TYPE_SRV6_TO_VRF_STEER;
    strncpy (Fake_dp_intf->if_name, SRv6_TO_VRF_STEER_INTF_NAME, strlen (SRv6_TO_VRF_STEER_INTF_NAME) -1);
    Fake_dp_intf->if_name[strlen (SRv6_TO_VRF_STEER_INTF_NAME) -1] = '\0';
    Fake_dp_intf->pkt_recv = 0;
    Fake_dp_intf->pkt_sent = 0;          
    Fake_dp_intf->xmit_pkt_dropped = 0;
    Fake_dp_intf->recvd_pkt_dropped = 0;

}
