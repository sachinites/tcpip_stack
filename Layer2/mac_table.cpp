#include <ncurses.h>
#include "mac_table.h"
#include "../Interface/Interface.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../graph.h"
#include "../Tracer/tracer.h"
#include "../gluethread/glthread.h"

extern int cprintf (const char* format, ...);

void
init_mac_table(mac_table_t **mac_table){

    *mac_table = new mac_table_t;
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, vlan_id_t vlan, c_string mac){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if (mac_address_compare((char *)mac_table_entry->mac.mac, (char *)mac) &&
                mac_table_entry->vlan_id == vlan) {

            return mac_table_entry;
        }
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    return NULL;
}

void 
mac_table_entry_cancel_expiry_timer (mac_table_entry_t *mac_table_entry) {

    if (mac_table_entry->exp_timer_wt_elem) {
        timer_de_register_app_event(mac_table_entry->exp_timer_wt_elem);
        mac_table_entry->exp_timer_wt_elem = NULL;
    }
}

void
clear_mac_table(node_t *node, mac_table_t *mac_table){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){
        
        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if (mac_table_entry->flags & MAC_STATIC) continue;
        remove_glthread(curr);
        mac_table_entry_cancel_expiry_timer(mac_table_entry);
        delete (mac_table_entry);

    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

static void
mac_table_entry_timer_expiry_cbk (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    mac_table_entry_t *mac_table_entry = (mac_table_entry_t *)arg;
    node_t *node = (node_t *)(ev_dis->app_data);

    tracer (node->dptr, DL2SW, 
            "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Expired\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5] );

    remove_glthread(&mac_table_entry->mac_entry_glue);
    mac_table_entry->exp_timer_wt_elem = NULL;
    delete (mac_table_entry);
}

void 
mac_table_entry_init_timer (node_t *node, mac_table_entry_t *mac_table_entry) {

    assert (!mac_table_entry->exp_timer_wt_elem);
    mac_table_entry->exp_timer_wt_elem = timer_register_app_event(
        DP_TIMER(node),
        mac_table_entry_timer_expiry_cbk,
        (void *)mac_table_entry,
        sizeof(mac_table_entry_t),
        MAC_ENTRY_EXP_TIME * 1000, 0);
}

void
mac_table_entry_delete2 (node_t *node, mac_table_t *mac_table, vlan_id_t vlan_id, c_string mac){

    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    mac_table_entry_cancel_expiry_timer(mac_table_entry);

    tracer (node->dptr, DL2SW, 
            "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Deleted\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5] );

    delete (mac_table_entry);
}

void
mac_table_entry_delete (node_t *node,
                          mac_table_t *mac_table, 
                          uint8_t *mac_addr, 
                          uint16_t vlan_id,
                          uint32_t ifindex,
                          uint32_t remote_dst_ip) {
    
    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    
    if (!mac_table_entry) {
        return;
    }

    /* Check if the entry has the specific interface */
    bool found_if = false;
    for (int i = 0; i < MAC_MAC_OIF_CNT; i++) {
        if (mac_table_entry->oif[i] && 
            mac_table_entry->oif[i]->ifindex == ifindex && 
                mac_table_entry->remote_dst_ip[i] == remote_dst_ip) {
            mac_table_entry->oif[i] = nullptr;
            mac_table_entry->remote_dst_ip[i] = 0;
            found_if = true;
            break;
        }
    }

    /* If no interfaces left or this was the only interface, remove the entry */
    bool has_remaining_oifs = false;
    for (int i = 0; i < MAC_MAC_OIF_CNT; i++) {
        if (mac_table_entry->oif[i]) {
            has_remaining_oifs = true;
            break;
        }
    }

    if (!has_remaining_oifs) {
        remove_glthread(&mac_table_entry->mac_entry_glue);
        if (mac_table_entry->exp_timer_wt_elem) {
            mac_table_entry_cancel_expiry_timer(mac_table_entry);
        }
        
        tracer (node->dptr, DL2SW, 
            "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Deleted\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5] );

        delete mac_table_entry;
    }
}

void
mac_table_entry_add (node_t *node,
                          mac_table_t *mac_table, 
                          uint8_t *mac_addr, 
                          uint16_t vlan_id,
                          uint32_t ifindex,
                         uint16_t flags,
                         uint32_t remote_dst_ip) {

    /* Get the interface by ifindex */
    Interface *oif = node_get_intf_by_ifindex(node, ifindex);

    if (!oif) {
        cprintf ("Error : Interface with ifindex %d not found\n", ifindex);
        return;
    }

    /* Look up existing MAC table entry */
    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    
    if (mac_table_entry) {
        /* Entry exists, check if interface is already in the entry */
        bool found_if = false;
        for (int i = 0; i < MAC_MAC_OIF_CNT; i++) {
            if (mac_table_entry->oif[i] && 
                mac_table_entry->oif[i]->ifindex == ifindex) {
                found_if = true;
                break;
            }
        }
        
        if (!found_if) {
            /* Add interface to existing entry */
            for (int i = 0; i < MAC_MAC_OIF_CNT; i++) {
                if (!mac_table_entry->oif[i]) {
                    mac_table_entry->oif[i] = oif->GetSharedPtr();
                    mac_table_entry->remote_dst_ip[i] = remote_dst_ip;
                    tracer(node->dptr, DL2SW, 
                           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Interface %s added to existing entry\n", 
                           vlan_id,
                           mac_addr[0], mac_addr[1], mac_addr[2], 
                           mac_addr[3], mac_addr[4], mac_addr[5],
                           oif->if_name.c_str());
                    break;
                }
            }
        }
        return;
    }

    /* Create new MAC table entry */
    mac_table_entry = new mac_table_entry_t;
    mac_table_entry->vlan_id = vlan_id;
    memcpy(mac_table_entry->mac.mac, mac_addr, sizeof(mac_addr_t));
    mac_table_entry->flags = flags;
    
    /* Initialize all OIFs to nullptr and remote_dst_ip to 0 */
    for (int i = 0; i < MAC_MAC_OIF_CNT; i++) {
        mac_table_entry->oif[i] = nullptr;
        mac_table_entry->remote_dst_ip[i] = 0;
    }
    
    /* Set the first OIF and remote_dst_ip */
    mac_table_entry->oif[0] = oif->GetSharedPtr();
    mac_table_entry->remote_dst_ip[0] = remote_dst_ip;
    
    /* Initialize timer for dynamic entries */
    if (!(flags & MAC_STATIC)) {
        mac_table_entry_init_timer(node, mac_table_entry);
    }

    /* Add to MAC table */
    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);

    tracer(node->dptr, DL2SW, 
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x %s] Added\n", 
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2], 
           mac_addr[3], mac_addr[4], mac_addr[5],
           oif->if_name.c_str());
}

static uint16_t
mac_table_entry_get_exp_time_left(
	mac_table_entry_t *mac_table_entry){

	if (mac_table_entry->exp_timer_wt_elem) {
	    return wt_get_remaining_time(mac_table_entry->exp_timer_wt_elem);
    }
    return 0;
}


static char *
mac_table_entry_append_oifs (mac_table_entry_t *mac_table_entry,
                                                 char *buffer, uint16_t buff_size) 
{
    int i = 0;
    uint16_t len = 0;

    InterfaceP oif;

    while ((oif = mac_table_entry->oif[i])) {
        len += snprintf(buffer + len, buff_size - len, "%s ", oif->if_name.c_str());
        if (mac_table_entry->remote_dst_ip[i]) {
            len += snprintf(buffer + len - 1, buff_size - len + 1, "(%d.%d.%d.%d) ",
                            (mac_table_entry->remote_dst_ip[i] >> 24) & 0xFF,
                            (mac_table_entry->remote_dst_ip[i] >> 16) & 0xFF,
                            (mac_table_entry->remote_dst_ip[i] >> 8) & 0xFF,
                            (mac_table_entry->remote_dst_ip[i]) & 0xFF);
        }
        i++;
        if (i >= MAC_MAC_OIF_CNT) break;
    }
    assert (len <= buff_size); 
    return buffer;
}

void
show_mac_table(mac_table_t *mac_table, vlan_id_t vlan_id) {

    int count = 0;
    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    char buffer[ (IF_NAME_SIZE + IPV4_ADDR_LEN_STR) * (MAC_MAC_OIF_CNT + 1)];

    printw("\n\r");

    cprintf("VLAN   MAC Address         Type         Exp-Time(ms)\n");
    cprintf("----  ------------        ------       --------------\n\n");

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr) {

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);

        if (vlan_id && vlan_id != mac_table_entry->vlan_id) {
            continue;
        }

        count++;

        if (mac_table_entry->vlan_id == DEFAULT_VLAN_ID ) {

            cprintf("%-6s %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-6d\n",
            "--",
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_entry_flag(mac_table_entry->flags),
            mac_table_entry_get_exp_time_left(mac_table_entry));
        }

        else {

            cprintf("%-6d %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-6d\n",
                mac_table_entry->vlan_id,
                mac_table_entry->mac.mac[0],
                mac_table_entry->mac.mac[1],
                mac_table_entry->mac.mac[2],
                mac_table_entry->mac.mac[3],
                mac_table_entry->mac.mac[4],
                mac_table_entry->mac.mac[5],
                mac_entry_flag(mac_table_entry->flags),
                mac_table_entry_get_exp_time_left(mac_table_entry));
        }

        mac_table_entry_append_oifs(mac_table_entry, buffer, sizeof(buffer));
        cprintf("       Ports: %s\n\n", buffer);

    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}
