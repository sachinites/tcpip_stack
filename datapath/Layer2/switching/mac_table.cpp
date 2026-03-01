
#include <memory.h>
#include <ncurses.h>
#include "mac_table.h"
#include "../../../net.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf_store.h"
#include "../../../EventDispatcher/event_dispatcher.h"
#include "../../../Tracer/tracer.h"
#include "../../../gluethread/glthread.h"
#include "../../dp_uapi.h"

extern int cprintf (const char* format, ...);

void
init_mac_table(mac_table_t **mac_table){

    *mac_table = new mac_table_t;
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, uint16_t vlan, c_string mac){

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
        mac_table_entry_clear_oifs(mac_table_entry);  // Clean up dynamic OIF list
        delete (mac_table_entry);

    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

static void
mac_table_entry_timer_expiry_cbk (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    mac_table_entry_t *mac_table_entry = (mac_table_entry_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    tracer (dp_ctx->dptr, DL2SW, 
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
mac_table_entry_init_timer (dp_ctx_t *dp_ctx, mac_table_entry_t *mac_table_entry) {

    assert (!mac_table_entry->exp_timer_wt_elem);
    mac_table_entry->exp_timer_wt_elem = timer_register_app_event(
        DP_TIMER(dp_ctx),
        mac_table_entry_timer_expiry_cbk,
        (void *)mac_table_entry,
        sizeof(mac_table_entry_t),
        MAC_ENTRY_EXP_TIME * 1000, 0);
}

void
mac_table_entry_delete2 (dp_ctx_t *dp_ctx, mac_table_t *mac_table, uint16_t vlan_id, c_string mac){

    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    mac_table_entry_cancel_expiry_timer(mac_table_entry);

    tracer (dp_ctx->dptr, DL2SW, 
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
mac_table_entry_delete (dp_ctx_t *dp_ctx,
                          mac_table_t *mac_table, 
                          uint8_t *mac_addr, 
                          uint16_t vlan_id,
                          uint32_t ifindex,
                          uint32_t remote_dst_ip) {
    
    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    
    if (!mac_table_entry) {
        return;
    }

    /* Remove the specific interface from the entry */
    mac_table_entry_remove_oif(mac_table_entry, ifindex, remote_dst_ip);

    /* If no interfaces left, remove the entire entry */
    if (!mac_table_entry_has_oifs(mac_table_entry)) {
        remove_glthread(&mac_table_entry->mac_entry_glue);
        if (mac_table_entry->exp_timer_wt_elem) {
            mac_table_entry_cancel_expiry_timer(mac_table_entry);
        }
        
        tracer (dp_ctx->dptr, DL2SW, 
            "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Deleted\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5] );

        mac_table_entry_clear_oifs(mac_table_entry);  // Clean up dynamic OIF list
        delete mac_table_entry;
    }
}

void
mac_table_entry_add (dp_ctx_t *dp_ctx,
                        mac_table_t *mac_table, 
                        uint8_t *mac_addr, 
                        uint16_t vlan_id,
                        uint32_t ifindex,
                        uint16_t flags,
                        uint32_t remote_dst_ip) {

    /* Get the interface by ifindex */
    dp_intf_t *oif = dp_look_up_interface(dp_ctx->dp_intf_ht, ifindex);

    if (!oif) {
        cprintf ("Error : Interface with ifindex %d not found\n", ifindex);
        return;
    }

    /* Look up existing MAC table entry */
    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    
    if (mac_table_entry) {
        /* Entry exists, try to add interface to existing entry */
        if (mac_table_entry_add_oif(mac_table_entry, oif, remote_dst_ip)) {
            tracer(dp_ctx->dptr, DL2SW, 
                   "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Interface %s added to existing entry\n", 
                   vlan_id,
                   mac_addr[0], mac_addr[1], mac_addr[2], 
                   mac_addr[3], mac_addr[4], mac_addr[5],
                   oif->if_name);
        }
        return;
    }

    /* Create new MAC table entry */
    mac_table_entry = new mac_table_entry_t;
    mac_table_entry->vlan_id = vlan_id;
    memcpy(mac_table_entry->mac.mac, mac_addr, sizeof(mac_addr_t));
    mac_table_entry->flags = flags;
    
    /* Initialize dynamic OIF list */
    init_glthread(&mac_table_entry->oif_list);
    
    /* Add the first OIF and remote_dst_ip */
    mac_table_entry_add_oif(mac_table_entry, oif, remote_dst_ip);
    
    /* Initialize timer for dynamic entries */
    if (!(flags & MAC_STATIC)) {
        mac_table_entry_init_timer(dp_ctx, mac_table_entry);
    }

    /* Add to MAC table */
    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);

    tracer(dp_ctx->dptr, DL2SW, 
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x %s] Added\n", 
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2], 
           mac_addr[3], mac_addr[4], mac_addr[5],
           oif->if_name);
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
    uint16_t len = 0;
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;

    memset (buffer, 0, buff_size);

    ITERATE_GLTHREAD_BEGIN(&mac_table_entry->oif_list, curr) {

        oif_entry = mac_oif_glue_to_entry(curr);
        
        if (!oif_entry->oif) continue;  // Skip invalid entries
        
        len += snprintf(buffer + len, buff_size - len, "%s", oif_entry->oif->if_name);
        
        if (oif_entry->remote_dst_ip) {
            len += snprintf(buffer + len, buff_size - len, "(%d.%d.%d.%d)",
                            (oif_entry->remote_dst_ip >> 24) & 0xFF,
                            (oif_entry->remote_dst_ip >> 16) & 0xFF,
                            (oif_entry->remote_dst_ip >> 8) & 0xFF,
                            (oif_entry->remote_dst_ip) & 0xFF);
        }
        
        len += snprintf(buffer + len, buff_size - len, " ");  // Add space after each interface
    } ITERATE_GLTHREAD_END(&mac_table_entry->oif_list, curr);
    
    assert (len <= buff_size); 
    return buffer;
}

void
show_mac_table(mac_table_t *mac_table, uint16_t vlan_id) {

    int count = 0;
    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    char buffer[1024];  // Generous buffer for dynamic interface list

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

/* Dynamic OIF list management functions */

mac_oif_entry_t *
mac_oif_entry_create(dp_intf_t * oif, uint32_t remote_dst_ip) {
    mac_oif_entry_t *oif_entry = new mac_oif_entry_t;
    oif_entry->oif = oif;
    oif_entry->remote_dst_ip = remote_dst_ip;
    init_glthread(&oif_entry->glue);
    return oif_entry;
}

void 
mac_oif_entry_destroy(mac_oif_entry_t *oif_entry) {
    if (oif_entry) {
        remove_glthread(&oif_entry->glue);
        delete oif_entry;
    }
}

bool 
mac_table_entry_add_oif(mac_table_entry_t *mac_entry, dp_intf_t * oif, uint32_t remote_dst_ip) {
    if (!mac_entry || !oif) return false;
    
    /* Check if this interface with this remote IP already exists */
    mac_oif_entry_t *existing = mac_table_entry_find_oif(mac_entry, oif->port_id, remote_dst_ip);
    if (existing) {
        return false; /* Already exists */
    }
    
    /* Create and add new OIF entry */
    mac_oif_entry_t *oif_entry = mac_oif_entry_create(oif, remote_dst_ip);
    glthread_add_next(&mac_entry->oif_list, &oif_entry->glue);
    return true;
}

bool 
mac_table_entry_remove_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip) {
    if (!mac_entry) return false;
    
    mac_oif_entry_t *oif_entry = mac_table_entry_find_oif(mac_entry, ifindex, remote_dst_ip);
    if (oif_entry) {
        mac_oif_entry_destroy(oif_entry);
        return true;
    }
    return false;
}

mac_oif_entry_t *
mac_table_entry_find_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip) {
    if (!mac_entry) return NULL;
    
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;
    
    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        if (oif_entry->oif && 
            oif_entry->oif->port_id== ifindex && 
            oif_entry->remote_dst_ip == remote_dst_ip) {
            return oif_entry;
        }
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);
    
    return NULL;
}

bool 
mac_table_entry_has_oifs(mac_table_entry_t *mac_entry) {
    if (!mac_entry) return false;
    return !IS_GLTHREAD_LIST_EMPTY(&mac_entry->oif_list);
}

void 
mac_table_entry_clear_oifs(mac_table_entry_t *mac_entry) {
    if (!mac_entry) return;
    
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;
    
    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        mac_oif_entry_destroy(oif_entry);
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);
}
