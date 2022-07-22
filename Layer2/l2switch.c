#include <stdlib.h>
#include <stdio.h>
#include "../graph.h"
#include "layer2.h"
#include "../gluethread/glthread.h"
#include "../comm.h"

/*L2 Switch Owns Mac Table*/

typedef struct mac_table_entry_{

    mac_add_t mac;
    char oif_name[IF_NAME_SIZE];
    glthread_t mac_entry_glue;
} mac_table_entry_t;
GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, mac_table_entry_t, mac_entry_glue);


typedef struct mac_table_{

    glthread_t mac_entries;
} mac_table_t;

void
init_mac_table(mac_table_t **mac_table){

    *mac_table = calloc(1, sizeof(mac_table_t));
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, char *mac){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if(strncmp(mac_table_entry->mac.mac, mac, sizeof(mac_add_t)) == 0){
            return mac_table_entry;
        }
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    return NULL;
}

void
clear_mac_table(mac_table_t *mac_table){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){
        
        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        remove_glthread(curr);
        free(mac_table_entry);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

void
delete_mac_table_entry(mac_table_t *mac_table, char *mac){

    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    free(mac_table_entry);
}

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (strncmp(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_add_t)) == 0 && \
            strncmp(mac_entry_1->oif_name, mac_entry_2->oif_name, IF_NAME_SIZE) == 0)


bool_t
mac_table_entry_add(mac_table_t *mac_table, mac_table_entry_t *mac_table_entry){

    mac_table_entry_t *mac_table_entry_old = mac_table_lookup(mac_table,
            mac_table_entry->mac.mac);

    if(mac_table_entry_old &&
            IS_MAC_TABLE_ENTRY_EQUAL(mac_table_entry_old, mac_table_entry)){

        return FALSE;
    }

    if(mac_table_entry_old){
        delete_mac_table_entry(mac_table, mac_table_entry_old->mac.mac);
    }

    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);
    return TRUE;
}

void
dump_mac_table(mac_table_t *mac_table){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        printf("\tMAC : %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX  | Intf : %s\n", 
            mac_table_entry->mac.mac[0], 
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3], 
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_table_entry->oif_name);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}


static void
l2_switch_perform_mac_learning(node_t *node, char *src_mac, char *if_name){

    mac_table_t *mac_table = node ->node_nw_prop.mac_table;
    mac_table_entry_t *mac_entry = mac_table_lookup(mac_table, src_mac);
    if(mac_entry) return;

    mac_table_entry_t *mac_new_entry = malloc(sizeof(mac_table_entry_t));
    memset(mac_new_entry ->mac.mac, 0, MAC_LEN);
    memcpy(mac_new_entry ->mac.mac, src_mac, MAC_LEN);
    memset(mac_new_entry ->oif_name, 0, IF_NAME_SIZE);
    memcpy(mac_new_entry ->oif_name, if_name, IF_NAME_SIZE);
    mac_new_entry ->mac_entry_glue.left = NULL;
    mac_new_entry ->mac_entry_glue.right = NULL;
    mac_table_entry_add(mac_table, mac_new_entry);
    
}

static void
l2_switch_forward_frame(node_t *node, interface_t *recv_intf, 
                        ethernet_hdr_t *ethernet_hdr, 
                        unsigned int pkt_size){

    /*If dst mac is broadcast mac, then flood the frame*/
    if(IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        l2_switch_flood_pkt_out(node, recv_intf, (char *)ethernet_hdr, pkt_size);
        return;
    }

    /*Check the mac table to forward the frame*/
    mac_table_entry_t *mac_table_entry = 
        mac_table_lookup(NODE_MAC_TABLE(node), ethernet_hdr->dst_mac.mac);

    if(!mac_table_entry){
        l2_switch_flood_pkt_out(node, recv_intf, (char *)ethernet_hdr, pkt_size);
        return;
    }

    char *oif_name = mac_table_entry->oif_name;
    interface_t *oif = get_node_if_by_name(node, oif_name);

    if(!oif){
        return;
    }

    send_pkt_out((char *)ethernet_hdr, pkt_size, oif);
}
void
l2_switch_recv_frame(interface_t *interface, 
                     char *pkt, unsigned int pkt_size){

    node_t *node = interface->att_node;

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;

    char *dst_mac = (char *)ethernet_hdr->dst_mac.mac;
    char *src_mac = (char *)ethernet_hdr->src_mac.mac;

    l2_switch_perform_mac_learning(node, src_mac, interface->if_name);
    l2_switch_forward_frame(node, interface, ethernet_hdr, pkt_size);
}
