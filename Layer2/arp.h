#ifndef __ARP__HDR__
#define __ARP__HDR__

#pragma pack (push,1)
typedef struct arp_hdr_{

    short hw_type;          /*1 for ethernet cable*/
    short proto_type;       /*0x0800 for IPV4*/
    char hw_addr_len;       /*6 for MAC*/
    char proto_addr_len;    /*4 for IPV4*/
    short op_code;          /*req or reply*/
    mac_add_t src_mac;      /*MAC of OIF interface*/
    uint32_t src_ip;    /*IP of OIF*/
    mac_add_t dst_mac;      /*?*/
    uint32_t dst_ip;        /*IP for which ARP is being resolved*/
} arp_hdr_t;
#pragma pack(pop)

void
send_arp_broadcast_request(node_t *node, 
                           interface_t *oif, 
                           char *ip_addr);

/*ARP Table APIs*/
typedef struct arp_table_{

    glthread_t arp_entries;
} arp_table_t;

typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef struct arp_entry_ arp_entry_t;
typedef void (*arp_processing_fn)(node_t *, 
                                  interface_t *oif,
                                  arp_entry_t *, 
                                  arp_pending_entry_t *);
struct arp_pending_entry_{

    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    uint32_t pkt_size;  /*Including ether net hdr*/
    char pkt[0];
};
GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry, \
    arp_pending_entry_t, arp_pending_entry_glue);


struct arp_entry_{

    ip_add_t ip_addr;   /*key*/
    mac_add_t mac_addr;
    char oif_name[IF_NAME_SIZE];
    glthread_t arp_glue;
    bool is_sane;
    /* List of packets which are pending for
     * this ARP resolution*/
    glthread_t arp_pending_list;
    uint16_t proto;
    long long unsigned int hit_count;
	wheel_timer_elem_t *exp_timer_wt_elem;
};
GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, arp_entry_t, arp_glue);
GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);

#define IS_ARP_ENTRIES_EQUAL(arp_entry_1, arp_entry_2)  \
    (strncmp(arp_entry_1->ip_addr.ip_addr, arp_entry_2->ip_addr.ip_addr, 16) == 0 && \
        strncmp(arp_entry_1->mac_addr.mac, arp_entry_2->mac_addr.mac, 6) == 0 && \
        strncmp(arp_entry_1->oif_name, arp_entry_2->oif_name, IF_NAME_SIZE) == 0 && \
        arp_entry_1->is_sane == arp_entry_2->is_sane &&     \
        arp_entry_1->is_sane == false && \
        arp_entry_1->proto == arp_entry_2->proto)

void
init_arp_table(arp_table_t **arp_table);

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, char *ip_addr);

void
clear_arp_table(arp_table_t *arp_table);

wheel_timer_elem_t *
arp_entry_create_expiration_timer(
		node_t *node,
		arp_entry_t *arp_entry,
		uint16_t exp_time);

void
arp_entry_delete_expiration_timer(
		arp_entry_t *arp_entry);

void
arp_entry_refresh_expiration_timer(
		arp_entry_t *arp_entry);

uint16_t
arp_entry_get_exp_time_left(arp_entry_t *arp_entry);

void
delete_arp_entry(arp_entry_t *arp_entry);

void
arp_entry_delete(node_t *node, char *ip_addr, uint16_t proto);

bool
arp_table_entry_add(node_t *node,
					arp_table_t *arp_table,
					arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list);
                   

void
show_arp_table(arp_table_t *arp_table);

void
arp_table_update_from_arp_reply(arp_table_t *arp_table,
                                arp_hdr_t *arp_hdr, interface_t *iif);


void
add_arp_pending_entry(arp_entry_t *arp_entry, 
                        arp_processing_fn, 
                        char *pkt, 
                        uint32_t pkt_size); 

void
create_arp_sane_entry(node_t *node,
					  arp_table_t *arp_table,
					  char *ip_addr,
                      char *pkt, uint32_t pkt_size);

static bool 
arp_entry_sane(arp_entry_t *arp_entry){

    return arp_entry->is_sane;
}

void
process_arp_broadcast_request(node_t *node, interface_t *iif, 
                                                    ethernet_hdr_t *ethernet_hdr);

void
process_arp_reply_msg(node_t *node, interface_t *iif,
                                        ethernet_hdr_t *ethernet_hdr);

/* ARP Table Public APIs to be exposed to applications */

bool
arp_entry_add(node_t *node, char *ip_addr, mac_add_t mac, interface_t *oif, uint16_t proto);

#endif
