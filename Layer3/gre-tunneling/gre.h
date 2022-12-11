#ifndef __GRESTRUCT__
#define __GRESTRUCT__

#include <stdint.h>
#include <stdbool.h>

#include "../../graph.h"
typedef struct pkt_block_ pkt_block_t;

typedef enum gre_tunne_cfg_flags_ {

    gre_tunnel_config_id = 1,
    gre_tunnel_config_local_ip = 2,
    gre_tunnel_config_local_mask = 4,
    gre_tunnel_config_src_ip = 8,
    gre_tunnel_config_src_if_name = 16,
    gre_tunnel_config_end_ip = 32
} gre_tunne_cfg_flags_t;


typedef struct gre_tunnel_config_ {

    uint32_t id;
    uint32_t local_ip;
    uint8_t local_mask;
    union {
        uint32_t tunnel_src_ip;
        byte ifname[IF_NAME_SIZE];
    }u;
    uint32_t tunnel_end_ip;
} gre_tunnel_config_t;

typedef struct gre_tunnel_data_ {

    uint8_t config_flags;
    uint32_t src_ip;
    gre_tunnel_config_t cli_config;
    bool active;
} gre_tunnel_data_t;

bool
gre_tunnel_activate (node_t *node, Interface *tunnel_intf);

void
gre_tunnel_deactivate (node_t *node, Interface *tunnel_intf);

void
gre_tunnel_send_pkt_out (node_t *node, Interface *tunnel_intf, pkt_block_t *pkt_block);

#endif 
