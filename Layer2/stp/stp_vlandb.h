/*
 * =====================================================================================
 *
 *       Filename:  stp_vlandb.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/28/2021 12:41:02 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __STP_VLANDB__
#define __STP_VLANDB__

#include "stp_struct.h"

typedef struct stp_vlan_config_{
	
} stp_vlan_config_t;

typedef struct stp_vlan_node_ stp_vlan_node_t;
typedef struct stp_vlan_intf_node_{

	uint16_t ifindex;	/* key */
	stp_vlan_intf_info_t *stp_vlan_intf_info;
	stp_vlan_node_t *stp_vlan_node;
	avltree_node_t glue;
} stp_vlan_intf_node_t;

struct stp_vlan_node_{

	uint16_t vlan_id;	/* key */
	stp_vlan_config_t *stp_vlan_config;
	avltree_t intf_avl_root;
	avltree_node_t glue;
};

void
stp_init_vlan_db(node_t *node);

avltree_t *
stp_get_vlan_db_root(node_t *node);

stp_vlan_node_t *
stp_lookup_vlan_node(node_t *node,
                     uint32_t vlan_id);

stp_vlan_intf_node_t *
stp_lookup_vlan_intf_node_under_vlan(node_t *node,
                                uint32_t vlan_id,
                                uint16_t ifindex);

stp_vlan_intf_info_t *
stp_lookup_vlan_intf_info(node_t *node,
                          uint32_t vlan_id,
                          uint16_t ifindex);

void
stp_insert_vlan_node(node_t *node,
                     stp_vlan_node_t *stp_vlan_node);


typedef struct stp_intf_node_ stp_intf_node_t;

/* For reverse lookup */
typedef struct stp_intf_vlan_node_{

	uint16_t vlan_id;   /*  key */
	stp_vlan_intf_info_t *stp_vlan_intf_info;
	stp_intf_node_t *stp_intf_node;
	avltree_node_t glue;
} stp_intf_vlan_node_t;

typedef struct stp_intf_config_{
	
} stp_intf_config_t;

struct stp_intf_node_{

	uint16_t ifindex;   /*  key */
	stp_intf_config_t *stp_intf_config;
	avltree_t vlan_avl_root;
 	avltree_node_t glue;
} ;

avltree_t *
stp_get_intf_db_root(node_t *node);

void
stp_init_intf_db(node_t *node);

stp_intf_node_t *
stp_lookup_intf_node(node_t *node, uint16_t ifindex);

void
stp_insert_intf_node(node_t *node,
					 stp_intf_node_t *stp_intf_node);

stp_intf_vlan_node_t *
stp_lookup_intf_vlan_node_under_intf(node_t *node,
					 uint32_t vlan_id,
					 uint16_t ifindex);

void
stp_print_vlan_db(node_t *node,
                  uint32_t vlan_id,
                  uint16_t ifindex);

bool
stp_create_update_vlan_intf_info(
            node_t *node,
            uint32_t vlan_id,
            uint16_t ifindex,
            stp_vlan_intf_info_t *stp_vlan_intf_info_template);

bool
stp_byte_cmp_stp_vlan_intf_info (
    stp_vlan_intf_info_t *info1,
    stp_vlan_intf_info_t *info2);

void
stp_copy_vlan_intf_info (
    stp_vlan_intf_info_t *src,
    stp_vlan_intf_info_t *dst);

#endif /* __STP_VLANDB__ */
