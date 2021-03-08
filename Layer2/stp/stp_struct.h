/*
 * =====================================================================================
 *
 *       Filename:  stp_struct.h
 *
 *    Description: This file defines the structures to be used for STP 
 *
 *        Version:  1.0
 *        Created:  02/28/2021 05:09:08 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __STP_STRUCT__
#define __STP_STRUCT__

#define STP_CONFIG_BPDU	123
#define DEFAULT_BRIDGE_PRIORITY	32768


typedef enum {

	STP_PORT_STATE_INITIALIZING,
	STP_PORT_STATE_BLOCKED,
	STP_PORT_STATE_LISTENING,
	STP_PORT_STATE_LEARNING,
	STP_PORT_STATE_FORWARING,
	STP_PORT_STATE_DISABLED,
	STP_PORT_STATE_STATE_MAX
} stp_port_state_t;

typedef enum {

	STP_PORT_ROLE_DESIGNATED,
	STP_PORT_ROLE_NON_DESIGNATED,
	STP_PORT_ROLE_ALTERNATE = STP_PORT_ROLE_NON_DESIGNATED,
	STP_PORT_ROLE_ROOT,
	STP_PORT_ROLE_BACKUP,
	STP_PORT_ROLE_MAX
} stp_port_role_t;

#pragma pack (push,1)

typedef struct stp_id_ {

	uint16_t priority;
	mac_add_t mac_add;
} stp_id_t;

typedef struct bpdu_fmt_ {

	char llc[3];
	uint16_t proto;
	uint8_t version;
	uint8_t type;
	uint8_t flags;
	stp_id_t root_id;
	uint32_t root_cost;
	/* Universally Administered Addresses, Assigned by
 	 * the manufacturing vendor*/
	stp_id_t bridge_id;
	uint16_t pid;
	uint16_t msg_age;
	uint16_t max_age;
	uint16_t hello_timer;
	uint16_t forward_delay;
} bpdu_fmt_t;
#pragma pack(pop)

typedef struct stp_vlan_intf_node_ stp_vlan_intf_node_t;
typedef struct stp_intf_vlan_node_ stp_intf_vlan_node_t;

/*
 * Each instance need to maintain per vlan per interface
 */
typedef struct stp_vlan_intf_info_ {

	bool is_enabled;
	/* Every port need to have a priority */
	uint16_t priority;
	uint32_t stp_cost;
	/* Most recent bpdu cached on this interface */
	bpdu_fmt_t *peer_config_bpdu;
	/*Local BPDU send out of this interface*/
	bpdu_fmt_t *local_config_bpdu;
	/* Set to true if STP config is changed since the
 	 * last time bpdu was recvd on this interface */
	bool stp_config_changed;

	/* Back pointers */
	stp_vlan_intf_node_t *stp_vlan_intf_node;
	stp_intf_vlan_node_t *stp_intf_vlan_node;
} stp_vlan_intf_info_t;

typedef struct stp_node_ {

	bool is_enabled;

	/* Begin : Local information */

	/* Every bridge node need to have a priority */
	uint16_t priority;
	/* Mac Addr assigned to this bridge, priority and
 	 * mac address combines to derive bridge id*/
	mac_add_t mac_add;

	/* End : Local Information */

	/* Begin : Root Bridge Election Result */

	/* Elected root port, a bridge can have only one
 	 * root port at any given point of time. It will
 	 * be NULL if this bridge itself is a root bridge.
 	 * STP root bridges do not have root port*/
	interface_t *root_port;
	/* Elected root bridge id */
	stp_id_t root_bridge_id;
	uint32_t root_path_cost;	

	/* End : Root Bridge Election Result */

	/* Valid only for root bridge, generate BPDUs and
	 * emit out of all designated ports*/
	wheel_timer_elem_t *bpdu_generation_wt_elem;

	/* stp vlan intf db */
	avltree_t vlan_db;
	avltree_t intf_db;
} stp_node_info_t;

bool
stp_byte_cmp_stp_vlan_intf_info (
	stp_vlan_intf_info_t *info1,
	stp_vlan_intf_info_t *info2);

void
stp_copy_vlan_intf_info (
	stp_vlan_intf_info_t *src,
	stp_vlan_intf_info_t *dst);

#endif /* __STP_STRUCT__  */
