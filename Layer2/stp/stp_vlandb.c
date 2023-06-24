/*
 * =====================================================================================
 *
 *       Filename:  stp_vlandb.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/28/2021 12:46:18 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "../../tcp_public.h"
#include "stp_vlandb.h"

static int
stp_vlan_node_comp_fn(const avltree_node_t *node1,
					  const avltree_node_t *node2) {

	stp_vlan_node_t *vlan_node1;
	stp_vlan_node_t *vlan_node2;

	vlan_node1 = avltree_container_of(node1, stp_vlan_node_t, glue);
	vlan_node2 = avltree_container_of(node2, stp_vlan_node_t, glue);

	return vlan_node1->vlan_id - vlan_node2->vlan_id;	
}

static int
stp_vlan_intf_node_comp_fn(
					const avltree_node_t *node1,
					const avltree_node_t *node2) {

	stp_vlan_intf_node_t *stp_vlan_intf_node1;
	stp_vlan_intf_node_t *stp_vlan_intf_node2;

	stp_vlan_intf_node1 = avltree_container_of(node1, stp_vlan_intf_node_t, glue);
	stp_vlan_intf_node2 = avltree_container_of(node2, stp_vlan_intf_node_t, glue);
	
	return (stp_vlan_intf_node1->ifindex - stp_vlan_intf_node2->ifindex);
}

avltree_t *
stp_get_vlan_db_root(node_t *node) {

	stp_node_info_t *stp_node_info = node->node_nw_prop.stp_node_info;

	if (!stp_node_info) {
		return NULL;
	}

	avltree_t *vlan_db_root = &stp_node_info->vlan_db;
	return vlan_db_root;
}

void
stp_init_vlan_db(node_t *node) {

	avltree_t *vlan_db_root = stp_get_vlan_db_root(node);
	avltree_init(vlan_db_root, stp_vlan_node_comp_fn);
}

stp_vlan_node_t *
stp_lookup_vlan_node(node_t *node,
					 uint32_t vlan_id) {
	
	stp_vlan_node_t stp_vlan_node_template;

	avltree_t *vlan_db_root = stp_get_vlan_db_root(node);

	if (!vlan_db_root) return NULL;

	memset(&stp_vlan_node_template, 0, sizeof(stp_vlan_node_template));

	stp_vlan_node_template.vlan_id = vlan_id;

	avltree_node_t *avltree_node = avltree_lookup(
									&stp_vlan_node_template.glue,
									vlan_db_root);									

	if (!avltree_node) return NULL;

	return avltree_container_of(avltree_node, stp_vlan_node_t, glue);	
}

void
stp_insert_vlan_node(node_t *node,
					 stp_vlan_node_t *stp_vlan_node) {

	memset(&stp_vlan_node->glue, 0,
			sizeof(stp_vlan_node->glue));

	avltree_init(&stp_vlan_node->intf_avl_root,
					stp_vlan_intf_node_comp_fn);
	avltree_insert(&stp_vlan_node->glue,
					stp_get_vlan_db_root(node));
}

static void
stp_insert_vlan_intf_node(stp_vlan_node_t *stp_vlan_node,
						  stp_vlan_intf_node_t *stp_vlan_intf_node) {

#if 0
	if (AVL_TREE_IS_NODE_ON_TREE(&stp_vlan_intf_node->glue)) {
		assert(0);
	}
#endif
	avltree_insert(&stp_vlan_intf_node->glue, &stp_vlan_node->intf_avl_root);	
	stp_vlan_intf_node->stp_vlan_node = stp_vlan_node;
}


stp_vlan_intf_node_t *
stp_lookup_vlan_intf_node_under_vlan(node_t *node,
								uint32_t vlan_id,
								uint16_t ifindex) {

	stp_vlan_node_t *stp_vlan_node = 
				stp_lookup_vlan_node(node, vlan_id);

	if (!stp_vlan_node) return NULL;

	avltree_t *per_vlan_intf_tree = &stp_vlan_node->intf_avl_root;

	if (!per_vlan_intf_tree) return NULL;

	stp_vlan_intf_node_t stp_vlan_intf_node_template;
	memset(&stp_vlan_intf_node_template, 0, sizeof(stp_vlan_intf_node_template));
	
	stp_vlan_intf_node_template.ifindex = ifindex;
	
	avltree_node_t *avltree_node = avltree_lookup(
									&stp_vlan_intf_node_template.glue,
									per_vlan_intf_tree);
	
	if (!avltree_node) return NULL;

	return avltree_container_of(avltree_node, stp_vlan_intf_node_t, glue);
}

stp_vlan_intf_info_t *
stp_lookup_vlan_intf_info(node_t *node,
						  uint32_t vlan_id,
						  uint16_t ifindex) {

	stp_vlan_intf_node_t *stp_vlan_intf_node =
			stp_lookup_vlan_intf_node_under_vlan(
					node, vlan_id, ifindex);

	if (!stp_vlan_intf_node) return NULL;

	return stp_vlan_intf_node->stp_vlan_intf_info;
}

/* Intf DB mgmt APIs */

static int
stp_intf_node_comp_fn(const avltree_node_t *node1,
					  const avltree_node_t *node2) {

	stp_intf_node_t *intf_node1;
	stp_intf_node_t *intf_node2;

	intf_node1 = avltree_container_of(node1, stp_intf_node_t, glue);
	intf_node2 = avltree_container_of(node2, stp_intf_node_t, glue);

	return intf_node1 - intf_node2;
}

static int
stp_intf_vlan_node_comp_fn(const avltree_node_t *node1,
						   const avltree_node_t *node2) {


	stp_intf_vlan_node_t *stp_intf_vlan_node1;
	stp_intf_vlan_node_t *stp_intf_vlan_node2;

	stp_intf_vlan_node1 = avltree_container_of(node1,
												stp_intf_vlan_node_t, glue);

	stp_intf_vlan_node2 = avltree_container_of(node2,
												stp_intf_vlan_node_t, glue);

	return stp_intf_vlan_node1->vlan_id - stp_intf_vlan_node2->vlan_id;
}

avltree_t *
stp_get_intf_db_root(node_t *node) {

	stp_node_info_t *stp_node_info = node->node_nw_prop.stp_node_info;

	if (!stp_node_info) {
		return NULL;
	}

	avltree_t *intf_db_root = &stp_node_info->intf_db;
	return intf_db_root;
}

void
stp_init_intf_db(node_t *node) {

	avltree_t *intf_db_root = stp_get_intf_db_root(node);
	avltree_init(intf_db_root, stp_intf_node_comp_fn);
}

stp_intf_node_t *
stp_lookup_intf_node(node_t *node, uint16_t ifindex) {

	stp_intf_node_t stp_intf_node_template;

	 avltree_t *intf_db_root = stp_get_intf_db_root(node);

	if (!intf_db_root) return NULL;

	memset(&stp_intf_node_template, 0, sizeof(stp_intf_node_t));

	stp_intf_node_template.ifindex = ifindex;
	
	avltree_node_t *avltree_node = avltree_lookup(
									&stp_intf_node_template.glue,
									intf_db_root);

	if (!avltree_node) return NULL;

	return  avltree_container_of(avltree_node, stp_intf_node_t, glue);
	
}

void
stp_insert_intf_node(node_t *node,
					 stp_intf_node_t *stp_intf_node) {

	memset(&stp_intf_node->glue, 0,
			sizeof(stp_intf_node->glue));

	avltree_init(&stp_intf_node->vlan_avl_root,
					stp_intf_vlan_node_comp_fn);

	avltree_insert(&stp_intf_node->glue,
					stp_get_intf_db_root(node));
}

static void
stp_insert_intf_vlan_node(stp_intf_node_t *stp_intf_node,
						  stp_intf_vlan_node_t *stp_intf_vlan_node) {

#if 0
	if (AVL_TREE_IS_NODE_ON_TREE(&stp_intf_vlan_node->glue)) {
		assert(0);
	}
#endif

	avltree_insert(&stp_intf_vlan_node->glue, &stp_intf_node->vlan_avl_root);
	stp_intf_vlan_node->stp_intf_node = stp_intf_node;
}

stp_intf_vlan_node_t *
stp_lookup_intf_vlan_node_under_intf(node_t *node,
									 uint32_t vlan_id,
									 uint16_t ifindex) {

	stp_intf_node_t *stp_intf_node =
			stp_lookup_intf_node(node, ifindex);

	if (!stp_intf_node) return NULL;

	avltree_t *per_intf_vlan_tree = &stp_intf_node->vlan_avl_root;

	if (!per_intf_vlan_tree) return NULL;

	stp_intf_vlan_node_t stp_intf_vlan_node_template;
	memset(&stp_intf_vlan_node_template, 0, sizeof(stp_intf_vlan_node_t));

	stp_intf_vlan_node_template.vlan_id = vlan_id;

	avltree_node_t *avltree_node = avltree_lookup(
									&stp_intf_vlan_node_template.glue,
									per_intf_vlan_tree);

	if (!avltree_node) return NULL;

	return avltree_container_of(avltree_node, stp_intf_vlan_node_t, glue);
}

static void
stp_print_vlan_intf_info(stp_vlan_intf_info_t *stp_vlan_intf_info) {


}

void
stp_print_vlan_db(node_t *node, 
				  uint32_t vlan_id,
				  uint16_t ifindex) {
	
	avltree_t *avltree;
	avltree_t *avltree2;
	avltree_node_t *curr;
	avltree_node_t *curr2;
	stp_vlan_node_t *stp_vlan_node;
	stp_intf_node_t *stp_intf_node;
	stp_vlan_intf_node_t *stp_vlan_intf_node;
	stp_intf_vlan_node_t *stp_intf_vlan_node;
	stp_vlan_intf_info_t *stp_vlan_intf_info;

	cprintf("STP Vlan DB\n");

	if (vlan_id && ifindex ) {

		stp_vlan_intf_info =
			stp_lookup_vlan_intf_info(node, vlan_id, ifindex);	

		if (stp_vlan_intf_info) {
			stp_print_vlan_intf_info(stp_vlan_intf_info);
		}
		return;
	}

	else if (vlan_id && !ifindex) {

		stp_vlan_node =
			stp_lookup_vlan_node(node, vlan_id);

		if (!stp_vlan_node ) return;

		avltree = &stp_vlan_node->intf_avl_root;

		if (avltree_is_empty(avltree)) return;
	
		ITERATE_AVL_TREE_BEGIN(avltree, curr) {

			stp_vlan_intf_node = avltree_container_of(
										curr, stp_vlan_intf_node_t, glue);

			if (stp_vlan_intf_node->stp_vlan_intf_info) {
				
				stp_print_vlan_intf_info(stp_vlan_intf_node->stp_vlan_intf_info);
			}	
		} ITERATE_AVL_TREE_END;
	}

	else if (!vlan_id && ifindex) {

		stp_intf_node =
			stp_lookup_intf_node(node, ifindex);

		if (!stp_intf_node ) return;

		avltree = &stp_intf_node->vlan_avl_root;

		if (avltree_is_empty(avltree)) return;
	
		ITERATE_AVL_TREE_BEGIN(avltree, curr) {

			stp_intf_vlan_node = avltree_container_of(
									curr, stp_intf_vlan_node_t, glue);

			if (stp_intf_vlan_node->stp_vlan_intf_info) {
				
				stp_print_vlan_intf_info(stp_intf_vlan_node->stp_vlan_intf_info);
			}	
		} ITERATE_AVL_TREE_END;
	}

	else {
	
		avltree = stp_get_vlan_db_root(node);
	
		ITERATE_AVL_TREE_BEGIN(avltree, curr) {

			stp_vlan_node = avltree_container_of(curr,
								stp_vlan_node_t, glue);

			avltree2 = &stp_vlan_node->intf_avl_root;

			ITERATE_AVL_TREE_BEGIN(avltree2, curr2) {

				stp_vlan_intf_node =
					avltree_container_of(curr2, stp_vlan_intf_node_t, glue);

				if (stp_vlan_intf_node->stp_vlan_intf_info) {

					stp_print_vlan_intf_info(stp_vlan_intf_node->stp_vlan_intf_info);	
				}
			} ITERATE_AVL_TREE_END;

		} ITERATE_AVL_TREE_END;	
	}	
}

bool
stp_create_update_vlan_intf_info(
			node_t *node,
			uint32_t vlan_id,
			uint16_t ifindex,
			stp_vlan_intf_info_t *stp_vlan_intf_info_template) {

	stp_vlan_intf_info_t *stp_vlan_intf_info;

	stp_vlan_node_t *stp_vlan_node = 
						stp_lookup_vlan_node(node, vlan_id);

	if (!stp_vlan_node) {

		stp_vlan_node = calloc(1, sizeof(stp_vlan_node_t));
		stp_vlan_node->vlan_id = vlan_id;
		stp_insert_vlan_node(node, stp_vlan_node);		
	}

	stp_vlan_intf_node_t *stp_vlan_intf_node =
		stp_lookup_vlan_intf_node_under_vlan(node, vlan_id, ifindex);			

	if (!stp_vlan_intf_node) {

		stp_vlan_intf_node =
						calloc(1, sizeof(stp_vlan_intf_node_t));
		stp_vlan_intf_node->ifindex = ifindex;
		stp_insert_vlan_intf_node(stp_vlan_node, stp_vlan_intf_node);
	}

	stp_vlan_intf_info = stp_vlan_intf_node->stp_vlan_intf_info;

	if (!stp_vlan_intf_info) {

		stp_vlan_intf_node->stp_vlan_intf_info = calloc(1,
					sizeof(stp_vlan_intf_info_t));
		
		stp_vlan_intf_info = stp_vlan_intf_node->stp_vlan_intf_info;
		stp_vlan_intf_info->stp_vlan_intf_node = stp_vlan_intf_node;
	}

	if (stp_byte_cmp_stp_vlan_intf_info(stp_vlan_intf_info_template,
										stp_vlan_intf_info)) {
		return false;
	}	
	
	stp_copy_vlan_intf_info(stp_vlan_intf_info_template, stp_vlan_intf_info);

	/* Fix up the Reverse Lookup Trees now */	
	stp_intf_node_t *stp_intf_node;
	stp_intf_vlan_node_t *stp_intf_vlan_node;

	stp_intf_node = stp_lookup_intf_node(node, ifindex); 
	
	if (!stp_intf_node) {

		stp_intf_node = calloc(1, sizeof(stp_intf_node_t));
		stp_intf_node->ifindex = ifindex;
		stp_insert_intf_node(node, stp_intf_node);	
	}

	stp_intf_vlan_node = stp_lookup_intf_vlan_node_under_intf(node,
							vlan_id, ifindex);

	if (!stp_intf_vlan_node) {

		stp_intf_vlan_node = calloc(1, sizeof(stp_intf_vlan_node_t));
		stp_intf_vlan_node->vlan_id = vlan_id;
		stp_insert_intf_vlan_node(stp_intf_node, stp_intf_vlan_node);	
	}

	stp_vlan_intf_info = stp_intf_vlan_node->stp_vlan_intf_info;

	if (!stp_vlan_intf_info) {

		stp_intf_vlan_node->stp_vlan_intf_info =
				stp_vlan_intf_node->stp_vlan_intf_info;
		stp_vlan_intf_info = stp_intf_vlan_node->stp_vlan_intf_info;
		stp_vlan_intf_info->stp_intf_vlan_node = stp_intf_vlan_node;
	}

	assert(stp_intf_vlan_node->stp_vlan_intf_info ==
			stp_intf_vlan_node->stp_vlan_intf_info);

	return true;
}

bool
stp_byte_cmp_stp_vlan_intf_info (
    stp_vlan_intf_info_t *info1,
    stp_vlan_intf_info_t *info2) {

	return true;
}

void
stp_copy_vlan_intf_info (
    stp_vlan_intf_info_t *src,
    stp_vlan_intf_info_t *dst) {


}

