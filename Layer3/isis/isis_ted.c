#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_ted.h"
#include "isis_tlv_struct.h"

extern int
avltree_prefix_tree_comp_fn(const avltree_node_t *n1, const avltree_node_t *n2) ;
extern int
avltree_v6prefix_tree_comp_fn(const avltree_node_t *n1, const avltree_node_t *n2) ;
extern isis_srv6_config_t *
isis_srv6_get_config(isis_node_info_t *node_info) ;

void
isis_ted_update_or_install_lsp (isis_node_info_t *node_info, ted_db_t *ted_db, isis_lsp_pkt_t *lsp_pkt) {

    uint16_t n_tlv22;
    uint32_t metric;
    uint16_t subtlv_len;
    tlv22_hdr_t *tlv22_hdr;
    byte *subtlv_navigator;
    isis_system_id_t system_id;
    avltree_t *prefix_tree_root = NULL;
    avltree_t *v6prefix_tree_root = NULL;
    avltree_t *srv6prefixsid_tree_root = NULL;
    byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

    /* Node-SID TLV(149) is a standalone top level TLV, its target prefix
        may be scanned before or after this TLV appears in the LSP - stash
        it here and reconcile against prefix_tree_root once the TLV walk
        is done */
    bool node_sid_present = false;
    uint32_t node_sid_prefix = 0;
    uint8_t node_sid_prefix_len = 0;
    uint32_t node_sid_index = 0;
    uint8_t node_sid_flags = 0;
   
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    uint16_t eth_payload_size = lsp_pkt->pkt_size - sizeof(ethernet_hdr_t) - ETH_FCS_SIZE;

    byte *tlv_buffer = (byte *)(lsp_pkt_hdr + 1);

    uint16_t tlv_buff_size = eth_payload_size - sizeof(isis_pkt_hdr_t);

    n_tlv22 = isis_count_tlv_occurrences(tlv_buffer, (pkt_size_t)tlv_buff_size, ISIS_IS_REACH_TLV);

    ted_template_node_data_t *node_data = (ted_template_node_data_t *)
        XCALLOC_BUFF(0, sizeof(ted_template_node_data_t) +
                            (n_tlv22 * sizeof(ted_template_nbr_data_t)));

    node_data->flags = lsp_pkt_hdr->flags;
    node_data->rtr_id = lsp_pkt_hdr->rtr_id;
    node_data->pn_no = lsp_pkt_hdr->pn_no;
    node_data->fr_no = lsp_pkt_hdr->fr_no;
    node_data->seq_no = lsp_pkt_hdr->seq_no;

    ted_template_nbr_data_t *nbr_data;
    byte tlv_type, tlv_len, *tlv_value = NULL;
    int nbr_index = 0;

    ITERATE_TLV_BEGIN(tlv_buffer, tlv_type,
                      tlv_len, tlv_value, tlv_buff_size) {

        switch (tlv_type) {

        case ISIS_TLV_HOSTNAME:
            string_copy((char *)node_data->node_name, tlv_value, tlv_len);
            break;
        case ISIS_IS_REACH_TLV:
            nbr_data = &node_data->nbr_data[nbr_index];
            nbr_index++;
            tlv22_hdr = (tlv22_hdr_t *)tlv_value;
            system_id = tlv22_hdr->system_id;
            metric = htonl(tlv22_hdr->metric);
            subtlv_len = tlv22_hdr->subtlv_len;

            nbr_data->nbr_rtr_id = system_id.rtr_id;
            nbr_data->nbr_pn_no = system_id.pn_id;
            nbr_data->metric = metric;

            subtlv_navigator = tlv_value + sizeof (tlv22_hdr_t );

            /* Now Read the Sub TLVs */
            ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                              tlv_len2, tlv_value2, subtlv_len) {

                switch (tlv_type2)
                {
                case ISIS_TLV_IF_INDEX:
                    if (tlv_len2 >= 2 * sizeof(uint32_t)) {
                        nbr_data->local_if_index = htonl(tlv_read_u32(tlv_value2));
                        nbr_data->remote_if_index = htonl(tlv_read_u32(tlv_value2 + sizeof(uint32_t)));
                    }
                    break;
                case ISIS_TLV_LOCAL_IP:
                    if (tlv_len2 >= sizeof(uint32_t)) {
                        nbr_data->local_ip = htonl(tlv_read_u32(tlv_value2));
                    }
                    break;
                case ISIS_TLV_REMOTE_IP:
                    if (tlv_len2 >= sizeof(uint32_t)) {
                        nbr_data->remote_ip = htonl(tlv_read_u32(tlv_value2));
                    }
                    break;
                default:;
                }
            }
            ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                            tlv_len2, tlv_value2, subtlv_len);
            break;
        case ISIS_TLV_IP_REACH:
        {
            if (!prefix_tree_root)
            {
                prefix_tree_root = (avltree_t *)XCALLOC(0, 1, avltree_t);
                avltree_init(prefix_tree_root, avltree_prefix_tree_comp_fn);
            }
            isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)tlv_value;
            ted_prefix_t *ted_prefix = (ted_prefix_t *)XCALLOC2(0, 1, ted_prefix_t);
            ted_prefix->prefix = htonl(tlv_130->prefix);
            ted_prefix->mask = tcp_ip_convert_bin_mask_to_dmask(htonl(tlv_130->mask));
            ted_prefix->metric = htonl(tlv_130->metric);
            ted_prefix->flags = tlv_130->flags;
            ted_prefix->src = lsp_pkt_hdr->fr_no;
            avltree_insert(&ted_prefix->avl_glue, prefix_tree_root);
        }
        break;
        case ISIS_TLV_IPV6_REACH:
        {
            if (!v6prefix_tree_root)
            {
                v6prefix_tree_root = (avltree_t *)XCALLOC(0, 1, avltree_t);
                avltree_init(v6prefix_tree_root, avltree_v6prefix_tree_comp_fn);
            }
            isis_tlv_236_t *tlv_236 = (isis_tlv_236_t *)tlv_value;
            ted_v6prefix_t *ted_prefix = (ted_v6prefix_t *)XCALLOC2(0, 1, ted_v6prefix_t);
            memcpy (ted_prefix->prefix, tlv_236->prefix, 16);
            ted_prefix->mask = tlv_236->prefix_len;
            ted_prefix->metric = htonl(tlv_236->metric);
            ted_prefix->flags = tlv_236->bits;
            ted_prefix->src = lsp_pkt_hdr->fr_no;
            avltree_insert(&ted_prefix->avl_glue, v6prefix_tree_root);
        }
        break;        
        case ISIS_TLV_LOCATOR:
        {
            locator_tlv_t *tlv_27;
            ted_v6prefix_t *ted_prefix;

            if ( (!isis_srv6_get_config(node_info))) break;

            if (!srv6prefixsid_tree_root)
            {
                srv6prefixsid_tree_root = (avltree_t *)XCALLOC(0, 1, avltree_t);
                avltree_init(srv6prefixsid_tree_root, avltree_v6prefix_tree_comp_fn);
            }
            do
            {
                tlv_27 = (locator_tlv_t *)tlv_value;
                ted_prefix = (ted_v6prefix_t *)XCALLOC2(0, 1, ted_v6prefix_t);
                memcpy(ted_prefix->prefix, tlv_27->locator, (tlv_27->loc_size + 7) / 8);
                ted_prefix->mask = tlv_27->loc_size;

                /* Locator TLV mau appear multiple times, in one or many fragments, avoid
                    multiple installation in AVL tree.*/
                if (avltree_lookup (&ted_prefix->avl_glue, srv6prefixsid_tree_root)) {
                    XFREE(ted_prefix);
                    break;
                }
                ted_prefix->metric = htonl(tlv_27->metric);
                ted_prefix->flags = tlv_27->flags;
                ted_prefix->src = lsp_pkt_hdr->fr_no;
                ted_prefix->endfn = 0; // locators dont have endfn
                ted_prefix->mt_id = tlv_27->RRRR_mt_id;
                ted_prefix->algo = tlv_27->algorithm;
                avltree_insert(&ted_prefix->avl_glue, srv6prefixsid_tree_root);

            } while (0);

            /* Now Prefix Sid Locator SubTLVs*/

            subtlv_navigator = tlv_value + sizeof(locator_tlv_t) + ((tlv_27->loc_size + 7)/8);
            subtlv_len = locator_tlv_get_subtlv_len(tlv_27);

            /* Now Read Prefix Sid SUBTLVs*/
            ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                              tlv_len2, tlv_value2, subtlv_len) {

                switch (tlv_type2)
                {
                    case ISIS_LOCATOR_PFX_SID_SUBTLV:
                    {
                        srv6_pfxsid_subtlv_t *pfxsid_subtlv = (srv6_pfxsid_subtlv_t *)tlv_value2;
                        ted_v6prefix_t *ted_prefix = (ted_v6prefix_t *)XCALLOC2(0, 1, ted_v6prefix_t);
                        memcpy (ted_prefix->prefix, pfxsid_subtlv->prefix, 16);
                        ted_prefix->mask = 128; // srv6 pfxsid subtlvs do not carry prefix len
                        ted_prefix->metric = 0;
                        ted_prefix->flags = pfxsid_subtlv->flags;
                        ted_prefix->src = lsp_pkt_hdr->fr_no;
                        ted_prefix->endfn = pfxsid_subtlv->endfn;
                        ted_prefix->mt_id = tlv_27->RRRR_mt_id; // inherit from the locator
                        ted_prefix->algo = tlv_27->algorithm; // inherit from the locator
                        avltree_insert(&ted_prefix->avl_glue, srv6prefixsid_tree_root);
                    }
                    break;
                }
            }
            ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                            tlv_len2, tlv_value2, subtlv_len);
        }
        break;
        case ISIS_TLV_RTR_CAP:
        {
            /* Router CAPABILITY TLV(242) : rtr_id(4) + flags(1), followed by
                zero or more SubTLVs. We only care about the SR-MPLS
                SR-Capability SubTLV ( SRGB ) here. Sub-TLVs embed their own
                type/length as the first two bytes of their struct ( unlike
                ITERATE_TLV_BEGIN's convention ), so walk them manually -
                mirrors isis_print_formatted_rtr_cap_tlv242() */
            size_t fixed_hdr_size = sizeof(isis_rtr_cap_tlv242_t);

            if (tlv_len > fixed_hdr_size) {

                byte *subtlv = tlv_value + fixed_hdr_size;
                uint16_t consumed = (uint16_t)fixed_hdr_size;
                bool next_subtlv;

                do {
                    next_subtlv = false;

                    switch (*subtlv) {

                        case ISIS_TLV_RTR_CAP_SR_CAP_SUBTLV:
                        {
                            isis_rtr_cap_sr_cap_subtlv_t *sr_cap_subtlv =
                                (isis_rtr_cap_sr_cap_subtlv_t *)subtlv;

                            node_data->has_srgb = true;
                            node_data->srgb_base = sr_cap_subtlv->srgb_base;
                            node_data->srgb_range = sr_cap_subtlv->srgb_range;

                            consumed += TLV_OVERHEAD_SIZE + sr_cap_subtlv->length;
                            if (tlv_len > consumed) {
                                subtlv += TLV_OVERHEAD_SIZE + sr_cap_subtlv->length;
                                next_subtlv = true;
                            }
                        }
                        break;

                        case ISIS_TLV_RTR_CAP_ALGO_SUBTLV:
                        {
                            isis_rtr_cap_algorithm_subtlv19_t *algo_subtlv =
                                (isis_rtr_cap_algorithm_subtlv19_t *)subtlv;

                            consumed += TLV_OVERHEAD_SIZE + algo_subtlv->length;
                            if (tlv_len > consumed) {
                                subtlv += TLV_OVERHEAD_SIZE + algo_subtlv->length;
                                next_subtlv = true;
                            }
                        }
                        break;

                        case ISIS_TLV_RTR_CAP_SRV6_SUBTLV:
                        {
                            isis_rtr_cap_srv6_subtlv2_t *srv6_subtlv =
                                (isis_rtr_cap_srv6_subtlv2_t *)subtlv;

                            consumed += TLV_OVERHEAD_SIZE + srv6_subtlv->length;
                            if (tlv_len > consumed) {
                                subtlv += TLV_OVERHEAD_SIZE + srv6_subtlv->length;
                                next_subtlv = true;
                            }
                        }
                        break;

                        default:
                            /* Unknown/garbage subtlv - stop walking */
                            break;
                    }

                } while (next_subtlv);
            }
        }
        break;
        case ISIS_TLV_NODE_SID:
        {
            isis_node_sid_tlv_t *node_sid_tlv = (isis_node_sid_tlv_t *)tlv_value;

            node_sid_present = true;
            node_sid_prefix = htonl(node_sid_tlv->prefix);
            node_sid_prefix_len = node_sid_tlv->prefix_len;
            node_sid_index = htonl(node_sid_tlv->sid_index);
            node_sid_flags = node_sid_tlv->flags;
        }
        break;
                default:;
        }
    }
    ITERATE_TLV_END(tlv_buffer, tlv_type,
                    tlv_len, tlv_value, tlv_buff_size);

    /* Reconcile the Node-SID ( if any ) against the prefix it is bound to.
        The Node-SID TLV may have been scanned before or after the matching
        IP-REACH TLV above, so this can only be done once the TLV walk over
        this LSP fragment is complete */
    if (node_sid_present) {

        if (!prefix_tree_root) {
            prefix_tree_root = (avltree_t *)XCALLOC(0, 1, avltree_t);
            avltree_init(prefix_tree_root, avltree_prefix_tree_comp_fn);
        }

        ted_prefix_t dummy_prefix;
        memset(&dummy_prefix, 0, sizeof(dummy_prefix));
        dummy_prefix.prefix = node_sid_prefix;
        dummy_prefix.mask = node_sid_prefix_len;

        avltree_node_t *avl_node = avltree_lookup(&dummy_prefix.avl_glue, prefix_tree_root);
        ted_prefix_t *ted_prefix;

        if (avl_node) {
            ted_prefix = avltree_container_of(avl_node, ted_prefix_t, avl_glue);
        }
        else {
            ted_prefix = (ted_prefix_t *)XCALLOC2(0, 1, ted_prefix_t);
            ted_prefix->prefix = node_sid_prefix;
            ted_prefix->mask = node_sid_prefix_len;
            ted_prefix->src = lsp_pkt_hdr->fr_no;
            avltree_insert(&ted_prefix->avl_glue, prefix_tree_root);
        }

        ted_prefix->has_sid = true;
        ted_prefix->sid_index = node_sid_index;
        ted_prefix->sid_flags = node_sid_flags;
    }

    node_data->n_nbrs = n_tlv22;
    ted_create_or_update_node(ted_db, node_data, 
            prefix_tree_root, v6prefix_tree_root, srv6prefixsid_tree_root);
    XFREE(node_data);
}

void
isis_ted_uninstall_lsp(isis_node_info_t *node_info, ted_db_t *ted_db, isis_lsp_pkt_t *lsp_pkt) {

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint8_t pn_no = isis_get_lsp_pkt_pn_id (lsp_pkt);
    ted_node_t *ted_node = ted_lookup_node(ted_db, *rtr_id, pn_no);
    if (!ted_node) return;
    ted_delete_node (ted_db, ted_node);
}

void
isis_cleanup_teddb (isis_node_info_t *node_info) {

    ted_node_t *ted_node;
    ted_db_t *ted_db = node_info->ted_db;
    
    if (!ted_db) return;
    
    avltree_node_t *curr;
    avltree_t *teddb_tree = &ted_db->teddb;

    ITERATE_AVL_TREE_BEGIN(teddb_tree, curr){

        ted_node = avltree_container_of(curr, ted_node_t, avl_glue);
        isis_spf_cleanup_spf_data (ted_node);
        ted_delete_node (ted_db, ted_node);

    } ITERATE_AVL_TREE_END;

    XFREE(ted_db);
    node_info->ted_db = NULL;
}

void
isis_cleanup_teddb_root(isis_node_info_t *node_info) {

    ted_db_t *ted_db = node_info->ted_db;
    if (!ted_db) return;
    assert(avltree_is_empty(&ted_db->teddb));
    XFREE(ted_db);
    node_info->ted_db = NULL;
 }
