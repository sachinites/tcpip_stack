#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_pkt.h"

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

	if (eth_hdr->type == ISIS_ETH_PKT_TYPE) {
		return true;
	}
	return false;
}

void
isis_pkt_recieve(void *arg, size_t arg_size) {

    char *pkt;
    node_t *node;
    interface_t *iif;
    uint32_t pkt_size;
	hdr_type_t hdr_code;
    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = pkt_notif_data->recv_interface;
    pkt         = pkt_notif_data->pkt;
    pkt_size    = pkt_notif_data->pkt_size;
	hdr_code    = pkt_notif_data->hdr_code;	

    if (hdr_code != ETH_HDR) return;


}

void
isis_install_lsp_pkt_in_lspdb(node_t *node, 
                              char *isis_lsp_pkt,
                              size_t lsp_pkt_size) {

}

char *
isis_generate_lsp_pkt(node_t *node, size_t *lsp_pkt_size) {

}