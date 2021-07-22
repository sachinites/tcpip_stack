#include "../../tcp_public.h"
#include "isis_struct.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"

bool
isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_props.isis_intf_info == NULL);
}

static bool
isis_interface_qualify_to_send_hellos(interface_t *intf){

    if (isis_node_intf_is_enable(intf) &&
         IS_INTF_L3_MODE(intf) &&
         IF_IS_UP(intf)) {
             
             return true;
    }
    return false;
}

static void
isis_transmit_hello(void *arg, uint32_t arg_size) {

    if (!arg) return;

    isis_pkt_meta_data_t *isis_pkt_meta_data =
        (isis_pkt_meta_data_t *)arg;

    node_t *node = isis_pkt_meta_data->node;
    interface_t *egress_intf = isis_pkt_meta_data->intf;
    char *hello_pkt = isis_pkt_meta_data->pkt;
    size_t pkt_size = isis_pkt_meta_data->pkt_size;

    if (hello_pkt && pkt_size) {
        send_pkt_out(hello_pkt, pkt_size, egress_intf);
    }
}

void
isis_start_sending_hellos(interface_t *intf) {

    node_t *node;
    size_t hello_pkt_size;
    isis_intf_info_t *isis_intf_info;

    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
    assert(isis_node_intf_is_enable(intf));
    
    isis_intf_info = intf->intf_nw_props.isis_intf_info;

    node = intf->att_node;
    wheel_timer_t *wt = node->node_nw_prop.wt;

    char *hello_pkt = isis_get_hello_pkt(intf, &hello_pkt_size);

    isis_pkt_meta_data_t *isis_pkt_meta_data =
        calloc(1, sizeof(isis_pkt_meta_data_t));

    isis_pkt_meta_data->node = node;
    isis_pkt_meta_data->intf = intf;
    isis_pkt_meta_data->pkt = hello_pkt;
    isis_pkt_meta_data->pkt_size = hello_pkt_size;

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = timer_register_app_event(wt,
                                    isis_transmit_hello,
                                    (void *)isis_pkt_meta_data,
                                    sizeof(isis_pkt_meta_data_t),
                                    isis_intf_info->hello_interval * 1000,
                                    1);

    
    if (ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL) {
        printf("Error : Failed to xmit hellos on interface (%s)%s",
            node->node_name, intf->if_name);
        free(isis_pkt_meta_data);
        return;
    }
}

void
isis_stop_sending_hellos(interface_t *intf){

    wheel_timer_elem_t *hello_xmit_timer = NULL;

    hello_xmit_timer = ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (!hello_xmit_timer) return;

    isis_pkt_meta_data_t *isis_pkt_meta_data =
        (isis_pkt_meta_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, 0);

    timer_de_register_app_event(hello_xmit_timer);

    free(isis_pkt_meta_data->pkt);
    free(isis_pkt_meta_data);

    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
}

void
isis_enable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *isis_intf_info;

    if (!intf->intf_nw_props.isis_intf_info) {
        intf->intf_nw_props.isis_intf_info = calloc(1, sizeof(isis_intf_info_t));
        isis_intf_info = intf->intf_nw_props.isis_intf_info;
        isis_intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    }
    
    if (isis_intf_info->hello_xmit_timer == NULL) {
        if (isis_interface_qualify_to_send_hellos(intf)) {
            isis_start_sending_hellos(intf);
        }
    }
}

void
isis_disable_protocol_on_interface(interface_t *intf) {

    isis_intf_info_t *isis_intf_info;

    isis_intf_info = intf->intf_nw_props.isis_intf_info;

    if (!isis_intf_info) return;

    isis_stop_sending_hellos(intf);
    isis_free_intf_info(intf);
}

void
isis_show_interface_protocol_state(interface_t *intf) {

    bool is_enabled;
    isis_intf_info_t *isis_intf_info = NULL;

    is_enabled = isis_node_intf_is_enable(intf);

    printf("\t %s : %sabled\n", intf->if_name, is_enabled ? "En" : "Dis");
    
    if(!is_enabled) return;

    isis_intf_info = intf->intf_nw_props.isis_intf_info;
    
    printf("\t\thello interval : %u sec\n", isis_intf_info->hello_interval);
    printf("\t\thello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");
}

void
isis_free_intf_info(interface_t *intf) {

    assert(intf->intf_nw_props.isis_intf_info);
    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);

    free(intf->intf_nw_props.isis_intf_info);
    intf->intf_nw_props.isis_intf_info = NULL;
}

void
isis_interface_updates(void *arg, size_t arg_size) {

	intf_notif_data_t *intf_notif_data = 
		(intf_notif_data_t *)arg;

	uint32_t flags = intf_notif_data->change_flags;
	interface_t *interface = intf_notif_data->interface;
	intf_nw_props_t *old_intf_nw_props = intf_notif_data->old_intf_nw_props;

    if (!isis_node_intf_is_enable(interface)) return;

    printf("notified\n");
}