#ifndef __ISIS_EVENTS__
#define __ISIS_EVENTS__


typedef enum isis_events_ {

    isis_event_none,
    isis_event_adj_state_goes_up,
    isis_event_adj_state_goes_down,
    isis_event_protocol_enable,
    isis_event_protocol_disable,
    isis_event_protocol_disable_on_intf,
    isis_event_protocol_enable_on_intf,
    isis_nbr_ip_changed,
    isis_nbr_metric_changed,
    isis_nbr_rtr_id_changed,
    isis_event_self_outdated_lsp_recvd,
    isis_event_max
} isis_events_t;

const char *
isis_event(isis_events_t isis_event_type);

#endif 