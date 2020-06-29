#ifndef __TCPIP_REGISTER__
#define __TCPIP_REGISTER__

typedef struct node_ node_t ;
typedef struct interface_ interface_t;

typedef void (*app_layer_cb)
    (node_t *, interface_t *, char *, uint32_t, uint32_t);

bool_t
tcp_stack_register_app_protocol(glthread_t *app_cb_db,
            uint32_t protocol_no,
            app_layer_cb app_cb);

bool_t
tcp_stack_unregister_app_protocol(glthread_t *app_cb_db,
        uint32_t protocol_no,
        app_layer_cb app_cb);

void
tcp_stack_invoke_app_callbacks(glthread_t *app_cb_db,
        uint32_t protocol_no,
        node_t *node,
        interface_t *intf,
        char *pkt, uint32_t pkt_size,
        uint32_t flags);

#endif /* __TCPIP_REGISTER__ */
