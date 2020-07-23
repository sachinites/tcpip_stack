#ifndef __TCPIP_REGISTER__
#define __TCPIP_REGISTER__

typedef struct node_ node_t ;
typedef struct interface_ interface_t;
typedef struct _glthread glthread_t;

typedef void (*app_layer_cb)
    (node_t *, interface_t *, char *, uint32_t, uint32_t);

typedef int (*app_print_pkt_cb)
    (char *, char *, uint32_t, int);

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

bool_t
tcp_stack_register_print_callback(
                    uint32_t protocol_no,
                    char *protocol_no_str,
                    app_print_pkt_cb app_cb);

int
tcp_stack_invoke_app_print_callbacks(
        glthread_t *app_print_cb_db,
        uint32_t protocol_no,
        char *buff, char *pkt,
        uint32_t pkt_size,
        int tab_count);

char *
tcp_stack_get_print_str_protocol_number(uint32_t protocol_no);

/*Interface Config Change Notification*/
typedef void (*interface_listerner_cb)(interface_t *, uint32_t);

void tcp_stack_register_interface_update_listener(
        interface_listerner_cb intf_lsnr_cb);

void
tcp_stack_notify_interface_change_config(
        interface_t *intf, uint32_t flags);
#endif /* __TCPIP_REGISTER__ */
