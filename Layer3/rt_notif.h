#ifndef __RT_NOTIF__
#define __RT_NOTIF__

typedef struct node_ node_t;
typedef struct l3_route_ l3_route_t;

typedef struct rt_route_notif_data_ {

    node_t *node;
    l3_route_t *l3route;
} rt_route_notif_data_t;

void nfc_ipv4_rt_subscribe (node_t *node, nfc_app_cb cbk);
void nfc_ipv4_rt_un_subscribe (node_t *node, nfc_app_cb cbk);

void nfc_ipv4_rt_subscribe_per_route (node_t *node, uint32_t ip, uint8_t mask);
void nfc_ipv4_rt_un_subscribe_per_route (node_t *node, uint32_t ip, uint8_t mask);

void nfc_ipv4_rt_request_flash (node_t *node, nfc_app_cb cbk);

#endif  /* __RT_NOTIF__ */