#include "../graph.h"
#include "../notif.h"
#include "rt_notif.h"
#include "../gluethread/glthread.h"
#include "../BitOp/bitsop.h"
#include "layer3.h"

void
rt_table_add_route_to_notify_list (
                rt_table_t *rt_table, 
                l3_route_t *l3route,
                uint8_t flag) {

    uint8_t old_flags = l3route->rt_flags;
    remove_glthread(&l3route->notif_glue);
    UNSET_BIT8(l3route->rt_flags, RT_ADD_F);
    UNSET_BIT8(l3route->rt_flags, RT_DEL_F);
    UNSET_BIT8(l3route->rt_flags, RT_UPDATE_F);

    if (IS_BIT_SET(old_flags, RT_DEL_F) &&
         IS_BIT_SET(flag, RT_ADD_F)) {
            SET_BIT(l3route->rt_flags, RT_UPDATE_F);
    } else {
            SET_BIT(l3route->rt_flags, flag);
    }
    glthread_add_next(&rt_table->rt_notify_list_head, &l3route->notif_glue);
    assert(l3route->rt_flags != 3);
}

static void
rt_table_notif_job_cb(void *arg, uint32_t arg_size) {

    glthread_t *curr;
    l3_route_t *l3route;
    rt_table_t *rt_table = (rt_table_t *)arg;
    
    rt_table->notif_job = NULL;

    rt_route_notif_data_t rt_route_notif_data;

    /* Start Sending Notifications Now */
    ITERATE_GLTHREAD_BEGIN(&rt_table->rt_notify_list_head, curr) {

        l3route = notif_glue_to_l3_route(curr);
        rt_route_notif_data.l3route = l3route;
        rt_route_notif_data.node = rt_table->node;
        nfc_invoke_notif_chain(&rt_table->nfc_rt_updates, 
                                               &rt_route_notif_data,
                                               sizeof(rt_route_notif_data), 0, 0);
                                               
        remove_glthread(&l3route->notif_glue);

        if (IS_BIT_SET(l3route->rt_flags, RT_DEL_F)) {
                l3_route_free(l3route);
                continue;
        }
        UNSET_BIT8(l3route->rt_flags, RT_ADD_F);
        UNSET_BIT8(l3route->rt_flags, RT_UPDATE_F);
        
    } ITERATE_GLTHREAD_END(&rt_table->rt_notify_list_head, curr)
}

void
rt_table_kick_start_notif_job(rt_table_t *rt_table) {

    if (rt_table->notif_job) return;
    rt_table->notif_job = task_create_new_job(
                                        rt_table, 
                                        rt_table_notif_job_cb,
                                        TASK_ONE_SHOT);
    assert(rt_table->notif_job);
}

void
nfc_ipv4_rt_subscribe (node_t *node, nfc_app_cb cbk) {

    notif_chain_elem_t nfce_template;

    memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
    nfce_template.app_cb = cbk;

    nfc_register_notif_chain(&node->node_nw_prop.rt_table->nfc_rt_updates,
                                              &nfce_template);
}

void
nfc_ipv4_rt_un_subscribe (node_t *node, nfc_app_cb cbk) {

    notif_chain_elem_t nfce_template;

    memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
    nfce_template.app_cb = cbk;

    nfc_de_register_notif_chain(&node->node_nw_prop.rt_table->nfc_rt_updates,
                                                    &nfce_template);
}

typedef struct flash_data_ {

    rt_table_t *rt_table;
    nfc_app_cb cbk;
} flash_data_t;

static void
rt_table_flash_job (void *arg, uint32_t arg_size) {

    glthread_t *curr;
    l3_route_t *l3route;

    flash_data_t *flash_data = (flash_data_t *)arg;

    nfc_app_cb cbk = flash_data->cbk;
    rt_table_t *rt_table = flash_data->rt_table;
    
    rt_route_notif_data_t route_notif_data;
    
    ITERATE_GLTHREAD_BEGIN(&rt_table->rt_flash_list_head, curr) {

        l3route = flash_glue_to_l3_route(curr);
        route_notif_data.node = rt_table->node;
        route_notif_data.l3route = l3route;
        cbk(&route_notif_data, sizeof(route_notif_data));
        UNSET_BIT8(l3route->rt_flags, RT_FLASH_REQ_F);
    } ITERATE_GLTHREAD_END(&rt_table->rt_flash_list_head, curr)

    free(flash_data);
    rt_table->flash_job = NULL;
}

static void
rt_table_add_route_to_flash_list (rt_table_t *rt_table,
                                                      l3_route_t *l3route,
                                                      nfc_app_cb cbk) {

    remove_glthread (&l3route->flash_glue);
    SET_BIT(l3route->rt_flags, RT_FLASH_REQ_F);
    glthread_add_next(&rt_table->rt_flash_list_head, &l3route->flash_glue);
    if (rt_table->flash_job) return;
    flash_data_t *flash_data = calloc(1, sizeof(flash_data_t));
    flash_data->rt_table = rt_table;
    flash_data->cbk = cbk;
    rt_table->flash_job = task_create_new_job( flash_data, rt_table_flash_job, TASK_ONE_SHOT);
}

void
nfc_ipv4_rt_request_flash (node_t *node, nfc_app_cb cbk) {

    glthread_t *curr;
    l3_route_t *l3route;
    rt_table_t *rt_table = NODE_RT_TABLE(node);

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr) {

        l3route = rt_glue_to_l3_route(curr);
        rt_table_add_route_to_flash_list (rt_table, l3route, cbk);

    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr)
}

void
nfc_ipv4_rt_subscribe_per_route (node_t *node, uint32_t ip, uint8_t mask) {

}

void
nfc_ipv4_rt_un_subscribe_per_route (node_t *node, uint32_t ip, uint8_t mask) {

}