#include <assert.h>
#include <stdlib.h>
#include "../../gluethread/glthread.h"
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../EventDispatcher/event_dispatcher.h"
#include "object_group.h"
#include "object_grp_update.h"
#include "../acl/acldb.h"
#include "../../graph.h"
#include "../fwall_trace_const.h"

#define HASH_PRIME_CONST 5381

static unsigned int
hashfromkey_acl(void *key)
{

    access_list_t **key1 = (access_list_t **)key;
    unsigned char *str = (unsigned char *)(*key1);
    unsigned int hash = HASH_PRIME_CONST;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int
equalkeys_acl(void *k1, void *k2)
{
    access_list_t **key1 = (access_list_t **)k1;
    access_list_t **key2 = (access_list_t **)k2;
    return *key1 == *key2;
}

static void
object_group_collect_dependent_access_lists(object_group_t *og, hashtable_t *ht)
{
    void *ht_key;
    glthread_t *curr;
    acl_entry_t *acl;
    access_list_t *access_list;
    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

    if (!og->db) return;

    ITERATE_GLTHREAD_BEGIN(&og->db->acls_list, curr) {

        objects_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        acl = objects_linked_acl_thread_node->acl;
        /* We are interested only in access lists which are installed in TCAM */
        if (!acl->is_installed) continue;
        ht_key = (void *)acl->access_list;
        access_list = (access_list_t *)hashtable_search(ht, (void *)&ht_key);
        if (access_list) continue;
        ht_key = (void *)calloc(1, sizeof(void *));
        void *temp = (void *)acl->access_list;
        memcpy(ht_key, &temp, sizeof(void *));
        hashtable_insert(ht, (void *)ht_key, (void *)acl->access_list);
        access_list_reference(acl->access_list);

    } ITERATE_GLTHREAD_END(&og->db->acls_list, curr)
}

static void
object_group_collect_dependent_access_lists_wrapper(object_group_t *og, void *ht)
{
    object_group_collect_dependent_access_lists(og, (hashtable_t *)ht);
}

static void
object_group_traverse_bottom_up(
    object_group_t *og,
    void (*og_processing_fn_ptr)(object_group_t *, void *),
    void *arg)
{
    glthread_t *curr;
    object_group_t *p_og;
    obj_grp_list_node_t *obj_grp_list_node;

    // process root
    og_processing_fn_ptr(og, arg);

    ITERATE_GLTHREAD_BEGIN(&og->parent_og_list_head, curr)
    {

        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
        object_group_traverse_bottom_up(
            obj_grp_list_node->og,
            object_group_collect_dependent_access_lists_wrapper,
            arg);
    }
    ITERATE_GLTHREAD_END(&og->parent_og_list_head, curr)
}

static hashtable_t *
object_group_collect_dependent_access_lists_bottom_up_traversal(object_group_t *og)
{

    hashtable_t *h = create_hashtable(128, hashfromkey_acl, equalkeys_acl);
    assert(h);
    object_group_traverse_bottom_up(
        og,
        object_group_collect_dependent_access_lists_wrapper,
        (void *)h);
    return h;
}

static void
og_update_acls_task(event_dispatcher_t *ev, void *arg, uint32_t arg_size);

void
object_group_update_reschedule_task(object_group_update_info_t *og_update_info)
{

    og_update_info->og_update_task =
        task_create_new_job(EV(og_update_info->node),
                            (void *)og_update_info,
                            og_update_acls_task,
                            TASK_ONE_SHOT,
                            TASK_PRIORITY_COMPUTE);
}

static void
og_update_acls_task(event_dispatcher_t *ev, void *arg, uint32_t arg_size)
{
    glthread_t *curr;
    acl_entry_t *acl_entry;
    struct hashtable_itr *itr;
    access_list_t *access_list;
    mtrie_t *mtrie1, *mtrie2;

    object_group_update_info_t *og_update_info =
        (object_group_update_info_t *)arg;

    node_t *node = og_update_info->node;

    og_update_info->og_update_task = NULL;

    sprintf(tlb, "%s : Entering Stage  : %s\n",
        FWALL_OBJGRP_UPDATE, og_update_acl_stage_to_string(og_update_info->stage));
    tcp_trace(node, 0, tlb);

    switch (og_update_info->stage)
    {
    case og_update_fsm_stage_init:
        assert(!og_update_info->access_lists_ht);
        og_update_info->access_lists_ht =
            object_group_collect_dependent_access_lists_bottom_up_traversal(og_update_info->p_og);

        og_update_info->access_list_to_be_processed_count = hashtable_count(og_update_info->access_lists_ht);
        og_update_info->access_list_processed_count = 0;

        if (og_update_info->access_list_to_be_processed_count == 0)
        {
            og_update_info->stage = og_update_fsm_access_list_stage_og_association;
            hashtable_destroy(og_update_info->access_lists_ht, 0);
            og_update_info->access_lists_ht = NULL;
        }
        else
        {
            /* We will skip the uninstall stage, and jump directly to decompile stage.
             * This is doe because we will create a new TCAM from scratch and replace
             * the ptr of older TCAM with new one in data path. So no need to uninstall
             * ACLs from older tcam now. We will flush the older TCAM by offloading it 
             * to purging thread*/
            //og_update_info->stage = og_update_fsm_access_list_stage_uninstall;
            og_update_info->stage = og_update_fsm_access_list_stage_decompile;
        }
        sprintf(tlb, "%s : Number of Access Lists to be updated : %u\n",
            FWALL_OBJGRP_UPDATE,
            og_update_info->access_list_to_be_processed_count);
        tcp_trace(node, 0, tlb);
        object_group_update_reschedule_task(og_update_info);
        break;


    /* Uninstall all ACLs in the hashtable */
    case og_update_fsm_access_list_stage_uninstall:
        itr = hashtable_iterator(og_update_info->access_lists_ht);
        while (1) {
            access_list = (access_list_t *)hashtable_iterator_value(itr);
            access_list_trigger_uninstall_job(node, access_list, og_update_info);
            if (!hashtable_iterator_advance(itr)) break;
        }
        free(itr);
        break;

        
    case og_update_fsm_access_list_stage_decompile:
        itr = hashtable_iterator(og_update_info->access_lists_ht);
        while (1) {
            access_list = (access_list_t *)hashtable_iterator_value(itr);

            ITERATE_GLTHREAD_BEGIN(&access_list->head, curr)
            {
                acl_entry = glthread_to_acl_entry(curr);
                acl_decompile(acl_entry);
            }
            ITERATE_GLTHREAD_END(&access_list->head, curr);
            if (!hashtable_iterator_advance(itr)) break;
        }
        free(itr);
        /* Move to Next Stage */
        og_update_info->stage = og_update_fsm_access_list_stage_og_association;
        object_group_update_reschedule_task(og_update_info);
        break;


    case og_update_fsm_access_list_stage_og_association:
        if (og_update_info->is_delete)
        {
            switch (og_update_info->c_og->og_type)
            {
            case OBJECT_GRP_NET_ADDR:
            case OBJECT_GRP_NET_HOST:
            case OBJECT_GRP_NET_RANGE:
                object_group_delete(node, og_update_info->c_og);
                og_update_info->c_og = NULL;
                break;
            case OBJECT_GRP_NESTED:
                object_group_unbind_parent(og_update_info->p_og, og_update_info->c_og);
                object_group_unbind_child(og_update_info->p_og, og_update_info->c_og);
                break;
            }
        }
        else
        {
            object_group_bind(og_update_info->p_og, og_update_info->c_og);
        }
        /* Move to Next Stage */
        og_update_info->stage = og_update_info->access_lists_ht ?
            og_update_fsm_access_list_stage_compile : \
            og_update_fsm_access_list_stage_cleanup;
        object_group_update_reschedule_task(og_update_info);
        break;


    case og_update_fsm_access_list_stage_compile:
        itr = hashtable_iterator(og_update_info->access_lists_ht);
        while (1) {
            access_list = (access_list_t *)hashtable_iterator_value(itr);

            ITERATE_GLTHREAD_BEGIN(&access_list->head, curr)
            {
                acl_entry = glthread_to_acl_entry(curr);
                acl_compile(acl_entry);
            }
            ITERATE_GLTHREAD_END(&access_list->head, curr);
            if (!hashtable_iterator_advance(itr)) break;
        }
        free(itr);
        /* Move to Next Stage */
        og_update_info->stage = og_update_fsm_access_list_stage_installation;
        object_group_update_reschedule_task(og_update_info);
        break;


    case og_update_fsm_access_list_stage_installation:
        itr = hashtable_iterator(og_update_info->access_lists_ht);
        while (1) {
            access_list = (access_list_t *)hashtable_iterator_value(itr);
            access_list_trigger_install_job(node, access_list, og_update_info);
            if (!hashtable_iterator_advance(itr)) break;
        }
        free(itr);
        break;


    case og_update_fsm_access_list_stage_cleanup:
        if (og_update_info->access_lists_ht) {
            sprintf(tlb, "%s : All Access-Lists has been successfully updated\n", FWALL_OBJGRP_UPDATE);
        }
        else {
            sprintf(tlb, "%s : No Access-Lists need to be updated\n", FWALL_OBJGRP_UPDATE);
        }
        tcp_trace(node, 0, tlb);

        /* Clean up the Hashtable */
        if (og_update_info->access_lists_ht) {
            itr = hashtable_iterator(og_update_info->access_lists_ht);
            while (1)
            {
                access_list = (access_list_t *)hashtable_iterator_value(itr);
                access_list_dereference(node, access_list);
                if (!hashtable_iterator_advance(itr)) break;
            }
            free(itr);
            hashtable_destroy(og_update_info->access_lists_ht, 0);
            og_update_info->access_lists_ht = NULL;
        }

        XFREE(og_update_info);
        break;
    default:;
    }
}


void object_group_update_referenced_acls(
    node_t *node,
    object_group_t *p_og,
    object_group_t *c_og,
    bool is_delete) {

    object_group_update_info_t *og_update_info =
        (object_group_update_info_t *)XCALLOC(0, 1, object_group_update_info_t);

    og_update_info->p_og = p_og;
    og_update_info->c_og = c_og;
    og_update_info->is_delete = is_delete;
    og_update_info->stage = og_update_fsm_stage_init;
    og_update_info->node = node;
    og_update_info->access_lists_ht = NULL;
    object_group_update_reschedule_task(og_update_info);
    sprintf(tlb, "%s : [p_og : %s,  c_og : %s]  Scheduling ACLs Update for %s\n",
            FWALL_OBJGRP_UPDATE, p_og->og_name, c_og->og_name,
            is_delete ? "delete" : "create");
    tcp_trace(node, 0, tlb);
}

void object_grp_update_mem_init()
{
    MM_REG_STRUCT(0, object_group_update_info_t);
}
