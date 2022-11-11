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

    acl_entry_t **key1 = (acl_entry_t **)key;
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
    acl_entry_t **key1 = (acl_entry_t **)k1;
    acl_entry_t **key2 = (acl_entry_t **)k2;
    return *key1 == *key2;
}

static void
object_group_collect_dependent_acls(object_group_t *og, hashtable_t *ht)
{

    void *ht_key;
    glthread_t *curr;
    acl_entry_t *acl1, *acl2;

    objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

    if (!og->db)
        return;

    ITERATE_GLTHREAD_BEGIN(&og->db->acls_list, curr)
    {
        objects_linked_acl_thread_node = glue_to_objects_linked_acl_thread_node(curr);
        acl1 = objects_linked_acl_thread_node->acl;

        if (!acl1->is_installed)
            continue;

        ht_key = (void *)acl1;
        acl2 = (acl_entry_t *)hashtable_search(ht, (void *)&ht_key);

        if (acl2)
        {
            assert(acl1 == acl2);
            continue;
        }

        ht_key = (void *)calloc(1, sizeof(void *));
        void *temp = (void *)acl1;
        memcpy(ht_key, &temp, sizeof(void *));
        hashtable_insert(ht, (void *)ht_key, acl1);
    }
    ITERATE_GLTHREAD_END(&og->db->acls_list, curr)
}

static void
object_group_collect_dependent_acls_wrapper(object_group_t *og, void *ht)
{

    object_group_collect_dependent_acls(og, (hashtable_t *)ht);
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
            object_group_collect_dependent_acls_wrapper,
            arg);
    }
    ITERATE_GLTHREAD_END(&og->parent_og_list_head, curr)
}

static hashtable_t *
object_group_collect_dependent_acls_bottom_up_traversal(object_group_t *og)
{

    hashtable_t *h = create_hashtable(128, hashfromkey_acl, equalkeys_acl);
    assert(h);
    object_group_traverse_bottom_up(
        og,
        object_group_collect_dependent_acls_wrapper,
        (void *)h);
    return h;
}

typedef enum og_update_acl_stage_
{

    og_update_acl_stage_init,
    og_update_acl_stage_uninstall,
    og_update_acl_stage_decompile,
    og_update_acl_stage_og_association,
    og_update_acl_stage_compile,
    og_update_acl_stage_installation,
    og_update_acl_stage_cleanup,
} og_update_acl_stage_t;

typedef struct object_group_update_info_
{

    object_group_t *p_og;
    object_group_t *c_og;
    bool is_delete;
    og_update_acl_stage_t stage;
    hashtable_t *acls_ht;
    struct hashtable_itr *itr;
    glthread_t acls_list_head;
    node_t *node;
    task_t *og_update_task;
} object_group_update_info_t;

static void
og_update_acls_task(event_dispatcher_t *ev, void *arg, uint32_t arg_size);

static void
object_group_update_reschedule_task(object_group_update_info_t *og_update_info)
{

    og_update_info->og_update_task =
        task_create_new_job(EV(og_update_info->node),
                            (void *)og_update_info,
                            og_update_acls_task,
                            TASK_ONE_SHOT,
                            TASK_PRIORITY_MEDIUM_MEDIUM);
}

static void
og_update_acls_task(event_dispatcher_t *ev, void *arg, uint32_t arg_size)
{

    object_group_update_info_t *og_update_info =
        (object_group_update_info_t *)arg;

    node_t *node = og_update_info->node;
    og_update_info->og_update_task = NULL;

    switch (og_update_info->stage)
    {

    case og_update_acl_stage_init:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_init\n", FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);

        assert(!og_update_info->acls_ht);
        og_update_info->acls_ht =
            object_group_collect_dependent_acls_bottom_up_traversal(og_update_info->p_og);

        if (hashtable_count(og_update_info->acls_ht) == 0)
        {
            og_update_info->stage = og_update_acl_stage_og_association;
            hashtable_destroy(og_update_info->acls_ht, 0);
            og_update_info->acls_ht = NULL;
            sprintf(tlb, "%s : Number of ACLs to be updated : 0\n", FWALL_OBJGRP_UPDATE);
            tcp_trace(node, 0, tlb);
        }
        else
        {
            og_update_info->stage = og_update_acl_stage_uninstall;
            sprintf(tlb, "%s : Number of ACLs to be updated : %u\n", FWALL_OBJGRP_UPDATE, hashtable_count(og_update_info->acls_ht));
            tcp_trace(node, 0, tlb);
        }

        object_group_update_reschedule_task(og_update_info);
        return;

    /* Uninstall all ACLs in the hashtable */
    case og_update_acl_stage_uninstall:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_uninstall\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        
        {
            if (event_dispatcher_should_suspend(EV(node)))
            {
                object_group_update_reschedule_task(og_update_info);
                return;
            }

            unsigned int count;
            acl_entry_t *acl_entry;
            struct hashtable_itr *itr;

            count = hashtable_count(og_update_info->acls_ht);

            if (!count)
            {
                og_update_info->stage = og_update_acl_stage_og_association;
                if (og_update_info->itr) {
                    free(og_update_info->itr);
                    og_update_info->itr = NULL;
                }
                hashtable_destroy(og_update_info->acls_ht, 0);
                og_update_info->acls_ht = NULL;
                object_group_update_reschedule_task(og_update_info);
                return;
            }

            if (og_update_info->itr)
            {
                itr = og_update_info->itr;
            }
            else
            {
                itr = hashtable_iterator(og_update_info->acls_ht);
                og_update_info->itr = itr;
            }

            do
            {
                acl_entry = (acl_entry_t *)hashtable_iterator_value(itr);
                assert(acl_entry->is_installed);
                acl_entry_uninstall(acl_entry->access_lst, acl_entry);
                objects_linked_acl_thread_node_t *objects_linked_acl_thread_node =
                    (objects_linked_acl_thread_node_t *)XCALLOC(0, 1, objects_linked_acl_thread_node_t);
                objects_linked_acl_thread_node->acl = acl_entry;
                init_glthread(&objects_linked_acl_thread_node->glue);
                glthread_add_last(&og_update_info->acls_list_head,
                                  &objects_linked_acl_thread_node->glue);

                if (event_dispatcher_should_suspend(EV(og_update_info->node)))
                {
                    if (!hashtable_iterator_advance(itr))
                    {
                        free(itr);
                        og_update_info->itr = NULL;
                    }
                    object_group_update_reschedule_task(og_update_info);
                    return;
                }

            } while (hashtable_iterator_advance(itr));

            /* All ACLs has been uninstalled, destroy hashtable and free it */
            free(og_update_info->itr);
            og_update_info->itr = NULL;
            hashtable_destroy(og_update_info->acls_ht, 0);
            og_update_info->acls_ht = NULL;

            /* Proceed to next stage */
            og_update_info->stage = og_update_acl_stage_decompile;
            object_group_update_reschedule_task(og_update_info);
            return;
        }
        break;
    case og_update_acl_stage_decompile:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_decompile\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        {
            glthread_t *curr;
            acl_entry_t *acl_entry;
            objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;

            ITERATE_GLTHREAD_BEGIN(&og_update_info->acls_list_head, curr)
            {

                objects_linked_acl_thread_node =
                    glue_to_objects_linked_acl_thread_node(curr);
                acl_entry = objects_linked_acl_thread_node->acl;
                acl_decompile(acl_entry);

                if (event_dispatcher_should_suspend(EV(node)))
                {
                    object_group_update_reschedule_task(og_update_info);
                    return;
                }
            }
            ITERATE_GLTHREAD_END(&og_update_info->acls_list_head, curr);

            /* All ACLs has been decompiled. move to the next stage */
            og_update_info->stage = og_update_acl_stage_og_association;
            object_group_update_reschedule_task(og_update_info);
            return;
        }
        break;
    case og_update_acl_stage_og_association:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_og_association\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);

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
        if (!IS_GLTHREAD_LIST_EMPTY(&og_update_info->acls_list_head))
        {
            og_update_info->stage = og_update_acl_stage_compile;
        }
        else
        {
            og_update_info->stage = og_update_acl_stage_cleanup;
        }
        object_group_update_reschedule_task(og_update_info);
        return;
        break;
    case og_update_acl_stage_compile:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_compile\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        {
            glthread_t *curr;
            acl_entry_t *acl_entry;
            objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;
            ITERATE_GLTHREAD_BEGIN(&og_update_info->acls_list_head, curr)
            {

                objects_linked_acl_thread_node =
                    glue_to_objects_linked_acl_thread_node(curr);
                acl_entry = objects_linked_acl_thread_node->acl;
                acl_compile(acl_entry);

                if (event_dispatcher_should_suspend(EV(node)))
                {
                    object_group_update_reschedule_task(og_update_info);
                    return;
                }
            }
            ITERATE_GLTHREAD_END(&og_update_info->acls_list_head, curr);

            /* All ACLs has been compiled. move to the next stage */
            og_update_info->stage = og_update_acl_stage_installation;
            object_group_update_reschedule_task(og_update_info);
            return;
        }
        break;
    case og_update_acl_stage_installation:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_installation\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        {
            glthread_t *curr;
            acl_entry_t *acl_entry;
            objects_linked_acl_thread_node_t *objects_linked_acl_thread_node;
            ITERATE_GLTHREAD_BEGIN(&og_update_info->acls_list_head, curr)
            {

                objects_linked_acl_thread_node =
                    glue_to_objects_linked_acl_thread_node(curr);
                acl_entry = objects_linked_acl_thread_node->acl;
                acl_entry_install(acl_entry->access_lst, acl_entry);
                remove_glthread(curr);
                XFREE(objects_linked_acl_thread_node);

                if (event_dispatcher_should_suspend(EV(node)))
                {
                    object_group_update_reschedule_task(og_update_info);
                    return;
                }
            }
            ITERATE_GLTHREAD_END(&og_update_info->acls_list_head, curr);

            /* All ACLs has been installed. move to the next stage */
            og_update_info->stage = og_update_acl_stage_cleanup;
            object_group_update_reschedule_task(og_update_info);
            return;
        }
        break;
    case og_update_acl_stage_cleanup:
        sprintf(tlb, "%s : Entering Stage  : og_update_acl_stage_cleanup\n",
                FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        sprintf(tlb, "%s : All ACLs has been successfully updated\n", FWALL_OBJGRP_UPDATE);
        tcp_trace(node, 0, tlb);
        assert(!og_update_info->acls_ht);
        assert(!og_update_info->itr);
        assert(IS_GLTHREAD_LIST_EMPTY(&og_update_info->acls_list_head));
        XFREE(og_update_info);
        break;
    default:;
    }
}

void object_group_update_referenced_acls(
    node_t *node,
    object_group_t *p_og,
    object_group_t *c_og,
    bool is_delete)
{

    object_group_update_info_t *og_update_info =
        (object_group_update_info_t *)XCALLOC(0, 1, object_group_update_info_t);

    og_update_info->p_og = p_og;
    og_update_info->c_og = c_og;
    og_update_info->is_delete = is_delete;
    og_update_info->stage = og_update_acl_stage_init;
    init_glthread(&og_update_info->acls_list_head);
    og_update_info->node = node;
    og_update_info->acls_ht = NULL;
    og_update_info->itr = NULL;
    og_update_info->og_update_task =
        task_create_new_job(EV(node),
                            (void *)og_update_info,
                            og_update_acls_task,
                            TASK_ONE_SHOT,
                            TASK_PRIORITY_MEDIUM_MEDIUM);
    sprintf(tlb, "%s : [p_og : %s,  c_og : %s]  Scheduling ACLs Update for %s\n",
            FWALL_OBJGRP_UPDATE, p_og->og_name, c_og->og_name,
            is_delete ? "delete" : "create");
    tcp_trace(node, 0, tlb);
}

void object_grp_update_mem_init()
{

    MM_REG_STRUCT(0, object_group_update_info_t);
}