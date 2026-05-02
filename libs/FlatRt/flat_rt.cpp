#include <stdlib.h>
#include <assert.h>
#include "flat_rt.h"

static flat_rt_lvl_t *
level_clone (flat_rt_lvl_t *lvl) {

    flat_rt_entry_t *rt_entry;
    flat_rt_entry_t *rt_entry_new;

    if (!lvl) return NULL;
    flat_rt_lvl_t *new_lvl = (flat_rt_lvl_t *)calloc(1, sizeof(flat_rt_lvl_t));

    rt_entry = &lvl->entries[0];
    rt_entry_new = &new_lvl->entries[0];

    for (int i=0; i < LEVEL_MAX_ENTRIES; i++) {

        rt_entry_new->app_data.store(
                rt_entry->app_data.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        rt_entry_new->next_lvl.store(
                rt_entry->next_lvl.load(std::memory_order_relaxed));
    }

    new_lvl->num_datas = lvl->num_datas;
    new_lvl->num_children = lvl->num_children;

    return new_lvl;
}


mtrie_ops_result_code_t
flat_rt_v4_insert (flat_rt_t *rt, 
                   uint32_t prefix, 
                   uint8_t prefix_len, 
                   void *app_data) {


    uint32_t index;
    bool new_lvl = false;
    flat_rt_lvl_t *lvl0 = rt->level0;

    if (prefix_len > 32) return FLAT_RT_INSERT_FAILED;

    if (prefix_len <= 16) {
        
        index = prefix >> 16;
        flat_rt_entry_t *rt_entry = &lvl0->entries[index];

        void *app_data_old = rt_entry->app_data.load(std::memory_order_acquire);

        if (app_data_old) return FLAT_RT_INSERT_DUPLICATE;

        /* After thie update, the updated RT table will be visible to all
            readers */
        rt_entry->app_data.store(app_data, std::memory_order_release);
        lvl0->num_datas += 1;
        return FLAT_RT_INSERT_SUCCESS;

    } else {

        index = prefix >> 16;
        flat_rt_entry_t *rt_entry_lvl0 = &lvl0->entries[index];

        flat_rt_lvl_t *lvl1 = rt_entry_lvl0->next_lvl.load(std::memory_order_acquire);

        if (!lvl1) {

            lvl1 = (flat_rt_lvl_t *)calloc(1, sizeof(flat_rt_lvl_t));
            new_lvl = true;
        }

        index = prefix & 0x0000FFFF;

        flat_rt_entry_t *rt_entry_lvl1 = &lvl1->entries[index];

        if (new_lvl) {
            
            rt_entry_lvl1->app_data.store(app_data, std::memory_order_relax);
            lvl1->num_datas += 1;

            rt_entry_lvl0->next_lvl.store(lvl1, std::memory_order_release);
            lvl0->num_children += 1;

            return FLAT_RT_INSERT_SUCCESS;
        }

        void *app_data_old = rt_entry_lvl1->app_data.load(std::memory_order_acquire);

        if (app_data_old) return FLAT_RT_INSERT_DUPLICATE;

        rt_entry_lvl1->app_data.store(app_data, std::memory_order_release);
        lvl1->num_datas += 1;

        return FLAT_RT_INSERT_SUCCESS;
    }

    assert(0);
    return FLAT_RT_INSERT_SUCCESS;
}



flat_rt_t *
flat_rt_create(uint8_t afi)
{

    flat_rt_t *rt = (flat_rt_t *)calloc(1, sizeof(flat_rt_t));
    rt->afi = afi;
    rt->level0 = (flat_rt_lvl_t *)calloc(1, sizeof(flat_rt_lvl_t));
    return rt;
}

