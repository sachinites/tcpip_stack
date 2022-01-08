#include <stddef.h>
#include <assert.h>
#include "eiprt.h"
#include "../../BitOp/bitsop.h"

static bool 
rt_entry_is_bit_set (ert_entry_t *rt_entry, int level) {

    assert(level < rt_entry->mask_len);
    uint32_t bitn = 1 << (31 - level);
    return (IS_BIT_SET(rt_entry->addr, bitn));
}

static void
rt_entry_swap(ert_entry_t *parent_rt_entry,
                        ert_entry_t *existing_rt_entry,
                        ert_entry_t *new_rt_entry) {

    assert (new_rt_entry->left == NULL &&
                new_rt_entry->right == NULL);

    new_rt_entry->left = existing_rt_entry->left;
    new_rt_entry->right = existing_rt_entry->right;
    existing_rt_entry->left = NULL;
    existing_rt_entry->right = NULL;

    if (!parent_rt_entry) return;

    if (parent_rt_entry->left == existing_rt_entry) {
        parent_rt_entry->left = new_rt_entry;
    }
    else {
        parent_rt_entry->right = new_rt_entry;
    }
}

static bool
_ert_entry_add_route(ert_table_t *rt_table,
                                    ert_entry_t *x, // new rt entry
                                    ert_entry_t *y, // current
                                    ert_entry_t *p_y, // parent of y
                                    int level) {   

}

bool
ert_entry_add_route(ert_table_t *rt_table, ert_entry_t *rt_entry) {

    assert (rt_entry->left == NULL && rt_entry->right == NULL);

    if (!rt_table->root) {
        rt_table->root = rt_entry;
        return true;
    }

    return _ert_entry_add_route(rt_table, rt_entry, rt_table->root, NULL, 0);
}