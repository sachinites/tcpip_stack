/*
 * =====================================================================================
 *
 *       Filename:  label_mgr_test.cpp
 *
 *    Description:  Standalone demo/test-driver for the MPLS Label Manager.
 *
 *        Not part of the main tcpstack.exe build - build/run with:
 *            make test        (from within LabelMgr/)
 *            ./label_mgr_test.exe
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <assert.h>
#include "label_mgr.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) {                                                   \
            g_pass++;                                                \
            printf("[PASS] %s\n", msg);                               \
        } else {                                                      \
            g_fail++;                                                 \
            printf("[FAIL] %s\n", msg);                               \
        }                                                              \
    } while (0)

int
main(void)
{
    label_mgr_t *lm = label_mgr_init();
    CHECK(lm != NULL, "label_mgr_init() returns a valid handle");

    label_mgr_client_t ldp0    = label_mgr_make_client(LABEL_CLIENT_LDP, 0);
    label_mgr_client_t static0 = label_mgr_make_client(LABEL_CLIENT_STATIC, 0);
    label_mgr_client_t isis0   = label_mgr_make_client(LABEL_CLIENT_ISIS, 0);
    label_mgr_client_t isis1   = label_mgr_make_client(LABEL_CLIENT_ISIS, 1);
    label_mgr_client_t sr0     = label_mgr_make_client(LABEL_CLIENT_SR_MPLS, 0);
    label_mgr_client_t bgp0    = label_mgr_make_client(LABEL_CLIENT_BGP_LU, 0);
    label_mgr_client_t rsvp0   = label_mgr_make_client(LABEL_CLIENT_RSVP_TE, 0);
    label_mgr_client_t oam0    = label_mgr_make_client(LABEL_CLIENT_OAM, 0);
    label_mgr_client_t l3vpn0  = label_mgr_make_client(LABEL_CLIENT_L3VPN, 0);
    label_mgr_client_t l2vpn0  = label_mgr_make_client(LABEL_CLIENT_L2VPN, 0);
    label_mgr_client_t ospf0   = label_mgr_make_client(LABEL_CLIENT_OSPF, 0);
    label_mgr_client_t ospf1   = label_mgr_make_client(LABEL_CLIENT_OSPF, 1);

    label_mgr_stats_t stats;
    label_mgr_get_stats(lm, &stats);
    CHECK(stats.total_labels == LABEL_MGR_POOL_SIZE, "pool total is exactly 100000");
    CHECK(stats.allocated_labels == 0, "pool starts fully free");

    /* ---- Single label: dynamic alloc ---- */
    uint32_t label1 = 0;
    label_mgr_rc_t rc = label_mgr_alloc_label(lm, ldp0, &label1);
    CHECK(rc == LABEL_MGR_OK && label1 == LABEL_MGR_POOL_MIN,
          "alloc_label() returns first free label (pool min)");

    uint32_t label2 = 0;
    rc = label_mgr_alloc_label(lm, ldp0, &label2);
    CHECK(rc == LABEL_MGR_OK && label2 == LABEL_MGR_POOL_MIN + 1,
          "alloc_label() returns the next free label");

    /* ---- Single label: explicit reserve ---- */
    rc = label_mgr_reserve_label(lm, static0, 16000);
    CHECK(rc == LABEL_MGR_OK, "reserve_label(16000) succeeds for a free label");

    rc = label_mgr_reserve_label(lm, isis0, 16000);
    CHECK(rc == LABEL_MGR_ERR_LABEL_IN_USE,
          "reserve_label(16000) fails - already reserved by another client");

    rc = label_mgr_reserve_label(lm, isis0, 0);
    CHECK(rc == LABEL_MGR_ERR_OUT_OF_RANGE, "reserve_label(0) is rejected - out of pool bounds");

    rc = label_mgr_reserve_label(lm, isis0, LABEL_MGR_POOL_MAX + 1);
    CHECK(rc == LABEL_MGR_ERR_OUT_OF_RANGE, "reserve_label(100001) is rejected - out of pool bounds");

    /* ---- Single label: release ---- */
    rc = label_mgr_release_label(lm, isis0, 16000);
    CHECK(rc == LABEL_MGR_ERR_WRONG_OWNER,
          "release_label(16000) by non-owner ISIS is rejected");

    /* Same type, different instance id must also be rejected as wrong owner */
    rc = label_mgr_release_label(lm, label_mgr_make_client(LABEL_CLIENT_STATIC, 99), 16000);
    CHECK(rc == LABEL_MGR_ERR_WRONG_OWNER,
          "release_label(16000) by same type but different id is rejected");

    rc = label_mgr_release_label(lm, static0, 16000);
    CHECK(rc == LABEL_MGR_OK, "release_label(16000) by the true owner STATIC/0 succeeds");

    rc = label_mgr_release_label(lm, static0, 16000);
    CHECK(rc == LABEL_MGR_ERR_NOT_FOUND, "releasing an already-released label fails with NOT_FOUND");

    /* ---- Two ISIS instances (same type, different id) own distinct labels ---- */
    rc = label_mgr_reserve_label(lm, isis0, 17000);
    CHECK(rc == LABEL_MGR_OK, "ISIS/0 can reserve label 17000");

    rc = label_mgr_reserve_label(lm, isis1, 17001);
    CHECK(rc == LABEL_MGR_OK, "ISIS/1 can reserve a different label");

    rc = label_mgr_release_label(lm, isis1, 17000);
    CHECK(rc == LABEL_MGR_ERR_WRONG_OWNER,
          "ISIS/1 cannot release a label owned by ISIS/0");

    rc = label_mgr_release_label(lm, isis0, 17000);
    CHECK(rc == LABEL_MGR_OK, "ISIS/0 releases its own label");

    rc = label_mgr_release_label(lm, isis1, 17001);
    CHECK(rc == LABEL_MGR_OK, "ISIS/1 releases its own label");

    /* ---- Ranges: dynamic alloc ---- */
    uint32_t range_start = 0;
    rc = label_mgr_alloc_range(lm, sr0, 8000, &range_start);
    CHECK(rc == LABEL_MGR_OK, "alloc_range(8000) for SR-MPLS succeeds");

    uint32_t range_start2 = 0;
    rc = label_mgr_alloc_range(lm, bgp0, 100, &range_start2);
    CHECK(rc == LABEL_MGR_OK && range_start2 >= range_start + 8000,
          "second alloc_range() does not overlap the first");

    /* ---- Ranges: explicit reserve + overlap detection ---- */
    rc = label_mgr_reserve_range(lm, rsvp0, 90000, 5000);
    CHECK(rc == LABEL_MGR_OK, "reserve_range(90000, 5000) succeeds on free space");

    rc = label_mgr_reserve_range(lm, oam0, 94000, 10);
    CHECK(rc == LABEL_MGR_ERR_RANGE_NOT_FREE,
          "reserve_range() overlapping an existing range is rejected");

    rc = label_mgr_reserve_range(lm, oam0, 99995, 10);
    CHECK(rc == LABEL_MGR_ERR_OUT_OF_RANGE,
          "reserve_range() spilling past the pool max is rejected");

    /* ---- Ranges: release ---- */
    rc = label_mgr_release_range(lm, isis0, 90000);
    CHECK(rc == LABEL_MGR_ERR_WRONG_OWNER, "release_range() by non-owner is rejected");

    rc = label_mgr_release_range(lm, rsvp0, 90000);
    CHECK(rc == LABEL_MGR_OK, "release_range() by the true owner succeeds");

    rc = label_mgr_release_range(lm, rsvp0, 90000);
    CHECK(rc == LABEL_MGR_ERR_NOT_FOUND, "releasing an already-released range fails with NOT_FOUND");

    /* release_label must not accept a range's start label */
    rc = label_mgr_release_label(lm, sr0, range_start);
    CHECK(rc == LABEL_MGR_ERR_NOT_FOUND,
          "release_label() refuses a start-label that belongs to a range");

    /* ---- Pool exhaustion boundary test on a tiny dedicated instance ---- */
    {
        label_mgr_t *small_lm = label_mgr_init();
        uint32_t got;
        label_mgr_rc_t last_rc = LABEL_MGR_OK;
        uint32_t count = 0;

        /* Drain the pool one label at a time via dynamic alloc. */
        while ((last_rc = label_mgr_alloc_label(small_lm, static0, &got)) == LABEL_MGR_OK) {
            count++;
        }
        CHECK(count == LABEL_MGR_POOL_SIZE, "dynamic alloc drains the entire fixed pool (1-100000)");
        CHECK(last_rc == LABEL_MGR_ERR_NO_LABELS_AVAILABLE,
              "further alloc_label() on a full pool fails with NO_LABELS_AVAILABLE");

        label_mgr_rc_t range_rc = label_mgr_alloc_range(small_lm, static0, 1, &got);
        CHECK(range_rc == LABEL_MGR_ERR_NO_LABELS_AVAILABLE,
              "alloc_range() on a full pool also fails with NO_LABELS_AVAILABLE");

        label_mgr_destroy(small_lm);
    }

    /* ---- Label blocks: opaque handle reserved from the global pool ---- */
    {
        label_mgr_block_t *block = NULL;
        rc = label_mgr_reserve_block(lm, l3vpn0, 10, &block);
        CHECK(rc == LABEL_MGR_OK && block != NULL,
              "reserve_block(10) for L3VPN returns a valid handle");

        label_mgr_block_stats_t bstats;
        label_mgr_block_get_stats(block, &bstats);
        CHECK(bstats.capacity == 10 && bstats.allocated == 0 && bstats.free == 10,
              "freshly reserved block starts with capacity=10, allocated=0");
        CHECK(label_mgr_client_equal(bstats.client, l3vpn0),
              "block stats carry owning client L3VPN/0");

        /* The block's range must itself now show up as a normal L3VPN
         * reservation at the global-pool level. */
        label_mgr_stats_t stats_before;
        label_mgr_get_stats(lm, &stats_before);

        uint32_t blabel[10];
        bool all_within_block = true;
        for (int i = 0; i < 10; i++) {
            rc = label_mgr_block_alloc_label(block, &blabel[i]);
            if (rc != LABEL_MGR_OK ||
                blabel[i] < bstats.base_label ||
                blabel[i] > bstats.base_label + bstats.capacity - 1) {
                all_within_block = false;
            }
        }
        CHECK(all_within_block, "block_alloc_label() x10 all stay within the reserved range");

        rc = label_mgr_block_alloc_label(block, &blabel[0]);
        CHECK(rc == LABEL_MGR_ERR_NO_LABELS_AVAILABLE,
              "block_alloc_label() on an exhausted (10/10) block fails cleanly");

        label_mgr_get_stats(lm, &stats_before); /* re-fetch, unused beyond sanity */
        label_mgr_block_get_stats(block, &bstats);
        CHECK(bstats.allocated == 10 && bstats.free == 0,
              "block stats reflect all 10 labels allocated");

        rc = label_mgr_block_release_label(block, blabel[3]);
        CHECK(rc == LABEL_MGR_OK, "block_release_label() succeeds for a label held by the block");

        rc = label_mgr_block_release_label(block, blabel[3]);
        CHECK(rc == LABEL_MGR_ERR_NOT_FOUND,
              "releasing the same block label twice fails with NOT_FOUND");

        rc = label_mgr_block_release_label(block, bstats.base_label + 999999);
        CHECK(rc == LABEL_MGR_ERR_OUT_OF_RANGE,
              "block_release_label() rejects a label outside the block's own range");

        uint32_t relabel = 0;
        rc = label_mgr_block_alloc_label(block, &relabel);
        CHECK(rc == LABEL_MGR_OK && relabel == blabel[3],
              "block reuses the just-released slot on the next alloc (first-fit)");

        /* Global pool must not have been touched by any block_alloc/release call:
         * the whole block's range was already marked used the moment it was reserved. */
        label_mgr_stats_t stats_after;
        label_mgr_get_stats(lm, &stats_after);
        CHECK(stats_after.allocated_labels == stats_before.allocated_labels,
              "block-internal alloc/release never changes the global pool's allocated count");

        rc = label_mgr_block_destroy(lm, block, false /* force */);
        CHECK(rc == LABEL_MGR_ERR_BLOCK_NOT_EMPTY,
              "block_destroy() without force refuses a block with outstanding labels");

        rc = label_mgr_block_destroy(lm, block, true /* force */);
        CHECK(rc == LABEL_MGR_OK, "block_destroy(force=true) releases the whole range back to the pool");
    }

    {
        /* reserve_block_at() - explicit start, plus overlap detection against
         * an existing plain range reservation. */
        label_mgr_block_t *block_a = NULL;
        rc = label_mgr_reserve_block_at(lm, ospf0, 50000, 20, &block_a);
        CHECK(rc == LABEL_MGR_OK, "reserve_block_at(50000, 20) succeeds on free space");

        label_mgr_block_t *block_b = NULL;
        rc = label_mgr_reserve_block_at(lm, ospf0, 50010, 5, &block_b);
        CHECK(rc == LABEL_MGR_ERR_RANGE_NOT_FREE,
              "reserve_block_at() overlapping an existing block is rejected");

        /* Exhaust one block, verify a sibling block with a different instance
         * id of the same type is unaffected. */
        label_mgr_block_t *block_c = NULL;
        rc = label_mgr_reserve_block(lm, ospf1, 3, &block_c);
        CHECK(rc == LABEL_MGR_OK, "a second OSPF block with a different id can be reserved");

        uint32_t tmp;
        for (int i = 0; i < 3; i++) {
            CHECK(label_mgr_block_alloc_label(block_c, &tmp) == LABEL_MGR_OK,
                  "block_c alloc_label() succeeds within its own 3-label capacity");
        }
        CHECK(label_mgr_block_alloc_label(block_c, &tmp) == LABEL_MGR_ERR_NO_LABELS_AVAILABLE,
              "block_c is exhausted independently of block_a's own free space");

        uint32_t a_label = 0;
        rc = label_mgr_block_alloc_label(block_a, &a_label);
        CHECK(rc == LABEL_MGR_OK, "block_a can still allocate even though block_c is full");

        printf("\n");
        label_mgr_block_show(block_a);

        label_mgr_block_destroy(lm, block_a, true);
        label_mgr_block_destroy(lm, block_c, true);
    }

    /* ---- Show functions (visual inspection) ---- */
    printf("\n");
    label_mgr_show_client(lm, ldp0);
    printf("\n");
    label_mgr_show_client(lm, sr0);
    printf("\n");
    label_mgr_show_all(lm);

    label_mgr_get_stats(lm, &stats);
    printf("\nFinal stats: total=%u allocated=%u free=%u records=%u\n",
           stats.total_labels, stats.allocated_labels, stats.free_labels, stats.num_records);

    label_mgr_destroy(lm);

    printf("\n=================================================\n");
    printf(" Test summary : %d passed, %d failed\n", g_pass, g_fail);
    printf("=================================================\n");

    return g_fail == 0 ? 0 : 1;
}
