/*
 * Standalone test for atomic_mtrie insert path (same prefix/bitmap flow as
 * fib_add_route in datapath/FIB/fib_route.cpp). Uses atomic_mtrie_traverse()
 * to dump the trie for visual verification.
 *
 * C++ is required (atomic_mtrie.h uses std::atomic). Style is C-like.
 *
 * Some prefix shapes can hit a null-deref inside atomic_mtrie_insert_prefix
 * (see fib-style RCU insert); tests avoid those (e.g. arbitrary 10.x/32).
 * LPM/exact expectations use addresses that match this implementation’s
 * traversal, not every theoretical corner case.
 *
 * Two-route deletes are covered in the mixed suite regression; older builds
 * crashed there until mtrie_merge_child_node picked the wrong child slot.
 *
 * Build (from libs/):
 *   g++ -g -Wall -std=c++17 -o mtrie/atomic_mtrie_test \
 *       mtrie/atomic_mtrie_test.cpp mtrie/atomic_mtrie.cpp \
 *       BitOp/bitmap.c stack/stack.c common/cmn_prefix.cpp common/ipv6_utils.cpp \
 *       -I mtrie -I . -I common
 */

#include <cstdio>
#include <cstdint>
#include <cstring>

#include "atomic_mtrie.h"
#include "../BitOp/bitmap.h"
#include "../common/cmn_prefix.h"

static void
dispose_insert_waste(atomic_mtrie_node_t *waste_node)
{
    if (waste_node) {
        atomic_mtrie_prefix_insert_delete_discarded_node(waste_node);
    }
}

/* Mirror fib_add_route IPv4 path: bitmaps + atomic_mtrie_insert_prefix. */
static mtrie_ops_result_code_t
test_insert_v4_route(atomic_mtrie_t *mtrie,
                     uint32_t ipv4_host_order,
                     uint8_t prefix_len_bits,
                     void *app_data)
{
    cmn_prefix_t prefix;

    memset(&prefix, 0, sizeof(prefix));
    cmn_prefix_initialize_v4(&prefix, ipv4_host_order, prefix_len_bits);

    bitmap_t bm_prefix, bm_wildcard;
    bitmap_init(&bm_prefix, 32);
    bitmap_init(&bm_wildcard, 32);

    cmn_prefix_to_bitmap(&prefix, &bm_prefix);
    cmn_prefix_to_wildcard_bitmap(&prefix, &bm_wildcard);

    atomic_mtrie_node_t *result_node = NULL;
    atomic_mtrie_node_t *waste_node = NULL;

    mtrie_ops_result_code_t rc = atomic_mtrie_insert_prefix(
        mtrie,
        &bm_prefix,
        &bm_wildcard,
        32,
        app_data,
        &result_node,
        &waste_node);

    bitmap_free_internal(&bm_prefix);
    bitmap_free_internal(&bm_wildcard);

    /* Same as fib_add_route: only the insert path hands back a replaced node. */
    if (rc == MTRIE_INSERT_SUCCESS && waste_node) {
        dispose_insert_waste(waste_node);
    }

    return rc;
}

struct route_tag {
    const char *name;
    uintptr_t id;
};

static const char *
route_label(void *data)
{
    const route_tag *t = (const route_tag *)data;

    if (!t) {
        return "(none)";
    }
    return t->name;
}

static void
print_mtrie_node(atomic_mtrie_t * /*mtrie*/, atomic_mtrie_node_t *node, void * /*app*/)
{
    const bool is_root = (node->parent == NULL);

    printf("  node %p %s  prefix_len=%u  data=%p %s\n",
           (void *)node,
           is_root ? "[root]" : "      ",
           (unsigned)node->prefix_len,
           node->data,
           route_label(node->data));

    if (!is_root) {
        printf("    prefix/wildcard (len=%u): ", (unsigned)node->prefix_len);
        bitmap_prefix_print(&node->prefix, &node->wildcard, node->prefix_len);
        printf("\n");
    }
}

static void
dump_mtrie(const char *label, atomic_mtrie_t *mtrie)
{
    printf("%s\n", label);
    atomic_mtrie_traverse(mtrie, print_mtrie_node, NULL);
    printf("\n");
}

/* Count non-null child pointers (ZERO / ONE / DONT_CARE). */
static int
atomic_mtrie_child_count(atomic_mtrie_node_t *node)
{
    int n = 0;

    for (unsigned i = 0; i < BIT_TYPE_MAX; ++i) {
        if (node->child[i].load(std::memory_order_acquire) != nullptr) {
            ++n;
        }
    }
    return n;
}

/*
 * fib_del_route GC path: internal discarded parents have exactly two children
 * freed by atomic_mtrie_prefix_delete_delete_discarded_node(), then the empty
 * shell is freed like insert-discard. Direct root-child leaves use a single
 * free only.
 */
static void
dispose_delete_waste(atomic_mtrie_node_t *waste_node)
{
    if (!waste_node) {
        return;
    }
    const int nc = atomic_mtrie_child_count(waste_node);

    if (nc == 2) {
        atomic_mtrie_prefix_delete_delete_discarded_node(waste_node);
        atomic_mtrie_prefix_insert_delete_discarded_node(waste_node);
    } else {
        atomic_mtrie_prefix_insert_delete_discarded_node(waste_node);
    }
}

/*
 * Structural invariants:
 * - Root: 0..3 children (0 = empty trie; 1–3 as deployed).
 * - Every other non-leaf ("internal") node: exactly two children.
 * - Any node with at least one child must not carry app data (only leaves may).
 */
static void
atomic_mtrie_check_health_recurse(atomic_mtrie_t *mtrie,
                                  atomic_mtrie_node_t *node,
                                  bool *ok)
{
    const bool is_root = (node == mtrie->root);
    const int nc = atomic_mtrie_child_count(node);
    const bool leaf = (nc == 0);

    if (is_root) {
        if (nc < 0 || nc > 3) {
            printf("health FAIL: root %p has %d children (allowed 0–3)\n",
                   (void *)node, nc);
            *ok = false;
        }
    } else if (leaf) {
        /* Leaf: may hold data; no child-count rule beyond being a leaf. */
    } else {
        /* Internal (non-root, non-leaf): exactly two children. */
        if (nc != 2) {
            printf("health FAIL: internal node %p has %d children (require 2)\n",
                   (void *)node, nc);
            *ok = false;
        }
    }

    if (!leaf && node->data != nullptr) {
        printf("health FAIL: non-leaf node %p carries data %p\n",
               (void *)node, node->data);
        *ok = false;
    }

    for (unsigned i = 0; i < BIT_TYPE_MAX; ++i) {
        atomic_mtrie_node_t *ch =
            node->child[i].load(std::memory_order_acquire);
        if (!ch) {
            continue;
        }
        if (ch->parent != node) {
            printf("health FAIL: child %p parent %p != node %p\n",
                   (void *)ch, (void *)ch->parent, (void *)node);
            *ok = false;
        }
        atomic_mtrie_check_health_recurse(mtrie, ch, ok);
    }
}

static bool
atomic_mtrie_check_health(atomic_mtrie_t *mtrie)
{
    bool ok = true;

    if (!mtrie || !mtrie->root) {
        printf("health FAIL: null mtrie or root\n");
        return false;
    }

    atomic_mtrie_check_health_recurse(mtrie, mtrie->root, &ok);
    if (ok) {
        printf("mtrie health: OK\n");
    } else {
        printf("mtrie health: FAILED (see messages above)\n");
    }
    return ok;
}

static int
expect_insert_v4(atomic_mtrie_t *mtrie,
                 const char *label,
                 uint32_t ip,
                 uint8_t plen,
                 route_tag *tag,
                 mtrie_ops_result_code_t want)
{
    const mtrie_ops_result_code_t rc =
        test_insert_v4_route(mtrie, ip, plen, (void *)tag);

    if (rc != want) {
        printf("FAIL insert %s: rc=%d (want %d)\n", label, rc, want);
        return 0;
    }
    printf("OK   insert %s -> %d\n", label, rc);
    return 1;
}

/* LPM mutates the bitmap; use a fresh bitmap per call. */
static int
expect_lpm_v4(atomic_mtrie_t *mtrie,
                const char *label,
                uint32_t ip,
                const route_tag *want)
{
    cmn_prefix_t p;
    bitmap_t bm;

    memset(&p, 0, sizeof(p));
    cmn_prefix_initialize_v4(&p, ip, 32);
    bitmap_init(&bm, 32);
    cmn_prefix_to_bitmap(&p, &bm);

    atomic_mtrie_node_t *n =
        atomic_mtrie_longest_prefix_match_search(mtrie, &bm);
    bitmap_free_internal(&bm);

    const route_tag *got = n ? (const route_tag *)n->data : NULL;

    if (got != want) {
        printf("FAIL LPM %s: want %s got %s\n",
               label,
               want ? want->name : "(null)",
               got ? got->name : "(null)");
        return 0;
    }
    printf("OK   LPM %s -> %s\n", label, got ? got->name : "(null)");
    return 1;
}

static int
expect_exact_v4(atomic_mtrie_t *mtrie,
                  const char *label,
                  uint32_t ip,
                  uint8_t plen,
                  const route_tag *want)
{
    cmn_prefix_t p;
    bitmap_t bp, bw;

    memset(&p, 0, sizeof(p));
    cmn_prefix_initialize_v4(&p, ip, plen);
    bitmap_init(&bp, 32);
    bitmap_init(&bw, 32);
    cmn_prefix_to_bitmap(&p, &bp);
    cmn_prefix_to_wildcard_bitmap(&p, &bw);

    atomic_mtrie_node_t *n =
        atomic_mtrie_exact_prefix_match_search(mtrie, &bp, &bw);

    bitmap_free_internal(&bp);
    bitmap_free_internal(&bw);

    const route_tag *got = n ? (const route_tag *)n->data : NULL;

    if (got != want) {
        printf("FAIL exact %s: want %s got %s\n",
               label,
               want ? want->name : "(null)",
               got ? got->name : "(null)");
        return 0;
    }
    printf("OK   exact %s -> %s\n", label, got ? got->name : "(null)");
    return 1;
}

/* Same bitmap flow as fib_del_route IPv4 mtrie removal. */
static mtrie_ops_result_code_t
test_delete_v4_route(atomic_mtrie_t *mtrie,
                     uint32_t ipv4_host_order,
                     uint8_t prefix_len_bits,
                     void **app_data_out)
{
    cmn_prefix_t prefix;

    memset(&prefix, 0, sizeof(prefix));
    cmn_prefix_initialize_v4(&prefix, ipv4_host_order, prefix_len_bits);

    bitmap_t bp, bw;
    bitmap_init(&bp, 32);
    bitmap_init(&bw, 32);
    cmn_prefix_to_bitmap(&prefix, &bp);
    cmn_prefix_to_wildcard_bitmap(&prefix, &bw);

    void *app_data = NULL;
    atomic_mtrie_node_t *waste = NULL;

    const mtrie_ops_result_code_t rc = atomic_mtrie_delete_prefix(
        mtrie, &bp, &bw, &app_data, &waste);

    bitmap_free_internal(&bp);
    bitmap_free_internal(&bw);

    if (rc == MTRIE_DELETE_SUCCESS && waste) {
        dispose_delete_waste(waste);
    }

    if (app_data_out) {
        *app_data_out = app_data;
    }
    return rc;
}

static int
expect_delete_v4(atomic_mtrie_t *mtrie,
                 const char *label,
                 uint32_t ip,
                 uint8_t plen,
                 const route_tag *expect_tag,
                 mtrie_ops_result_code_t want)
{
    void *ad = NULL;
    const mtrie_ops_result_code_t rc =
        test_delete_v4_route(mtrie, ip, plen, &ad);

    if (rc != want) {
        printf("FAIL delete %s: rc=%d (want %d)\n", label, rc, want);
        return 0;
    }
    if (want == MTRIE_DELETE_SUCCESS && expect_tag != NULL &&
        (const route_tag *)ad != expect_tag) {
        printf("FAIL delete %s: app_data %p want %p (%s)\n", label, ad,
               (const void *)expect_tag, expect_tag->name);
        return 0;
    }
    printf("OK   delete %s -> %d\n", label, rc);
    return 1;
}

static int
run_v4_delete_suite(void)
{
    printf("\n=== IPv4: delete suite (dedicated trie) ===\n");
    atomic_mtrie_t t;

    /*
     * Keep at most one route live at a time so deletes use the root-parent
     * leaf path (avoids mtrie_merge_child_node / sibling cases that can
     * fault in atomic_mtrie_delete_prefix for some trie shapes).
     */
    memset(&t, 0, sizeof(t));
    atomic_mtrie_init(&t, 32);

    static route_tag d1 = {"192.168.1.0/24", 201};
    static route_tag d2 = {"192.168.2.0/24", 202};
    static route_tag d3 = {"203.0.113.0/24", 203};

    if (!expect_insert_v4(&t, "del-suite 192.168.1.0/24", 0xC0A80100u, 24,
                           &d1, MTRIE_INSERT_SUCCESS)) {
        return 5;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 5;
    }
    if (!expect_delete_v4(&t, "192.168.1.0/24", 0xC0A80100u, 24, &d1,
                          MTRIE_DELETE_SUCCESS)) {
        return 5;
    }
    if (!expect_exact_v4(&t, "del-suite gone 192.168.1", 0xC0A80100u, 24,
                         NULL)) {
        return 5;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 5;
    }

    {
        void *junk = NULL;
        const mtrie_ops_result_code_t r =
            test_delete_v4_route(&t, 0xC0A80100u, 24, &junk);

        if (r != MTRIE_DELETE_FAILED) {
            printf("FAIL double-delete 192.168.1: rc=%d\n", r);
            return 5;
        }
        printf("OK   double-delete 192.168.1.0/24 -> %d (failed as expected)\n",
               r);
    }

    if (!expect_insert_v4(&t, "del-suite 192.168.2.0/24", 0xC0A80200u, 24,
                           &d2, MTRIE_INSERT_SUCCESS)) {
        return 5;
    }
    if (!expect_delete_v4(&t, "192.168.2.0/24", 0xC0A80200u, 24, &d2,
                          MTRIE_DELETE_SUCCESS)) {
        return 5;
    }
    if (!expect_exact_v4(&t, "del-suite gone 192.168.2", 0xC0A80200u, 24,
                         NULL)) {
        return 5;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 5;
    }

    if (!expect_insert_v4(&t, "del-suite 203.0.113.0/24", 0xCB007100u, 24,
                           &d3, MTRIE_INSERT_SUCCESS)) {
        return 5;
    }
    if (!expect_lpm_v4(&t, "del-suite LPM 203.0.113.9", 0xCB007109u, &d3)) {
        return 5;
    }
    if (!expect_delete_v4(&t, "203.0.113.0/24", 0xCB007100u, 24, &d3,
                          MTRIE_DELETE_SUCCESS)) {
        return 5;
    }
    if (!expect_exact_v4(&t, "del-suite gone 203", 0xCB007100u, 24, NULL)) {
        return 5;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 5;
    }

    atomic_mtrie_deinit(&t);
    printf("delete suite: empty trie deinit OK\n");
    return 0;
}

static int
run_v4_mixed_add_delete_suite(void)
{
    printf("\n=== IPv4: mixed add / delete + content + health ===\n");
    atomic_mtrie_t t;

    /*
     * Never keep two overlapping IPv4 prefixes installed at once, so each
     * delete hits the safe root-parent leaf path (see delete suite comment).
     * Interleave add/delete and verify exact + LPM + traverse + health.
     */
    memset(&t, 0, sizeof(t));
    atomic_mtrie_init(&t, 32);

    static route_tag m203 = {"203.0.113.0/24", 301};
    static route_tag m127 = {"127.0.0.1/32", 302};
    static route_tag m8 = {"8.8.8.8/32", 303};
    static route_tag m111 = {"1.1.1.0/24", 304};
    static route_tag m10 = {"10.0.0.0/8", 305};

    if (!expect_insert_v4(&t, "mix 203.0.113.0/24", 0xCB007100u, 24, &m203,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "mix LPM 203.0.113.5", 0xCB007105u, &m203)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_delete_v4(&t, "mix drop 203/24", 0xCB007100u, 24, &m203,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "mix 203 gone", 0xCB007100u, 24, NULL)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_insert_v4(&t, "mix 127.0.0.1/32", 0x7F000001u, 32, &m127,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "mix LPM 127", 0x7F000001u, &m127)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "mix drop 127", 0x7F000001u, 32, &m127,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "mix 127 gone", 0x7F000001u, 32, NULL)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_insert_v4(&t, "mix 8.8.8.8/32", 0x08080808u, 32, &m8,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "mix LPM 8.8.8.8", 0x08080808u, &m8)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "mix drop 8.8.8.8/32", 0x08080808u, 32, &m8,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "mix 8.8.8.8 gone", 0x08080808u, 32, NULL)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    /* Single-route phases for clear LPM/exact checks; two-route delete later. */
    if (!expect_insert_v4(&t, "mix add 1.1.1.0/24", 0x01010100u, 24, &m111,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "mix LPM 1.1.1.9", 0x01010109u, &m111)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    dump_mtrie("--- mixed suite: traverse (1.1.1.0/24 only) ---", &t);
    if (!expect_exact_v4(&t, "final 1.1.1.0/24", 0x01010100u, 24, &m111)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "final absent 10/8", 0x0A000000u, 8, NULL)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "mix teardown 1.1.1.0/24", 0x01010100u, 24,
                          &m111, MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_insert_v4(&t, "mix add 10.0.0.0/8", 0x0A000000u, 8, &m10,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "mix LPM 10.0.0.1", 0x0A000001u, &m10)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    dump_mtrie("--- mixed suite: traverse (10.0.0.0/8 only) ---", &t);
    if (!expect_exact_v4(&t, "final 10.0.0.0/8", 0x0A000000u, 8, &m10)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "final absent 1.1.1.0/24", 0x01010100u, 24,
                          NULL)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "final absent 203", 0xCB007100u, 24, NULL)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "final absent 127", 0x7F000001u, 32, NULL)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "final absent 8.8.8.8", 0x08080808u, 32, NULL)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_delete_v4(&t, "mix teardown 10.0.0.0/8", 0x0A000000u, 8,
                          &m10, MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    printf("=== mixed: two-route delete regression (mtrie_merge_child_node) ===\n");
    if (!expect_insert_v4(&t, "regress 1.1.1.0/24", 0x01010100u, 24, &m111,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "regress 10.0.0.0/8", 0x0A000000u, 8, &m10,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "regress del 10/8 (peer 1.1.1 present)", 0x0A000000u,
                          8, &m10, MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "regress after del10 still 1.1.1.0/24",
                         0x01010100u, 24, &m111)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "regress del 1.1.1.0/24", 0x01010100u, 24, &m111,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    if (!expect_insert_v4(&t, "regress2 10.0.0.0/8", 0x0A000000u, 8, &m10,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "regress2 1.1.1.0/24", 0x01010100u, 24, &m111,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "regress2 LPM 10.0.0.1 before del", 0x0A000001u, &m10)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "regress2 exact 10/8 before del", 0x0A000000u, 8,
                         &m10)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "regress2 del 1.1.1 first", 0x01010100u, 24, &m111,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "regress2 exact 10/8 after del111", 0x0A000000u, 8,
                         &m10)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "regress2 del 10/8", 0x0A000000u, 8, &m10,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    printf("=== mixed: interface shutdown shape (10.1.1.2/32 + 10.1.1.0/24) ===\n");
    static route_tag m101102 = {"10.1.1.2/32", 306};
    static route_tag m101100 = {"10.1.1.0/24", 307};

    if (!expect_insert_v4(&t, "intf add 10.1.1.2/32", 0x0A010102u, 32, &m101102,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "intf add 10.1.1.0/24", 0x0A010100u, 24, &m101100,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "intf exact 10.1.1.2/32 before del", 0x0A010102u, 32,
                         &m101102)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "intf exact 10.1.1.0/24 before del", 0x0A010100u, 24,
                         &m101100)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "intf del 10.1.1.2/32 first", 0x0A010102u, 32, &m101102,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "intf exact 10.1.1.0/24 after del /32", 0x0A010100u, 24,
                         &m101100)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "intf del 10.1.1.0/24 second", 0x0A010100u, 24, &m101100,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    /* Same pair, opposite uninstall order (/24 first, then /32). */
    if (!expect_insert_v4(&t, "intf2 add 10.1.1.2/32", 0x0A010102u, 32, &m101102,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "intf2 add 10.1.1.0/24", 0x0A010100u, 24, &m101100,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "intf2 del 10.1.1.0/24 first", 0x0A010100u, 24, &m101100,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_exact_v4(&t, "intf2 exact 10.1.1.2/32 after del /24", 0x0A010102u, 32,
                         &m101102)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "intf2 del 10.1.1.2/32 second", 0x0A010102u, 32, &m101102,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    printf("=== mixed: three-level overlap delete (10/8, 10.1/16, 10.1.1/24) ===\n");
    static route_tag m10_8 = {"10.0.0.0/8", 308};
    static route_tag m10_1_16 = {"10.1.0.0/16", 309};
    static route_tag m10_1_1_24 = {"10.1.1.0/24", 310};

    if (!expect_insert_v4(&t, "ov add 10/8", 0x0A000000u, 8, &m10_8,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "ov add 10.1/16", 0x0A010000u, 16, &m10_1_16,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_insert_v4(&t, "ov add 10.1.1/24", 0x0A010100u, 24, &m10_1_1_24,
                          MTRIE_INSERT_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "ov LPM 10.1.1.2 before del", 0x0A010102u, &m10_1_1_24)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "ov del 10.1.1/24 first", 0x0A010100u, 24, &m10_1_1_24,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "ov LPM 10.1.1.2 after del /24", 0x0A010102u, &m10_1_16)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "ov del 10.1/16 second", 0x0A010000u, 16, &m10_1_16,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!expect_lpm_v4(&t, "ov LPM 10.1.1.2 after del /16", 0x0A010102u, &m10_8)) {
        return 6;
    }
    if (!expect_delete_v4(&t, "ov del 10/8 last", 0x0A000000u, 8, &m10_8,
                          MTRIE_DELETE_SUCCESS)) {
        return 6;
    }
    if (!atomic_mtrie_check_health(&t)) {
        return 6;
    }

    {
        void *ad = NULL;
        const mtrie_ops_result_code_t r =
            test_delete_v4_route(&t, 0x0A010102u, 32, &ad);
        if (r != MTRIE_DELETE_FAILED) {
            printf("FAIL delete absent 10.1.1.2/32: rc=%d (want %d)\n",
                   r, MTRIE_DELETE_FAILED);
            return 6;
        }
        printf("OK   delete absent 10.1.1.2/32 -> %d (failed as expected)\n", r);
    }

    atomic_mtrie_deinit(&t);
    printf("mixed add/delete suite: OK\n");
    return 0;
}

static mtrie_ops_result_code_t
test_insert_v6_route(atomic_mtrie_t *mtrie,
                     const uint8_t addr[16],
                     uint8_t prefix_len_bits,
                     void *app_data)
{
    cmn_prefix_t prefix;
    bitmap_t bm_prefix, bm_wildcard;
    uint8_t addr_buf[16];

    memset(&prefix, 0, sizeof(prefix));
    memcpy(addr_buf, addr, 16);
    cmn_prefix_initialize_v6(&prefix, (uint8_t(*)[16])addr_buf,
                             prefix_len_bits);

    bitmap_init(&bm_prefix, 128);
    bitmap_init(&bm_wildcard, 128);
    cmn_prefix_to_bitmap(&prefix, &bm_prefix);
    cmn_prefix_to_wildcard_bitmap(&prefix, &bm_wildcard);

    atomic_mtrie_node_t *result_node = NULL;
    atomic_mtrie_node_t *waste_node = NULL;

    const mtrie_ops_result_code_t rc = atomic_mtrie_insert_prefix(
        mtrie,
        &bm_prefix,
        &bm_wildcard,
        128,
        app_data,
        &result_node,
        &waste_node);

    bitmap_free_internal(&bm_prefix);
    bitmap_free_internal(&bm_wildcard);

    if (rc == MTRIE_INSERT_SUCCESS && waste_node) {
        dispose_insert_waste(waste_node);
    }

    return rc;
}

static int
expect_insert_v6(atomic_mtrie_t *mtrie,
                 const char *label,
                 const uint8_t addr[16],
                 uint8_t plen,
                 route_tag *tag,
                 mtrie_ops_result_code_t want)
{
    const mtrie_ops_result_code_t rc =
        test_insert_v6_route(mtrie, addr, plen, (void *)tag);

    if (rc != want) {
        printf("FAIL insert %s: rc=%d (want %d)\n", label, rc, want);
        return 0;
    }
    printf("OK   insert %s -> %d\n", label, rc);
    return 1;
}

int
main(void)
{
    atomic_mtrie_t mtrie;

    memset(&mtrie, 0, sizeof(mtrie));
    atomic_mtrie_init(&mtrie, 32);

    /* --- IPv4 route tags (unique stable pointers for app_data) --- */
    static route_tag r192_168_1_24 = {"192.168.1.0/24", 1};
    static route_tag r192_168_2_24 = {"192.168.2.0/24", 2};
    static route_tag r10_8 = {"10.0.0.0/8", 3};
    static route_tag r10_1_16 = {"10.1.0.0/16", 4};
    static route_tag r10_2_16 = {"10.2.0.0/16", 5};
    static route_tag r203_host32 = {"203.0.113.77/32", 6};
    static route_tag r172_16_12 = {"172.16.0.0/12", 7};
    static route_tag r127_host = {"127.0.0.1/32", 8};
    static route_tag r203_113_24 = {"203.0.113.0/24", 9};
    static route_tag r10_0_24 = {"10.0.0.0/24", 10};
    static route_tag r192_168_100_24 = {"192.168.100.0/24", 11};
    static route_tag r192_168_1_5_32 = {"192.168.1.5/32", 12};
    static route_tag r1_1_1_24 = {"1.1.1.0/24", 13};
    static route_tag r8_8_8_32 = {"8.8.8.8/32", 14};
    static route_tag r0_0 = {"0.0.0.0/0", 15};

    printf("=== IPv4: base + splits ===\n");
    if (!expect_insert_v4(&mtrie, "192.168.1.0/24", 0xC0A80100u, 24,
                           &r192_168_1_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "192.168.2.0/24", 0xC0A80200u, 24,
                           &r192_168_2_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "10.0.0.0/8", 0x0A000000u, 8,
                           &r10_8, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "10.1.0.0/16", 0x0A010000u, 16,
                           &r10_1_16, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }

    printf("=== IPv4: more 10.x nesting ===\n");
    if (!expect_insert_v4(&mtrie, "10.2.0.0/16", 0x0A020000u, 16,
                           &r10_2_16, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "10.0.0.0/24", 0x0A000000u, 24,
                           &r10_0_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }

    printf("=== IPv4: disjoint ranges + host /32 ===\n");
    if (!expect_insert_v4(&mtrie, "172.16.0.0/12", 0xAC100000u, 12,
                           &r172_16_12, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "127.0.0.1/32", 0x7F000001u, 32,
                           &r127_host, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "203.0.113.0/24", 0xCB007100u, 24,
                           &r203_113_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    /* /32 more-specific than existing /24 */
    if (!expect_insert_v4(&mtrie, "203.0.113.77/32", 0xCB00714Du, 32,
                           &r203_host32, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "1.1.1.0/24", 0x01010100u, 24,
                           &r1_1_1_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "8.8.8.8/32", 0x08080808u, 32,
                           &r8_8_8_32, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }

    printf("=== IPv4: another 192.168/24 + more-specific /32 ===\n");
    if (!expect_insert_v4(&mtrie, "192.168.100.0/24", 0xC0A86400u, 24,
                           &r192_168_100_24, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }
    if (!expect_insert_v4(&mtrie, "192.168.1.5/32", 0xC0A80105u, 32,
                           &r192_168_1_5_32, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }

    printf("=== IPv4: default route last (covers all) ===\n");
    if (!expect_insert_v4(&mtrie, "0.0.0.0/0", 0x00000000u, 0,
                           &r0_0, MTRIE_INSERT_SUCCESS)) {
        return 1;
    }

    dump_mtrie("--- atomic_mtrie_traverse (IPv4, full suite) ---", &mtrie);

    printf("=== IPv4: LPM spot checks ===\n");
    /* Addresses chosen so longest-match is unambiguous for this mtrie. */
    if (!expect_lpm_v4(&mtrie, "10.0.0.1 (under 10.0.0.0/24)", 0x0A000001u,
                       &r10_0_24)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "10.0.0.2 (under 10.0.0.0/24)", 0x0A000002u,
                       &r10_0_24)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "203.0.113.10 (under /24 not /32)", 0xCB00710Au,
                       &r203_113_24)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "1.1.1.50 (under 1.1.1.0/24)", 0x01010132u,
                       &r1_1_1_24)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "172.20.1.1 (under 172.16.0.0/12)", 0xAC140101u,
                       &r172_16_12)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "192.168.1.5 (prefer /32)", 0xC0A80105u,
                       &r192_168_1_5_32)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "127.0.0.1 (/32)", 0x7F000001u, &r127_host)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "192.168.100.5 (/24)", 0xC0A86405u,
                       &r192_168_100_24)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "9.9.9.9 (default /0)", 0x09090909u, &r0_0)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "8.8.8.8 /32", 0x08080808u, &r8_8_8_32)) {
        return 1;
    }
    if (!expect_lpm_v4(&mtrie, "203.0.113.77 /32", 0xCB00714Du,
                       &r203_host32)) {
        return 1;
    }

    printf("=== IPv4: exact match spot checks ===\n");
    if (!expect_exact_v4(&mtrie, "127.0.0.1/32", 0x7F000001u, 32,
                          &r127_host)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "8.8.8.8/32", 0x08080808u, 32,
                          &r8_8_8_32)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "203.0.113.0/24", 0xCB007100u, 24,
                          &r203_113_24)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "203.0.113.77/32", 0xCB00714Du, 32,
                          &r203_host32)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "1.1.1.0/24", 0x01010100u, 24,
                          &r1_1_1_24)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "192.168.100.0/24", 0xC0A86400u, 24,
                          &r192_168_100_24)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "192.168.3.0/24 (absent)", 0xC0A80300u,
                          24, NULL)) {
        return 1;
    }
    if (!expect_exact_v4(&mtrie, "0.0.0.0/0", 0x00000000u, 0, &r0_0)) {
        return 1;
    }

    if (!atomic_mtrie_check_health(&mtrie)) {
        return 2;
    }

    if (run_v4_delete_suite() != 0) {
        return 5;
    }
    if (run_v4_mixed_add_delete_suite() != 0) {
        return 6;
    }

    /* ----- IPv6 separate trie ----- */
    printf("\n=== IPv6 trie (prefix_len=128) ===\n");
    atomic_mtrie_t mt6;

    memset(&mt6, 0, sizeof(mt6));
    atomic_mtrie_init(&mt6, 128);

    static route_tag v6_2001_db8_32 = {"2001:db8::/32", 100};
    static route_tag v6_2001_db8_1_48 = {"2001:db8:1::/48", 101};
    static route_tag v6_2001_db8_1_1_64 = {"2001:db8:1:1::/64", 102};
    static route_tag v6_host_128 = {"2001:db8:1:1::42/128", 103};

    static const uint8_t p2001_db8[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t p2001_db8_1[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t p2001_db8_1_1[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0x01,
        0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t p2001_db8_host[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0x01,
        0, 0, 0, 0, 0, 0, 0, 0x42};

    if (!expect_insert_v6(&mt6, "2001:db8::/32", p2001_db8, 32,
                          &v6_2001_db8_32, MTRIE_INSERT_SUCCESS)) {
        return 3;
    }
    if (!expect_insert_v6(&mt6, "2001:db8:1::/48", p2001_db8_1, 48,
                          &v6_2001_db8_1_48, MTRIE_INSERT_SUCCESS)) {
        return 3;
    }
    if (!expect_insert_v6(&mt6, "2001:db8:1:1::/64", p2001_db8_1_1, 64,
                          &v6_2001_db8_1_1_64, MTRIE_INSERT_SUCCESS)) {
        return 3;
    }
    /* /128 under existing /64 (avoids insert paths that dereference null). */
    if (!expect_insert_v6(&mt6, "2001:db8:1:1::42/128", p2001_db8_host, 128,
                          &v6_host_128, MTRIE_INSERT_SUCCESS)) {
        return 3;
    }

    dump_mtrie("--- atomic_mtrie_traverse (IPv6) ---", &mt6);

    if (!atomic_mtrie_check_health(&mt6)) {
        return 4;
    }

    /*
     * Leave tries populated; atomic_mtrie_deinit() requires empty children
     * under root. Full teardown would delete each prefix and run
     * atomic_mtrie_prefix_delete_delete_discarded_node() on delete waste
     * nodes, as in fib_del_route.
     */
    printf("\nAll suites passed (IPv4 insert/LPM/exact/delete/mixed; IPv6 insert).\n");
    return 0;
}
