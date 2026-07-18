/* Multi-threaded smoke test for the instance-based, thread-safe parser.
 *
 * Each thread owns its own mexpr_parser_t instance (which in turn owns its own
 * reentrant flex scanner and undo_stack), so concurrent parses must not
 * interfere. A single-threaded baseline is computed first, then many threads
 * repeat the same parses concurrently and assert they get identical results.
 *
 * Build (with ThreadSanitizer):
 *   flex Parser.l
 *   g++ -g -fsanitize=thread -fpermissive \
 *       lex.yy.c ExpressionParser.c mt_thread_test.cpp -o mt_test -lpthread
 *   ./mt_test
 */

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>

#include "ParserExport.h"

/* Grammar entry points implemented in ExpressionParser.c */
extern parse_rc_t E (mexpr_parser_t *p);
extern parse_rc_t S (mexpr_parser_t *p);

/* Application token-code -> Mexpr token-code mapper. The flex rules in
 * Parser.l already emit MATH_CPP_* codes, so an identity mapping is enough
 * for this test. */
int Appln_to_Mexpr_enum_converter (int token_code) { return token_code; }

static std::atomic<int> g_failures {0};

static int
run_parse (const char *expr, parse_rc_t (*fn)(mexpr_parser_t *), parse_rc_t *rc_out) {

    mexpr_parser_t *p = mexpr_parser_create ();
    if (!p) { *rc_out = PARSE_ERR; return -2; }

    strncpy ((char *)p->lex_buffer, expr, sizeof (p->lex_buffer) - 1);
    p->lex_buffer[sizeof (p->lex_buffer) - 1] = '\0';
    lex_set_scan_buffer (p, (const char *)p->lex_buffer);

    parse_rc_t rc = fn (p);
    int top = Parser_get_current_stack_index (p);

    Parser_stack_reset (p);
    mexpr_parser_destroy (p);

    *rc_out = rc;
    return top;
}

static void
worker (const char *expr, parse_rc_t (*fn)(mexpr_parser_t *),
        parse_rc_t exp_rc, int exp_top, int iters) {

    for (int i = 0; i < iters; i++) {
        parse_rc_t rc;
        int top = run_parse (expr, fn, &rc);
        if (rc != exp_rc || top != exp_top) {
            g_failures.fetch_add (1);
        }
    }
}

int
main (void) {

    const char *e_math = "10 + 20 * 3 - sqrt ( 16 )";
    const char *e_logic = "salary > 100 and age < 50 or dept = 'eng'";

    parse_rc_t rc_math, rc_logic;
    int top_math  = run_parse (e_math,  E, &rc_math);
    int top_logic = run_parse (e_logic, S, &rc_logic);

    printf ("baseline: E rc=%d stack_top=%d | S rc=%d stack_top=%d\n",
            rc_math, top_math, rc_logic, top_logic);

    const int NTHREADS = 8;
    const int ITERS    = 3000;

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        if (i % 2 == 0)
            threads.emplace_back (worker, e_math,  E, rc_math,  top_math,  ITERS);
        else
            threads.emplace_back (worker, e_logic, S, rc_logic, top_logic, ITERS);
    }
    for (auto &t : threads) t.join ();

    int failures = g_failures.load ();
    if (failures == 0) {
        printf ("MT TEST PASSED: %d threads x %d iterations, no mismatches\n",
                NTHREADS, ITERS);
        return 0;
    }

    printf ("MT TEST FAILED: %d mismatches detected\n", failures);
    return 1;
}
