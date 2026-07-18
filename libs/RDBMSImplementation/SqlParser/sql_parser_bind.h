#ifndef __SQL_PARSER_BIND__
#define __SQL_PARSER_BIND__

#include "../uapi/rdbms_ctx.h"
#include "ParserExport.h"

/* Declare in every grammar function before using parse_init()/cyylex() macros. */
#define RDBMS_PARSER_BIND(rdbms) \
    mexpr_parser_t *p = (rdbms)->parser

/* SQL grammar uses no-arg shims; requires RDBMS_PARSER_BIND above. */
#define lex_curr_token        (p->lex_curr_token)
#define lex_curr_token_len    (p->lex_curr_token_len)
#define cyylex()              cyylex(p)
#define yyrewind(n)           yyrewind(p, n)
#define Parser_stack_reset()  Parser_stack_reset(p)
#define lex_set_scan_buffer(buf) lex_set_scan_buffer(p, buf)

parse_rc_t select_query_parser (rdbms_t *rdbms);
parse_rc_t create_query_parser (rdbms_t *rdbms);
parse_rc_t insert_into_query_parser (rdbms_t *rdbms);
parse_rc_t delete_query_parser (rdbms_t *rdbms);
parse_rc_t update_query_parser (rdbms_t *rdbms);

#endif
