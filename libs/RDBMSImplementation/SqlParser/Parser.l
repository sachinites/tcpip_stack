%top{
#define PARSER_LEX_IMPL 1
#include "ParserExport.h"
#undef PARSER_LEX_IMPL
}
%option reentrant
%option noyywrap
%option extra-type="mexpr_parser_t *"

%{

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>

void
lex_push (mexpr_parser_t *p, lex_data_t lex_data) {

    assert (p->undo_stack.top < MAX_MEXPR_LEN - 1);
    p->undo_stack.data[++p->undo_stack.top] = lex_data;
    p->lex_curr_token = (char *)lex_data.token_val;
    p->lex_curr_token_len = lex_data.token_len;
}

static lex_data_t
lex_pop (mexpr_parser_t *p) {

    assert (p->undo_stack.top > -1);
    lex_data_t res = p->undo_stack.data[p->undo_stack.top];
    p->undo_stack.top--;
    if (p->undo_stack.top > -1) {
        lex_data_t stck_top_lexd = p->undo_stack.data[p->undo_stack.top];
        p->lex_curr_token = (char *)stck_top_lexd.token_val;
        p->lex_curr_token_len = stck_top_lexd.token_len;
    }
    else {
        p->lex_curr_token = NULL;
        p->lex_curr_token_len = 0;
    }
    return res;
}

void
yyrewind (mexpr_parser_t *p, int n) {

    if (n <= 0) return;
    if (p->curr_ptr == p->lex_buffer) return;
    int data_len = 0;
    lex_data_t lex_data;
    while (n)  {
        lex_data = lex_pop(p);
        data_len += lex_data.token_len;
        if (lex_data.token_code == PARSER_WHITE_SPACE) {
            continue;
        }
        n--;
        lex_data.token_code = 0;
        lex_data.token_len = 0;
        if (lex_data.token_val) {
            free (lex_data.token_val);
            lex_data.token_val = NULL;
        }
    }
    p->curr_ptr -= data_len;
    if (p->buf_state) {
        yy_delete_buffer ((YY_BUFFER_STATE)p->buf_state, p->scanner);
    }
    p->buf_state = (void *) yy_scan_string(p->curr_ptr, p->scanner);
}

void
RESTORE_CHKP (mexpr_parser_t *p, int a) {

    lex_data_t lex_data;
    int data_len = 0;

    while (p->undo_stack.top > a) {

        lex_data = lex_pop(p);
        data_len += lex_data.token_len;

        if (lex_data.token_val) {
            free (lex_data.token_val);
            lex_data.token_val = NULL;
        }
    }
    p->curr_ptr -= data_len;
    if (p->buf_state) {
        yy_delete_buffer ((YY_BUFFER_STATE)p->buf_state, p->scanner);
    }
    p->buf_state = (void *) yy_scan_string(p->curr_ptr, p->scanner);
}

unsigned char *
parser_alloc_token_value_default (mexpr_parser_t *p, uint16_t token_id) {

    int leng = yyget_leng (p->scanner);
    char *text = yyget_text (p->scanner);
    unsigned char *ptr = (unsigned char *)(calloc (1, leng + 1));
    strncpy ((char *)ptr, text, leng);
    ptr [leng] = '\0';
    return ptr;
}

int
cyylex (mexpr_parser_t *p) {

    int token_code = yylex(p->scanner);
    p->curr_ptr += yyget_leng (p->scanner);
    lex_data_t lex_data;
    lex_data.token_code = token_code;
    lex_data.token_len = yyget_leng (p->scanner);
    lex_data.token_val = parser_alloc_token_value_default (p, token_code);
    lex_push(p, lex_data);
    return token_code;
}

void
process_white_space (mexpr_parser_t *p, int n) {

    lex_data_t lex_data;
    p->curr_ptr += n;
    lex_data.token_code = PARSER_WHITE_SPACE;
    lex_data.token_len = n;
    lex_data.token_val = NULL;
    lex_push(p, lex_data);
}

int cyylexlh (mexpr_parser_t *p) {

    int token_code = cyylex(p);
    yyrewind(p, 1);
    return token_code;
}

int cyylexlb (mexpr_parser_t *p) {

    yyrewind(p, 1);
    int token_code = cyylex(p);
    yyrewind(p, 1);
    return token_code;
}

void
Parser_stack_reset (mexpr_parser_t *p) {

    int i;
    lex_data_t *lex_data;

    for (i = 0; i <= p->undo_stack.top; i++) {
        lex_data = &p->undo_stack.data[i];
        lex_data->token_code = 0;
        lex_data->token_len = 0;
        if (lex_data->token_val) {
            free (lex_data->token_val);
            lex_data->token_val = NULL;
        }
    }
    p->undo_stack.top = -1;
    p->curr_ptr = p->lex_buffer;
    p->lex_curr_token = NULL;
    p->lex_curr_token_len = 0;
}

int
Parser_get_current_stack_index (mexpr_parser_t *p) {
    return p->undo_stack.top;
}

void
lex_set_scan_buffer (mexpr_parser_t *p, const char *buffer) {

    if (p->buf_state) {
        yy_delete_buffer ((YY_BUFFER_STATE)p->buf_state, p->scanner);
    }
    p->buf_state = (void *) yy_scan_string (buffer, p->scanner);
    p->curr_ptr = p->lex_buffer;
}

/* ========================================
            Warning : Do  Not Modify this file above this line 
    ======================================= */
            /* User specific parsing logic starts below */


/* User specific parsing logic starts below */

/* User specific header files */
#include "SqlEnums.h"

%}

%%

"select" {
    return SQL_SELECT_Q;
}

"create" {
    return SQL_CREATE_Q;
}

"insert into" {
    return SQL_INSERT_Q;
}

"drop" {
    return SQL_DROP_TABLE_Q;
}

"set" {
    return SQL_SET;
}

"delete" {
    return SQL_DELETE_Q;
}

"update" {
    return SQL_UPDATE_Q;
}

"varchar" {
    return SQL_STRING;
}

"int" {
    return SQL_INT;
}

decimal|double {
    return SQL_DOUBLE;
}

"ipv4" {
    return SQL_IPV4_ADDR;
}

"interval" {
    return SQL_INTERVAL;
}

"primary key" {
    return SQL_PRIMARY_KEY;
}

"not null" {
    return SQL_NOT_NULL;
}

"max" {
    return SQL_MAX;
}

"sum" {
    return SQL_SUM;
}

"min" {
    return SQL_MIN;
}

"count" {
    return SQL_COUNT;
}

"avg" {
    return SQL_AVG;
}

"from" {
    return SQL_FROM;
}

"where" {
    return SQL_WHERE;
}

"group by" {
    return SQL_GROUP_BY;
}

"order by" {
    return SQL_ORDER_BY;
}

"limit" {
    return SQL_LIMIT;
}


"having" {
    return SQL_HAVING;
}

"asc" {
    return SQL_ORDERBY_ASC;
}

"desc" {
    return SQL_ORDERBY_DSC;
}


"(" {
    return SQL_BRACKET_START;
}

")" {
    return SQL_BRACKET_END;
}

"'" {
    return SQL_QUOTATION_MARK;
}

"<" {
    return SQL_LESS_THAN;
}

">" {
    return SQL_GREATER_THAN;
}

"=" {
    return SQL_EQ;
}

"!=" {
    return SQL_NOT_EQ;
}

"and" {
    return SQL_AND;
}

"or" {
    return SQL_OR;
}

"as" {
    return SQL_AS;
}

"*" {
    return SQL_MATH_MUL;
}

"+" {
    return SQL_MATH_PLUS;
}

"-" {
    return SQL_MATH_MINUS;
}

"/" {
    return SQL_MATH_DIV;
}

"in" {
    return SQL_IN;
}

"LIKE" {
    
    return SQL_LIKE;
}

"sqrt" {
    return SQL_MATH_SQRT;
}

"sqr" {
    return SQL_MATH_SQR;
}

"hmax" {
    return SQL_MATH_MAX;
}

"hmin" {
    return SQL_MATH_MIN;
}

"sin" {
    return SQL_MATH_SIN;
}

"pow" {
    return SQL_MATH_POW;
}

\n {
    return PARSER_EOL;
}

\\\n {
    return PARSER_CONTINUE_NEXTLINE;
}

"\\dt\n" {
    return SQL_SHOW_DB_TABLES;
}

"," {
    return SQL_COMMA;
}

\[[ \t]*[+-]?[0-9]+[ \t]*,[ \t]*[+-]?[0-9]+[ \t]*\] {
    // [<integer>, <integer>]
    return SQL_INTERVAL_VALUE;
}

[ ] { 
    /* Ignore */
    process_white_space(yyextra, 1);
}

[\t] {
    /*ignore*/
    process_white_space(yyextra, 4);
}

"\\q" {
    return PARSER_QUIT;
}

(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]) {

    return SQL_IPV4_ADDR_VALUE;
}

0|-?[1-9][0-9]* {
    return SQL_INTEGER_VALUE;
}

-?[0-9]*\.[0-9]+ {
    return SQL_DOUBLE_VALUE;
}

[a-zA-Z0-9_]+ {
    return SQL_IDENTIFIER;
}

[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+ {
    return SQL_IDENTIFIER_IDENTIFIER;
}

'[^']*' {
    // string enclosed within single quotes
    return SQL_STRING_VALUE;
}

\"[^"]*\" {
    // string enclosed within double quotes
    return SQL_STRING_VALUE;
}

. {
    
}

%%

mexpr_parser_t *
mexpr_parser_create (void) {

    mexpr_parser_t *p = (mexpr_parser_t *) calloc (1, sizeof (mexpr_parser_t));
    if (!p) return NULL;

    if (yylex_init_extra (p, (yyscan_t *)&p->scanner) != 0) {
        free (p);
        return NULL;
    }

    p->buf_state = NULL;
    p->curr_ptr = p->lex_buffer;
    p->lex_curr_token = NULL;
    p->lex_curr_token_len = 0;
    p->undo_stack.top = -1;
    return p;
}

void
mexpr_parser_destroy (mexpr_parser_t *p) {

    if (!p) return;

    Parser_stack_reset (p);

    if (p->buf_state) {
        yy_delete_buffer ((YY_BUFFER_STATE)p->buf_state, p->scanner);
        p->buf_state = NULL;
    }

    yylex_destroy (p->scanner);
    free (p);
}
