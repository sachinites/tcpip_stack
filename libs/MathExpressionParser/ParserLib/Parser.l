%top{
#include "ParserExport.h"
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
#include "MexprEnums.h"


%}

%%

"(" {
    return MATH_BRACKET_START;
}

")" {
    return MATH_BRACKET_END;
}

"<=" {
    return MATH_LESS_THAN_EQ;
}

"<" {
    return MATH_LESS_THAN;
}

">" {
    return MATH_GREATER_THAN;
}

"=" {
    return MATH_EQ;
}

"!=" {
    return MATH_NOT_EQ;
}

"and" {
    return MATH_AND;
}

"or" {
    return MATH_OR;
}

"*" {
    return MATH_MUL;
}

"+" {
    return MATH_PLUS;
}

"-" {
    return  MATH_MINUS;
}

"/" {
    return MATH_DIV;
}

"," {
    return MATH_COMMA;
}

"sqrt" {
    return MATH_SQRT;
}

"sqr" {
    return MATH_SQR;
}

"mmax" {
    return MATH_MAX;
}

"mmin" {
    return MATH_MIN;
}

"sin" {
    return MATH_SIN;
}

"cos" {
    return MATH_COS;
}

"pow" {
    return MATH_POW;
}

\n {
    return PARSER_EOL;
}

"\\\n" {

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

0|-?[1-9][0-9]* {
    return MATH_INTEGER_VALUE;
}

-?[0-9]*\.[0-9]+ {
    return MATH_DOUBLE_VALUE;
}

[a-zA-Z0-9_]+ {
    return MATH_IDENTIFIER;
}

[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+ {
    return MATH_IDENTIFIER_IDENTIFIER;
}

'[^']*' {
    // string enclosed within single quotes
    return MATH_STRING_VALUE;
}

\"[^"]*\" {
    // string enclosed within double quotes
    return MATH_STRING_VALUE;
}


. {
    // ignore any other character
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
