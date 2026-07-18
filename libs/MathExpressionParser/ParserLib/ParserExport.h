#ifndef __PARSER_EXPORT__
#define __PARSER_EXPORT__

#include <stdint.h>

#define MAX_MEXPR_LEN  512
#define MAX_STRING_SIZE 512

typedef enum parse_rc_ {

    PARSE_ERR,
    PARSE_SUCCESS

} parse_rc_t;

typedef struct lex_data_ {

    int token_code;
    int token_len;
    uint8_t *token_val;
} lex_data_t;

typedef struct stack_ {

    int top;
    lex_data_t data[MAX_MEXPR_LEN];
} stack_t;

/* Per-instance parser context (thread-safe: one instance per thread/parse). */
typedef struct mexpr_parser_ {

    void      *scanner;     /* yyscan_t        : reentrant flex scanner state */
    void      *buf_state;   /* YY_BUFFER_STATE : current scan buffer         */
    char       lex_buffer[MAX_STRING_SIZE];
    char      *curr_ptr;
    char      *lex_curr_token;
    int        lex_curr_token_len;
    stack_t    undo_stack;
} mexpr_parser_t;

extern "C" int    yylex (void *yyscanner);
extern "C" char  *yyget_text (void *yyscanner);
extern "C" int    yyget_leng (void *yyscanner);

extern mexpr_parser_t *mexpr_parser_create (void);
extern void            mexpr_parser_destroy (mexpr_parser_t *p);

extern void lex_push (mexpr_parser_t *p, lex_data_t lex_data);
extern void yyrewind (mexpr_parser_t *p, int n);
extern void RESTORE_CHKP (mexpr_parser_t *p, int a);
extern unsigned char *parser_alloc_token_value_default (mexpr_parser_t *p, uint16_t token_id);
extern int cyylex (mexpr_parser_t *p);
extern void process_white_space (mexpr_parser_t *p, int n);
extern int cyylexlh (mexpr_parser_t *p);
extern int cyylexlb (mexpr_parser_t *p);
extern void Parser_stack_reset (mexpr_parser_t *p);
extern int  Parser_get_current_stack_index (mexpr_parser_t *p);
extern void lex_set_scan_buffer (mexpr_parser_t *p, const char *buffer);

#define parse_init(p)                   \
    int token_code = 0;                 \
    int _lchkp = (p)->undo_stack.top;   \
    parse_rc_t err = PARSE_SUCCESS

#define RETURN_PARSE_ERROR      \
    {RESTORE_CHKP(p, _lchkp);   \
    return PARSE_ERR;}

#define RETURN_PARSE_SUCCESS    \
    return PARSE_SUCCESS

#define PARSER_CALL(fn) \
    fn(p)

#define CHECKPOINT(p, a)    \
    ((a) = (p)->undo_stack.top)

#define CHECK_FOR_EOL                \
    {token_code = cyylex(p);         \
    if (token_code == PARSER_EOL) {  \
        RETURN_PARSE_SUCCESS;        \
    }}

#define PARSER_LOG_ERR(token_obtained, expected_token)  \
    printf ("%s(%d) : Token Obtained = %d (%s) , expected token = %d\n",    \
        __FUNCTION__, __LINE__, token_obtained, yyget_text((p)->scanner), expected_token);

#define ITERATE_LEX_STACK_BEGIN(p, i , j , token_code_, len_, value_)    \
{   int _k;                                                                                                              \
     for (_k = i; _k <= j && _k <= (p)->undo_stack.top; _k++) {                               \
     lex_data_t *lex_data = &(p)->undo_stack.data[_k];  \
     if (lex_data->token_code == 0 || lex_data->token_code == PARSER_WHITE_SPACE) continue; \
     token_code_ = lex_data->token_code;               \
     len_ = lex_data->token_len;                               \
     value_ = lex_data->token_val;

#define ITERATE_LEX_STACK_END }}

/* Common token codes (reserved: 10000-10002, app codes 5001-5050). */
#define PARSER_EOL  10000
#define PARSER_QUIT 10001
#define PARSER_WHITE_SPACE  10002
#define PARSER_CONTINUE_NEXTLINE    10003
#define PARSER_INVALID_CODE INT32_MAX

#endif
