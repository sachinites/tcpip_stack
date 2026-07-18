#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "ParserExport.h"
#include "SqlEnums.h"
#include "../core/qep.h"
#include "sql_parser_bind.h"
#include "../core/SqlMexprIntf.h"
#include "../core/sql_delete.h"
#include "../core/sql_const.h"

extern int cprintf (const char* format, ...);
#define printf cprintf

 /* CFG : 
    delete_query_parser -> delete from TABS WHERE
    TABS -> <ident> L
    L -> $ | as <identifier>
    WHERE -> $ | where LEXPR 
 */

static parse_rc_t WHERE (rdbms_t *rdbms) ;
static parse_rc_t L (rdbms_t *rdbms) ;
static parse_rc_t TABS (rdbms_t *rdbms) ;

/* WHERE -> $ | where LEXPR */
parse_rc_t
WHERE (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_WHERE) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    rdbms->qep.where.gexptree = sql_create_exp_tree_conditional(p);

    if (!rdbms->qep.where.gexptree) {
        printf ("Error : Could not build Where Logical Expression Tree\n");
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}

// L -> $ | as <identifier>
parse_rc_t
L (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

     rdbms->parse_alias_name[0] = '\0';

    token_code = cyylex();

    if (token_code != SQL_AS) {
        yyrewind(1);
       RETURN_PARSE_SUCCESS;
    }

    token_code = cyylex ();

    if (token_code != SQL_IDENTIFIER) {
        yyrewind(2);
        RETURN_PARSE_SUCCESS;
    }

    strncpy (rdbms->parse_alias_name,  lex_curr_token, lex_curr_token_len);
    RETURN_PARSE_SUCCESS;
}

// TABS -> <ident> L
parse_rc_t
TABS (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {
        PARSER_LOG_ERR (token_code, SQL_IDENTIFIER); 
        RETURN_PARSE_ERROR;
    }

    /* Store a Table name */
    if (!qep_struct_record_table (&rdbms->qep, lex_curr_token)) {

        printf ("Error : Table %s Do not Exist\n", lex_curr_token);
        RETURN_PARSE_ERROR;
    }

    rdbms->parse_alias_name = rdbms->qep.join.tables[rdbms->qep.join.table_cnt].alias_name;

    err = L(rdbms);

    if (err == PARSE_ERR ) {

        printf ("Error : Could not parse Alias name\n");
        RETURN_PARSE_ERROR;
    }

    rdbms->qep.join.table_cnt++;

    RETURN_PARSE_SUCCESS;
}


parse_rc_t 
delete_query_parser (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    memset0_qep (&rdbms->qep);
    rdbms->qep.query_type = SQL_DELETE_Q;

    token_code = cyylex();

    assert (token_code == SQL_DELETE_Q);

    token_code = cyylex();

    if (token_code != SQL_FROM) {
        PARSER_LOG_ERR (token_code, SQL_FROM);
        RETURN_PARSE_ERROR;
    }

    err = TABS(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on Tables\n");
        RETURN_PARSE_ERROR;        
    }

    err = WHERE(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on Where Clause\n");
        RETURN_PARSE_ERROR;        
    }

    token_code = cyylex ();

    if (token_code !=  PARSER_EOL) {
        PARSER_LOG_ERR (token_code, PARSER_EOL);
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}
