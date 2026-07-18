#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <string>
#include "ParserExport.h"
#include "SqlEnums.h"
#include "../core/sql_const.h"
#include "../core/SqlMexprIntf.h"
#include "../core/qep.h"
#include "sql_parser_bind.h"

extern int cprintf (const char* format, ...);
#define printf cprintf

 /* CFG : 
    update_query_parser -> update TAB set COL_ASSIGN_LIST WHERE LEXPR
    TAB -> <ident>
    COL_ASSIGN_LIST -> COL_ASSIGN | COL_ASSIGN , COL_ASSIGN_LIST
    COL_ASSIGN -> <ident> = LEXPR
 */

static parse_rc_t WHERE (rdbms_t *rdbms) ;
static parse_rc_t TAB (rdbms_t *rdbms) ;
static parse_rc_t COL_ASSIGN_LIST (rdbms_t *rdbms) ;
static parse_rc_t COL_ASSIGN (rdbms_t *rdbms) ;


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

// TABS -> <ident>
parse_rc_t
TAB (rdbms_t *rdbms) {
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

    rdbms->qep.join.table_cnt++;

    RETURN_PARSE_SUCCESS;
}

// COL_ASSIGN -> <ident> = LEXPR
parse_rc_t
COL_ASSIGN (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {
        PARSER_LOG_ERR (token_code, SQL_IDENTIFIER); 
        RETURN_PARSE_ERROR;
    }

    /* Store a Column name */
    strncpy (rdbms->qep.update.upd_colmns[rdbms->qep.update.n].col_name, 
                    lex_curr_token, lex_curr_token_len);

    token_code = cyylex();

    if (token_code != SQL_EQ) {
        PARSER_LOG_ERR (token_code, SQL_EQ); 
        RETURN_PARSE_ERROR;
    }

    rdbms->qep.update.upd_colmns[rdbms->qep.update.n].value_exptree = sql_create_exp_tree_compute(p);

    RETURN_PARSE_SUCCESS;
}

// COL_ASSIGN_LIST -> COL_ASSIGN | COL_ASSIGN , COL_ASSIGN_LIST
parse_rc_t
COL_ASSIGN_LIST (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    int initial_chkp;
    CHECKPOINT(p, initial_chkp);

    // COL_ASSIGN_LIST -> COL_ASSIGN , COL_ASSIGN_LIST
    do {

        err = COL_ASSIGN(rdbms);

        if (err == PARSE_ERR) break;

        token_code = cyylex();

        if (token_code != SQL_COMMA) break;

        rdbms->qep.update.n++;

        err = COL_ASSIGN_LIST(rdbms);

        if (err == PARSE_ERR) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    // COL_ASSIGN_LIST -> COL_ASSIGN

    err = COL_ASSIGN(rdbms);

    if (err == PARSE_ERR) {

        if (!rdbms->qep.update.upd_colmns[rdbms->qep.update.n].value_exptree) {
            
            printf ("Error : Could not build Update Column Value Expression Tree for Column %s\n", 
                        rdbms->qep.update.upd_colmns[rdbms->qep.update.n].col_name);
            RETURN_PARSE_ERROR;
        }

    }

    rdbms->qep.update.n++;
    
    RETURN_PARSE_SUCCESS;
}

// update_query_parser -> update TAB set COL_ASSIGN_LIST WHERE LEXPR
parse_rc_t
update_query_parser (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    memset0_qep (&rdbms->qep);

    token_code = cyylex();

    if (token_code != SQL_UPDATE_Q) {
        PARSER_LOG_ERR (token_code, SQL_UPDATE_Q); 
        RETURN_PARSE_ERROR;
    }

    rdbms->qep.query_type = SQL_UPDATE_Q;

    err = TAB(rdbms);

    if (err == PARSE_ERR) {
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != SQL_SET) {
        PARSER_LOG_ERR (token_code, SQL_SET); 
        RETURN_PARSE_ERROR;
    }

    err = COL_ASSIGN_LIST(rdbms);

    if (err == PARSE_ERR) {
        RETURN_PARSE_ERROR;
    }

    err = WHERE(rdbms);

    if (err == PARSE_ERR) {
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != PARSER_EOL) {
        PARSER_LOG_ERR (token_code, PARSER_EOL); 
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}
