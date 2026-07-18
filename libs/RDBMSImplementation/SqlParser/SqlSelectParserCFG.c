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

/* CFG 

select_query_parser -> select COLLIST  from TABS WHERE GRPBY ORDERBY LMT

COLLIST -> COL | COL , COLLIST

COL -> AGG_FN(MEXPR) | AGG_FN(MEXPR) as L

L -> $ | as <identifer>

TABS -> <ident> L | <ident> L , TABS

WHERE -> $ | where LEXPR

GRPBY ->  $  |  group by INDTF_LST HAVING

HAVING  ->  $  |  having LEXPR

INDTF_LST -> IDENT | IDENT , INDTF_LST

IDENT -> identifer | identider.identifer  [identifer can be col name or name of colmn alias] 
                                                                [identider.identifer is table_name.colmn name only ]

ORDERBY  -> $  |  order by IDENT C

C ->  asc |  dsc | $

LMT  -> $  |  limit <integer>

*/


static parse_rc_t LMT (rdbms_t *rdbms);
static parse_rc_t ORDER_BY (rdbms_t *rdbms);
static parse_rc_t HAVING (rdbms_t *rdbms);
static parse_rc_t INDTF_LST (rdbms_t *rdbms);
static parse_rc_t GROUP_BY (rdbms_t *rdbms);
static parse_rc_t WHERE (rdbms_t *rdbms) ;
static parse_rc_t TABS (rdbms_t *rdbms) ;
static parse_rc_t L (rdbms_t *rdbms) ;
static parse_rc_t COL (rdbms_t *rdbms);
static parse_rc_t COLLIST (rdbms_t *rdbms);



// LMT  -> $  |  limit <integer>
parse_rc_t
LMT (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_LIMIT) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    token_code = cyylex();

    if (token_code != SQL_INTEGER_VALUE) {

        yyrewind(2);
        RETURN_PARSE_SUCCESS;
    }

    rdbms->qep.limit = atoi(lex_curr_token);

    RETURN_PARSE_SUCCESS;
}


// ORDERBY  -> $  |  order by IDENT C
parse_rc_t
ORDER_BY (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_ORDER_BY) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER &&
         token_code != SQL_IDENTIFIER_IDENTIFIER) {

        yyrewind(2);
        RETURN_PARSE_SUCCESS;
    }

    strncpy (rdbms->qep.orderby.column_name, lex_curr_token, sizeof (rdbms->qep.orderby.column_name));

    token_code = cyylex();

    if (token_code != SQL_ORDERBY_ASC &&
         token_code != SQL_ORDERBY_DSC) {

        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    rdbms->qep.orderby.asc = (token_code == SQL_ORDERBY_ASC);
    RETURN_PARSE_SUCCESS;
}

/* HAVING  ->  $  |  having LEXPR */
parse_rc_t
HAVING (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_HAVING) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    rdbms->qep.having.gexptree_phase1 = sql_create_exp_tree_conditional (p);

    if (!rdbms->qep.having.gexptree_phase1) {

        printf ("Error : Could not build Having clause expression tree\n");
        RETURN_PARSE_SUCCESS;
    }

    RETURN_PARSE_SUCCESS;
}


/* INDTF_LST -> IDENT | IDENT , INDTF_LST */
parse_rc_t
INDTF_LST (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);
    qp_col_t *qp_col;

    sql_exptree_t *exp_tree = sql_create_exp_tree_compute (p);

    if (!exp_tree) RETURN_PARSE_ERROR;

    qp_col = (qp_col_t *)calloc (1, sizeof (qp_col_t));
    qp_col->agg_fn = SQL_AGG_FN_NONE;
    qp_col->aggregator = NULL;
    qp_col->alias_provided_by_user = false;
    qp_col->computed_value = NULL;
    qp_col->sql_tree = exp_tree;
    rdbms->qep.groupby.col_list[rdbms->qep.groupby.n++] = qp_col;

    token_code = cyylex();

    if (token_code != SQL_COMMA) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = INDTF_LST(rdbms) ;

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}


/* GRPBY ->  $  |  group by INDTF_LST HAVING */
parse_rc_t
GROUP_BY (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_GROUP_BY) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = INDTF_LST(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

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


/* TABS -> <ident> L | <ident> L , TABS */
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
    assert (err == PARSE_SUCCESS);

    rdbms->qep.join.table_cnt++;

    token_code = cyylex();

    if (token_code != SQL_COMMA) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = TABS(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

/* L -> $ | as <identifer> */
parse_rc_t
L (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_AS) {
        yyrewind(1);
        rdbms->parse_alias_name[0] = '\0';
       RETURN_PARSE_SUCCESS;
    }

    token_code = cyylex ();

    if (token_code != SQL_IDENTIFIER) {
        yyrewind(2);
        rdbms->parse_alias_name[0] = '\0';
        RETURN_PARSE_SUCCESS;
    }

    strncpy (rdbms->parse_alias_name,  lex_curr_token, lex_curr_token_len);
    RETURN_PARSE_SUCCESS;
}

/* COL -> MEXPR | MEXPR as L | AGG_FN(MEXPR) | AGG_FN(MEXPR) as L */
parse_rc_t
COL (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    qp_col_t *qp_col = (qp_col_t *)calloc (1, sizeof (qp_col_t));
    qp_col->agg_fn = SQL_AGG_FN_NONE;
    qp_col->alias_provided_by_user = false;
    rdbms->qep.select.sel_colmns[rdbms->qep.select.n++] = qp_col;

    do {

        /* COL -> MEXPR */
        qp_col->sql_tree = sql_create_exp_tree_compute (p);

        if (!qp_col->sql_tree) break;
        
        /* COL ->MEXPR as L */
        rdbms->parse_alias_name = qp_col->alias_name;
        err = L(rdbms);
        assert (err == PARSE_SUCCESS);
        
        if (qp_col->alias_name[0] != '\0') {
            qp_col->alias_provided_by_user = true;
        }

        RETURN_PARSE_SUCCESS;

    } while (0);


    do {

        /* COL -> AGG_FN(MEXPR) */
        token_code = cyylex ();
        if (token_code != SQL_SUM &&
            token_code != SQL_MIN &&
            token_code != SQL_MAX &&
            token_code != SQL_COUNT &&
            token_code != SQL_AVG) {

            PARSER_LOG_ERR(token_code, SQL_SUM);
            PARSER_LOG_ERR(token_code, SQL_MIN);
            PARSER_LOG_ERR(token_code, SQL_MAX);
            PARSER_LOG_ERR(token_code, SQL_COUNT);
            PARSER_LOG_ERR(token_code, SQL_AVG);
            RETURN_PARSE_ERROR;
        }

        qp_col->agg_fn = (sql_agg_fn_t)token_code;

        token_code = cyylex();

        if (token_code != SQL_BRACKET_START) RETURN_PARSE_ERROR;

        qp_col->sql_tree = sql_create_exp_tree_compute (p);

        if (!qp_col->sql_tree) RETURN_PARSE_ERROR;

        token_code = cyylex();

         if (token_code != SQL_BRACKET_END) RETURN_PARSE_ERROR;

         /* COL -> AGG_FN(MEXPR) as L */
         rdbms->parse_alias_name = qp_col->alias_name;
         err = L(rdbms);
         assert (err == PARSE_SUCCESS);      

        if (qp_col->alias_name[0] != '\0') {
            qp_col->alias_provided_by_user = true;
        }
        
    }   while (0); 

    RETURN_PARSE_SUCCESS;
}


/* COLLIST -> * | COL | COL , COLLIST */
parse_rc_t
COLLIST (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code == SQL_MATH_MUL) {
        rdbms->qep.select.n = 0;
        RETURN_PARSE_SUCCESS;
    }

    yyrewind(1);

    err = COL(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    token_code = cyylex();

    if (token_code != SQL_COMMA) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = COLLIST(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;
    RETURN_PARSE_SUCCESS;
}

/* select_query_parser -> select COLS from TABS WHERE GRPBY ORDERBY LMT */
parse_rc_t
select_query_parser (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    memset0_qep (&rdbms->qep);
    rdbms->qep.query_type = SQL_SELECT_Q;
    
    /* consume 'select' keyword */
    token_code = cyylex ();
    assert (token_code == SQL_SELECT_Q);

    /* Now parse list of Columns*/
    err = COLLIST(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Column list parsing failed\n");
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != SQL_FROM) {

        PARSER_LOG_ERR(token_code, SQL_FROM);
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

    err = GROUP_BY(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on GROUP BY Clause\n");
        RETURN_PARSE_ERROR;        
    }    

    err = HAVING(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on HAVING Clause\n");
        RETURN_PARSE_ERROR;        
    }    

    err = ORDER_BY(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on ORDER BY Clause\n");
        RETURN_PARSE_ERROR;        
    }    

    err = LMT(rdbms);

    if (err == PARSE_ERR) {

        printf ("Error : Parsing Error on LIMIT Clause\n");
        RETURN_PARSE_ERROR;        
    }    

    token_code = cyylex ();

    if (token_code !=  PARSER_EOL) {
        PARSER_LOG_ERR (token_code, PARSER_EOL);
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}
