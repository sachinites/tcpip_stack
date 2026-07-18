#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "ParserExport.h"
#include "sql_parser_bind.h"
#include "SqlEnums.h"
#include "../core/SqlMexprIntf.h"
#include "../core/sql_create.h"
#include "../core/sql_const.h"

extern int cprintf (const char* format, ...);
#define printf cprintf

/* Grammar for Create Query 

    create_query_parser -> create table IDENTFIER (COLSLIST) [ using IDENTIFIER ]

    IDENTFIER -> <string>

    COLSLIST -> COL | COL , COLSLIST 

    COL -> IDENTFIER DTYPE |  IDENTFIER DTYPE primary key 

    DTYPE -> varchar (<number>) | int | double | ipv4

    Optional per-table storage engine:
      create table t (...) using list
      create table t (...) using bplustree
      create table t (...)            -- registry default (bplustree)
*/

parse_rc_t
DTYPE (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    do {

        token_code = cyylex();

        if (token_code != SQL_STRING) {

            yyrewind(1);
            break;
        }
        rdbms->cdata.column_data[rdbms->cdata.n_cols].dtype = SQL_STRING;

        token_code = cyylex();

        if (token_code != SQL_BRACKET_START) {
             PARSER_LOG_ERR (token_code, SQL_BRACKET_START);
             yyrewind(2);
             break;
        }

        token_code = cyylex ();

        if (token_code != SQL_INTEGER_VALUE) {

            PARSER_LOG_ERR (token_code, SQL_INTEGER_VALUE);
            yyrewind(3);
            break;
        }
        rdbms->cdata.column_data[rdbms->cdata.n_cols].dtype_len = atoi (lex_curr_token);

        token_code = cyylex();

        if (token_code != SQL_BRACKET_END) {
             PARSER_LOG_ERR (token_code, SQL_BRACKET_END);
             yyrewind(4);
             break;
        }
        
        RETURN_PARSE_SUCCESS;

    } while (0);


    token_code = cyylex();

    switch (token_code) {

        case SQL_INT:
        case SQL_DOUBLE:
        case SQL_IPV4_ADDR:
        case SQL_INTERVAL:
            rdbms->cdata.column_data[rdbms->cdata.n_cols].dtype = (sql_dtype_t )token_code;
            rdbms->cdata.column_data[rdbms->cdata.n_cols].dtype_len = sql_dtype_size ((sql_dtype_t )token_code);
            RETURN_PARSE_SUCCESS;
        default:
            PARSER_LOG_ERR (token_code, SQL_INT);
            PARSER_LOG_ERR (token_code, SQL_DOUBLE);
            PARSER_LOG_ERR (token_code, SQL_IPV4_ADDR);
             PARSER_LOG_ERR (token_code, SQL_INTERVAL);
            RETURN_PARSE_ERROR;
    }
    
}

parse_rc_t
COL (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {
        PARSER_LOG_ERR (token_code, SQL_IDENTIFIER);
        RETURN_PARSE_ERROR;
    }

    strncpy (rdbms->cdata.column_data[rdbms->cdata.n_cols].col_name,
                    lex_curr_token, SQL_COLUMN_NAME_MAX_SIZE);

    err = DTYPE(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    token_code = cyylex();

    if (token_code != SQL_PRIMARY_KEY) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    rdbms->cdata.column_data[rdbms->cdata.n_cols].is_primary_key = true;

    RETURN_PARSE_SUCCESS;
}

parse_rc_t
COLSLIST (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    err = COL(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    rdbms->cdata.n_cols++;

    token_code = cyylex();

    if (token_code != SQL_COMMA) {
        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = COLSLIST (rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

parse_rc_t
create_query_parser (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    memset (&rdbms->cdata, 0, sizeof (rdbms->cdata));

    token_code = cyylex();
    assert (token_code == SQL_CREATE_Q);

    token_code = cyylex();

    if (strcmp (lex_curr_token, "table")) {
        printf ("Error : Expected keyword \'table\' is missing, typo error  = %s\n", lex_curr_token);
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {

        PARSER_LOG_ERR(token_code, SQL_IDENTIFIER);
        RETURN_PARSE_ERROR;
    }

    strncpy(rdbms->cdata.table_name, lex_curr_token, SQL_TABLE_NAME_MAX_SIZE);

    token_code = cyylex();

    if (token_code != SQL_BRACKET_START) {

        PARSER_LOG_ERR (token_code, SQL_BRACKET_START);
        RETURN_PARSE_ERROR;
    }

    err = COLSLIST (rdbms);

    if (err == PARSE_ERR) {
        printf ("Failed\n");
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != SQL_BRACKET_END) {

        PARSER_LOG_ERR (token_code, SQL_BRACKET_END);
        printf ("Failed\n");
        RETURN_PARSE_ERROR;        
    }

    token_code = cyylex ();

    /* Optional: using <engine_name> */
    if (token_code == SQL_IDENTIFIER &&
        strcmp (lex_curr_token, "using") == 0) {

        token_code = cyylex ();

        if (token_code != SQL_IDENTIFIER) {
            PARSER_LOG_ERR (token_code, SQL_IDENTIFIER);
            printf ("Error : Expected storage engine name after USING\n");
            RETURN_PARSE_ERROR;
        }

        strncpy (rdbms->cdata.engine_name,
                 lex_curr_token,
                 SQL_STORAGE_ENGINE_NAME_MAX);

        token_code = cyylex ();
    }

    if (token_code !=  PARSER_EOL) {
        PARSER_LOG_ERR (token_code, PARSER_EOL);
        printf ("Failed\n");
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}
