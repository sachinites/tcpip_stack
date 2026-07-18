#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <assert.h>
#include "ParserExport.h"
#include "sql_parser_bind.h"
#include "SqlEnums.h"
#include "../core/sql_insert_into.h"
#include "../core/sql_utils.h"
#include "../core/sql_const.h"

extern int cprintf (const char* format, ...);
#define printf cprintf

/* CFG 

insert_query_parser -> Q1 | Q2 

INSERT INTO table_name
VALUES (value1, value2, value3, ...);

Q1 -> insert into IDENTFIER values (VALUES)
IDENTFIER -> <string>
VALUES -> VALUE | VALUE , VALUES
VALUE ->  <integer> | <double> | '<string>' | ipv4-addr

INSERT INTO table_name (column1, column2, column3, ...)
VALUES (value1, value2, value3, ...);

Q2 -> insert into IDENTFIER (COLS) values (VALUES)
VALUES -> Same as above
COLS -> COL | COL, COLS
COL -> IDENTFIER
IDENTFIER -> <string>

We are supporitng only Q1 method of specifying values

*/

/* VALUE ->  <integer> | <double> | '<string>' | ipv4-addr | interval */
parse_rc_t
VALUE (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    token_code = cyylex();

    switch (token_code ) {

        case SQL_INTEGER_VALUE:
            rdbms->idata.sql_values[rdbms->idata.n].dtype = SQL_INT;
            rdbms->idata.sql_values[rdbms->idata.n].u.int_val = atoi (lex_curr_token);
            break;
        case SQL_DOUBLE_VALUE:
            rdbms->idata.sql_values[rdbms->idata.n].dtype = SQL_DOUBLE;
            rdbms->idata.sql_values[rdbms->idata.n].u.d_val = (double)atof (lex_curr_token);
            break;
        case SQL_IPV4_ADDR_VALUE:
            rdbms->idata.sql_values[rdbms->idata.n].dtype = SQL_IPV4_ADDR;
            strncpy (rdbms->idata.sql_values[rdbms->idata.n].u.ipv4_addr_str, lex_curr_token, 16);
            break;
        case SQL_STRING_VALUE:
            rdbms->idata.sql_values[rdbms->idata.n].dtype = SQL_STRING;
            if ( (sizeof (rdbms->idata.sql_values[rdbms->idata.n].u.str_val) <= lex_curr_token_len -2)) {
                printf ("Error : %s(%d) Buffer overflow\n", __FUNCTION__, __LINE__);
                RETURN_PARSE_ERROR;
            }
            strncpy (rdbms->idata.sql_values[rdbms->idata.n].u.str_val, lex_curr_token + 1,  // skip ' or "
                        lex_curr_token_len - 2); 
            break;
        case SQL_INTERVAL_VALUE:
            {
                sql_read_interval_values (lex_curr_token, 
                    &rdbms->idata.sql_values[rdbms->idata.n].u.ival.lb,
                    &rdbms->idata.sql_values[rdbms->idata.n].u.ival.ub);
                rdbms->idata.sql_values[rdbms->idata.n].dtype = SQL_INTERVAL;
            }
            break;
        default:
            RETURN_PARSE_ERROR;
    }
    RETURN_PARSE_SUCCESS;
}


/* VALUES -> VALUE | VALUE , VALUES */
parse_rc_t
VALUES (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    err = VALUE (rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    rdbms->idata.n++;

    token_code = cyylex();

    if (token_code != SQL_COMMA) {

        yyrewind(1);
        RETURN_PARSE_SUCCESS;
    }

    err = VALUES(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}


parse_rc_t
insert_into_query_parser (rdbms_t *rdbms) {
    RDBMS_PARSER_BIND (rdbms);

    parse_init(p);

    memset (&rdbms->idata, 0, sizeof (rdbms->idata));

    token_code = cyylex ();

    assert (token_code == SQL_INSERT_Q);

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {
        PARSER_LOG_ERR (token_code, SQL_IDENTIFIER);
        RETURN_PARSE_ERROR;
    }

    strncpy (rdbms->idata.table_name, lex_curr_token, sizeof (rdbms->idata.table_name));

    token_code = cyylex();

    if (token_code != SQL_IDENTIFIER) {
        PARSER_LOG_ERR (token_code, SQL_IDENTIFIER);
        RETURN_PARSE_ERROR;
    }

    if (strcmp (lex_curr_token, "values") || 
            lex_curr_token_len != 6) {

        printf ("Error : Expected keyword \'values\' is missing, typo error  = %s\n", lex_curr_token);
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex();

    if (token_code != SQL_BRACKET_START) {

        PARSER_LOG_ERR (token_code, SQL_BRACKET_START);
        RETURN_PARSE_ERROR;
    }

    err = VALUES(rdbms);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    token_code = cyylex();

    if (token_code != SQL_BRACKET_END) {

        PARSER_LOG_ERR (token_code, SQL_BRACKET_END);
        RETURN_PARSE_ERROR;
    }

    token_code = cyylex ();

    if (token_code !=  PARSER_EOL) {
        PARSER_LOG_ERR (token_code, PARSER_EOL);
        printf ("Failed\n");
        RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;    
}
