#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "sql_api.h"
#include "../core/qep.h"
#include "../../MathExpressionParser/Dtype.h"
#include "../SqlParser/ParserExport.h"
#include "../SqlParser/sql_parser_bind.h"
#include "../core/sql_create.h"
#include "../core/sql_insert_into.h"
#include "../core/sql_delete.h"
#include "../core/Catalog.h"
#include "../core/rdbms_ds.h"

rdbms_t *
rdbms_create (void) {

    /* Register the built-in storage engines (idempotent). The record/schema
       stores default to the B+tree engine. */
    rdbms_ds_register_builtins ();

    rdbms_t *rdbms = (rdbms_t *) calloc (1, sizeof (rdbms_t));
    if (!rdbms) return NULL;

    rdbms->catalog = catalog_create ();
    if (!rdbms->catalog) {
        free (rdbms);
        return NULL;
    }

    rdbms->parser = mexpr_parser_create ();
    if (!rdbms->parser) {
        catalog_destroy (rdbms->catalog);
        free (rdbms);
        return NULL;
    }

    return rdbms;
}

void
rdbms_destroy (rdbms_t *rdbms) {

    if (!rdbms) return;

    if (rdbms->parser) {
        mexpr_parser_destroy (rdbms->parser);
        rdbms->parser = NULL;
    }

    if (rdbms->catalog) {
        catalog_destroy (rdbms->catalog);
        rdbms->catalog = NULL;
    }

    free (rdbms);
}

int
sql_query_exec (rdbms_t *rdbms, char *sql_query, char *err_msg)
{
    int rc = 0;

    if (!rdbms || !rdbms->catalog || !rdbms->parser) {
        sprintf (err_msg, "Error : Invalid RDBMS instance\n");
        return -1;
    }

    RDBMS_PARSER_BIND (rdbms);

    memset (&rdbms->qep, 0, sizeof (rdbms->qep));
    rdbms->qep.catalog = rdbms->catalog;
    rdbms->parse_alias_name = NULL;

    strncpy ((char *)p->lex_buffer, sql_query, sizeof (p->lex_buffer) - 1);
    p->lex_buffer[sizeof (p->lex_buffer) - 1] = '\0';
    lex_set_scan_buffer ((char *)p->lex_buffer);
    Parser_stack_reset ();

    parse_init (p);

    token_code = cyylex ();

    switch (token_code)
    {

    case SQL_SELECT_Q:

        yyrewind (1);
        err = select_query_parser (rdbms);
        if (err == PARSE_SUCCESS)
        {
            sql_execute_qep (rdbms->catalog, &rdbms->qep);
        }
        qep_deinit (&rdbms->qep);
        break;

    case SQL_CREATE_Q:

        yyrewind (1);
        err = create_query_parser (rdbms);
        if (err == PARSE_SUCCESS)
        {
            sql_process_create_query (rdbms->catalog, &rdbms->cdata);
        }
        sql_create_data_destroy (&rdbms->cdata);
        break;

    case SQL_INSERT_Q:

        yyrewind (1);
        err = insert_into_query_parser (rdbms);
        if (err == PARSE_SUCCESS)
        {
            sql_process_insert_query (rdbms->catalog, &rdbms->idata);
        }
        sql_insert_into_data_destroy (&rdbms->idata);
        break;

    case SQL_DROP_TABLE_Q:
    {
        char *table_name;
        token_code = cyylex ();
        if (strcmp (lex_curr_token, "table"))
        {
            sprintf (err_msg, "Error : Unrecognized Input\n");
            rc = -1;
            break;
        }
        token_code = cyylex ();
        if (token_code != SQL_IDENTIFIER)
        {
            sprintf (err_msg, "Error : Unrecognized Input\n");
            rc = -1;
            break;
        }
        table_name = lex_curr_token;
        token_code = cyylex ();
        if (token_code != PARSER_EOL)
        {
            sprintf (err_msg, "Error : Unrecognized Input\n");
            rc = -1;
            break;
        }
        sql_drop_table (rdbms->catalog, table_name);
        break;
    }

    case SQL_DELETE_Q:
        yyrewind (1);
        err = delete_query_parser (rdbms);
        if (err == PARSE_SUCCESS)
        {
            sql_execute_qep (rdbms->catalog, &rdbms->qep);
        }
        qep_deinit (&rdbms->qep);
        break;

    case SQL_UPDATE_Q:
        yyrewind (1);
        err = update_query_parser (rdbms);
        if (err == PARSE_SUCCESS)
        {
            sql_execute_qep (rdbms->catalog, &rdbms->qep);
        }
        qep_deinit (&rdbms->qep);
        break;

    case SQL_SHOW_DB_TABLES:
        sql_show_table_catalog (rdbms->catalog);
        break;

    case PARSER_QUIT:
        rc = 1;
        break;

    default:
        sprintf (err_msg, "Error : Unrecognized Input\n");
        rc = -1;
        break;
    }

    Parser_stack_reset ();
    return rc;
}
