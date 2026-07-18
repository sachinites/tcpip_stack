#ifndef __RDBMS_CTX__
#define __RDBMS_CTX__

#include "../core/qep.h"
#include "../core/sql_create.h"
#include "../core/sql_insert_into.h"

typedef struct mexpr_parser_ mexpr_parser_t;
typedef struct catalog_ catalog_t;

/* Thread-safe session: all per-connection state lives here (no parser globals). */
typedef struct rdbms_instance_ {

    catalog_t *catalog;
    mexpr_parser_t *parser;

    qep_struct_t qep;
    sql_create_data_t cdata;
    sql_insert_into_data_t idata;

    /* Transient pointer used while parsing SELECT/DELETE table aliases. */
    char *parse_alias_name;

} rdbms_t;

#endif
