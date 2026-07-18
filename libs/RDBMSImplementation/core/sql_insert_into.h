#ifndef __SQL_INSERT_INTO__
#define __SQL_INSERT_INTO__

#include <stdbool.h>
#include "sql_const.h"
#include "../SqlParser/SqlEnums.h"

typedef struct catalog_ catalog_t;

typedef struct sql_value_ {

    sql_dtype_t dtype;

    union {

        char str_val[SQL_STRING_MAX_VAUE_LEN];
        int int_val;
        double d_val;
        char ipv4_addr_str[16];
        struct {
            int lb;
            int ub;
        } ival;
    } u;
} sql_value_t;


typedef struct sql_insert_into_data_ {

    char table_name[SQL_TABLE_NAME_MAX_SIZE];
    int n;
    sql_value_t  sql_values [SQL_MAX_COLUMNS_SUPPORTED_PER_TABLE];

} sql_insert_into_data_t;


void
 sql_process_insert_query (catalog_t *tcatalog, sql_insert_into_data_t *idata);

void
 sql_insert_into_data_destroy(sql_insert_into_data_t *idata);

#endif 
