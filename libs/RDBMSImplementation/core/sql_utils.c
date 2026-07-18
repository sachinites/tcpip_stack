
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>
#include <string>
#include <vector>
#include "qep.h"
#include "sql_const.h"
#include "Catalog.h"
#include "sql_utils.h"
#include "sql_create.h"
#include "SqlMexprIntf.h"

qp_col_t *
sql_get_qp_col_by_name (   qp_col_t **qp_col_array, 
                                                        int n, 
                                                        char *name, 
                                                        bool is_alias) {

    int i;
    int len;
    qp_col_t *qp_col;

    len = strlen (name) ;
    
    for (i = 0; i < n; i++) {

        qp_col = qp_col_array[i];

        if (is_alias) {

            if (!qp_col->alias_provided_by_user) continue;
            if (strncmp (name, qp_col->alias_name, SQL_ALIAS_NAME_LEN)) continue;
            if (len != strlen (qp_col->alias_name)) continue;
            return qp_col;
        }
        else {

            if (!sql_is_single_operand_expression_tree  (qp_col->sql_tree)) continue;

            if (strncmp (
                name, 
                qp_col->alias_name,
                SQL_FQCN_SIZE)) continue;

            return qp_col;
        }
    }

    return NULL;
}

bool
sql_read_interval_values (char *string_fmt,  // "[ a , b]"
                                            int *a, int *b) {

    int i = 0, j = 0;
    char dst_buffer[64];

    int string_fmt_len = strlen (string_fmt);

    if (string_fmt_len > sizeof(dst_buffer)) {
        return false;
    }

    while (string_fmt[i] != '\0' && i < string_fmt_len)
    {
        if (string_fmt[i] == ' ')
        {
            i++;
            continue;
        }
        dst_buffer[ j++] = string_fmt[i];
        i++;
    }
    dst_buffer[j] = '\0';
    sscanf(dst_buffer, "[%d,%d]", a, b);
    return true;
}

void 
sql_select_flush_computed_values (qep_struct_t *qep) {

    int i;
    qp_col_t *sqp_col;

    for (i = 0; i < qep->select.n; i++) {

        sqp_col = qep->select.sel_colmns[i];

        if (sqp_col->computed_value) {
            sql_destroy_Dtype_value_holder (sqp_col->computed_value);
            sqp_col->computed_value = NULL;
        }

        if (sqp_col->aggregator) {
            sql_destroy_aggregator (sqp_col);
            sqp_col->aggregator = NULL;
        }
    }
}

bool 
sql_is_dtype_compatible (sql_dtype_t expected_dtype, sql_dtype_t computed_dtype) {

    if (expected_dtype == computed_dtype) return true;
    if (expected_dtype == SQL_DOUBLE && computed_dtype == SQL_INT) return true;
    if (expected_dtype == SQL_INT && computed_dtype == SQL_DOUBLE) return true;
    return false;  
}

int 
sql_get_qep_table_index (qep_struct_t *qep, char *table_name) {

    int i;

    catalog_t *catalog = qep->catalog;

    ctable_val_t *ctable_val = 
            sql_catalog_table_lookup_by_table_name (
                catalog, table_name);
    
    if (!ctable_val) return -1;

    for (i = 0; i < qep->join.table_cnt; i++) {

        if (qep->join.tables[i].ctable_val == ctable_val) return i;
    }

    return -1;
}