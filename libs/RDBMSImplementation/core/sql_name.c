#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "sql_const.h"
#include "sql_name.h"
#include "qep.h"
#include "Catalog.h"

sql_col_name_type_t
sql_col_get_name_type ( qep_struct_t *qep, 
                                         char *col_name) {

    const char del[2] = ".";
    char fqcn[SQL_FQCN_SIZE] = {0};
    catalog_t *catalog = qep->catalog;

    strncpy (fqcn, col_name, SQL_FQCN_SIZE);

    char *str1 = strtok (fqcn, del);
    char *str2 = strtok (NULL, del);

    if (!str1) return SQL_COL_NAME_NOT_KNOWN;
    if (!str1 && !str2) return SQL_COL_NAME_NOT_KNOWN;
    if (str1 && !str2) return SQL_COL_NAME_LCN;

    auto it = qep->join.table_alias->find(str1);
    if (it !=  qep->join.table_alias->end()) return SQL_COL_NAME_ACN;

    ctable_val_t *ctable_val = sql_catalog_table_lookup_by_table_name (
                                catalog, str1);
    
    if (ctable_val) {
        return SQL_COL_NAME_FQCN;
    }

    return SQL_COL_NAME_NOT_KNOWN;
}


void 
sql_get_column_table_names ( qep_struct_t *qep,
                                                    char *input_column_name, 
                                                    char *table_name_out,
                                                    char *col_name_out) {
    
    const char del[2] = ".";
    char fqcn[SQL_FQCN_SIZE] = {0};

    strncpy (fqcn, input_column_name, SQL_FQCN_SIZE);

    char *str1 = strtok (fqcn, del);
    char *str2 = strtok (NULL, del);

    sql_col_name_type_t col_name_type = sql_col_get_name_type (
                                                                        qep, input_column_name);

    switch (col_name_type) {

        case SQL_COL_NAME_NOT_KNOWN:
            table_name_out[0] = '\0';
            col_name_out[0] = '\0';
            break;

        case SQL_COL_NAME_FQCN:
            strncpy (table_name_out, str1, SQL_TABLE_NAME_MAX_SIZE);
            strncpy (col_name_out, str2, SQL_COLUMN_NAME_MAX_SIZE);
            break;

        case SQL_COL_NAME_ACN:
        {
            auto it = qep->join.table_alias->find(str1);
            strncpy (table_name_out, it->second.c_str(), SQL_TABLE_NAME_MAX_SIZE);
            strncpy (col_name_out, str2, SQL_COLUMN_NAME_MAX_SIZE);
        }
        break;

        case SQL_COL_NAME_LCN:
            strncpy (table_name_out, qep->join.tables[0].table_name, 
                            SQL_TABLE_NAME_MAX_SIZE);
            strncpy (col_name_out, str1, SQL_COLUMN_NAME_MAX_SIZE);
            break;
        
        default:
            assert(0);
    }
}

void 
sql_convert_name_to_FQCN (qep_struct_t *qep, 
                                                char *input_column_name,
                                                int input_column_name_size) {

    sql_col_name_type_t name_type;
    char table_name [SQL_TABLE_NAME_MAX_SIZE];
    char column_name [SQL_COLUMN_NAME_MAX_SIZE];
    
    assert (input_column_name_size >= SQL_FQCN_SIZE);

    name_type = sql_col_get_name_type  (qep, input_column_name);

    if (name_type == SQL_COL_NAME_FQCN) { 
        return;
    }

    sql_get_column_table_names (qep, input_column_name, table_name, column_name);
    snprintf (input_column_name, input_column_name_size, "%s.%s", table_name, column_name);
}
