#ifndef __SQL_NAME__
#define __SQL_NAME__

#include <stdbool.h>

typedef struct qep_struct_ qep_struct_t;

typedef enum COL_NAME_TYPE_ {

    SQL_COL_NAME_NOT_KNOWN,
    SQL_COL_NAME_FQCN,
    SQL_COL_NAME_ACN,
    SQL_COL_NAME_LCN

} sql_col_name_type_t;


void 
sql_get_column_table_names ( qep_struct_t *qep,
                                                    char *input_column_name, 
                                                    char *table_name_out,
                                                    char *col_name_out);

sql_col_name_type_t
sql_col_get_name_type ( qep_struct_t *qep, 
                                         char *col_name);

void 
sql_convert_name_to_FQCN (qep_struct_t *qep, 
                                                char *input_column_name,
                                                int input_column_name_size);
#endif 
