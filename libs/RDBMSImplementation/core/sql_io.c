#include <stddef.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <vector>
#include "sql_const.h"
#include "rdbms_struct.h"
#include "qep.h"
#include "Catalog.h"
#include "sql_io.h"
#include "../BPlusTreeLib/BPlusTree.h"
#include "sql_utils.h"
#include "SqlMexprIntf.h"
#include "sql_name.h"

extern int cprintf (const char *fmt,...);
#define printf cprintf


#define SCREEN_WIDTH    80
#define COLUMN_WIDTH   20

static void 
print_line(int num_columns, int column_width) {
    for (int i = 0; i < num_columns; i++) {
        for (int j = 0; j < column_width; j++) {
            printf("-");
        }
        printf("+");
    }
    printf("\n");
}

void 
sql_print_hdr (qep_struct_t *qep, qp_col_t **col_list, int n_cols ) {

    int i;
    qp_col_t *col;
    int num_columns = n_cols;

    char table_name[SQL_TABLE_NAME_MAX_SIZE];
    char column_name[SQL_COLUMN_NAME_MAX_SIZE];
    char composite_col_name[SQL_FQCN_SIZE];

    int column_width = COLUMN_WIDTH; // Default column width
    
    if (qep->select.sql_record_reader) {
        return;
    }

    if (num_columns > 0) {
        column_width = SCREEN_WIDTH / num_columns; // Adjust column width based on available space
    }

    // Print the top line
    print_line(num_columns, column_width);

    for (i = 0; i < n_cols; i++) {

        col = col_list[i];

        if (qep->join.table_cnt > 1) {
        
            printf("%-*s|", column_width, col->alias_name);
        }

        else {
        
            /* col->alias_name[0] = '\0' when user has typed an expression without specifying
                an alias name, eg : select a + b from quad */
            if (col->alias_name[0] != '\0') {

                sql_get_column_table_names (qep,
                                                                   col->alias_name,
                                                                   table_name,
                                                                   column_name );
                printf("%-*s|", column_width, column_name);
            }
            else {
                printf("%-*s|", column_width, "");
            }
        }
    }

    printf("\n");

    // Print the line below the header
    print_line(num_columns, column_width);
}


void sql_emit_select_output(qep_struct_t *qep,
                                               int n_col,
                                               qp_col_t **col_list_head) {

    int i;
    Dtype *dtype;
    qp_col_t *qp_col;
    int num_columns = n_col;
    std::vector<Dtype *> dtype_vector;

    if (qep->select.sql_record_reader) {

        
        for (i = 0; i < n_col; i++) {
            
            qp_col = col_list_head[i];
            dtype = (qp_col->agg_fn != SQL_AGG_FN_NONE ) ? \
                                    sql_column_get_aggregated_value (qp_col) :  \
                                    qp_col->computed_value;
            dtype_vector.push_back (dtype);
        }
        qep->select.sql_record_reader (qep->select.app_data, &dtype_vector);
        dtype_vector.clear();
        return;
    }


    int column_width = COLUMN_WIDTH; // Default column width

    if (num_columns > 0) {
        column_width = SCREEN_WIDTH / num_columns; // Adjust column width based on available space
    }

    dtype_value_t dtype_value;

    // Print each row of data
    for (i = 0; i < n_col; i++) {

        qp_col = col_list_head[i];
        dtype = (qp_col->agg_fn != SQL_AGG_FN_NONE ) ? \
                                    sql_column_get_aggregated_value (qp_col) :  \
                                    qp_col->computed_value;

        dtype_value = DTYPE_GET_VAUE(dtype);

        switch (dtype_value.dtype) {

            case SQL_STRING:
                printf("%-*s|", column_width, dtype_value.u.str_val);
                break;

            case SQL_INT:
                printf("%-*d|", column_width, dtype_value.u.int_val);
                break;

            case SQL_DOUBLE:
                if (mexpr_double_is_integer ( dtype_value.u.d_val)) {
                    printf("%-*d|", column_width, (int)dtype_value.u.d_val);
                }
                else {
                    printf("%-*f|", column_width, dtype_value.u.d_val);
                }
                break;

            case SQL_BOOL:
                printf("%-*s|", column_width, dtype_value.u.b_val ? "True" : "False"); 
                break;
                
            case SQL_IPV4_ADDR:
                printf("%-*s|", column_width, dtype_value.u.ipv4.ipv4_addr_str);
                break;

            case SQL_INTERVAL: 
                printf("%-*s|", column_width, dtype_value.u.interval.interval_str);
                break;

            default:
                assert(0);
        }
    }
    printf("\n");
}
