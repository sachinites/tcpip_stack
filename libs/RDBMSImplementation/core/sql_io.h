#ifndef __SQL_IO__
#define __SQL_IO__

typedef struct qp_col_ qp_col_t;
typedef struct qep_struct_ qep_struct_t;

void 
sql_print_hdr (qep_struct_t *qep, qp_col_t **col_list, int n_cols );

void sql_emit_select_output(qep_struct_t *qep,
                                               int n_col,
                                              qp_col_t **col_list_head);

#endif 