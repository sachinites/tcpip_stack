#include <stdbool.h>
typedef struct qep_struct_ qep_struct_t;
typedef struct joined_row_ joined_row_t;
typedef struct catalog_ catalog_t;

bool
qep_execute_join_predicate (qep_struct_t *qep_struct, joined_row_t *joined_row);

bool
sql_query_initialize_where_clause (qep_struct_t *qep, catalog_t *tcatalog);