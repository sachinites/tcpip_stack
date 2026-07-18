#ifndef __SQL_SELECT__
#define __SQL_SELECT__

typedef struct qep_struct_ qep_struct_t;
typedef struct catalog_ catalog_t ;

bool
sql_query_initialize_select_column_list (qep_struct_t *qep, catalog_t *tcatalog);

bool 
qep_resolve_select_asterisk (qep_struct_t *qep);

void 
sql_process_select_query (qep_struct_t *qep) ;

#endif 