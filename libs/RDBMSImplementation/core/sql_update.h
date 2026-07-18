#ifndef SQL_UPDATE_H
#define SQL_UPDATE_H

#include <stdbool.h>

typedef struct qep_struct_ qep_struct_t;
typedef struct catalog_ catalog_t;

void 
sql_process_update_query (qep_struct_t *qep);

bool
 sql_query_initialize_update_query (qep_struct_t *qep, catalog_t *TableCatalog);

#endif //SQL_UPDATE_H