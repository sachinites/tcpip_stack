#ifndef __SQL_GROUP_BY__
#define __SQL_GROUP_BY__
#include <list>

typedef struct qep_struct_ qep_struct_t;
typedef struct catalog_ catalog_t;

/* C Wrapper object over C++ object because we cannot insert 
    C++ objects into HT. If you want you can use C++ hashmap etc.
*/
typedef struct ht_group_by_record_ {

    std::list<joined_row_t *> *record_lst ;

} ht_group_by_record_t;

void 
 sql_group_by_clause_group_records_phase1 (qep_struct_t *qep) ;

void 
sql_group_by_clause_process_grouped_records_phase2 (qep_struct_t *qep) ;

bool
sql_query_initialize_groupby_clause (qep_struct_t *qep, catalog_t *tcatalog) ;

bool
sql_query_initialize_having_clause (qep_struct_t *qep, catalog_t *tcatalog);

#endif 