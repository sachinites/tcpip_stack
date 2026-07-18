#ifndef __RDBMS_STRUCT__
#define __RDBMS_STRUCT__

#include <string>

#include "../SqlParser/SqlEnums.h"
#include "sql_const.h"
#include "../BPlusTreeLib/BPlusTree.h"

typedef struct catalog_table_value ctable_val_t ;
typedef struct schema_rec_ schema_rec_t ;
typedef struct sql_exptree_ sql_exptree_t;

class Dtype;
class Aggregator;

typedef struct qp_col_ {

    sql_exptree_t *sql_tree;
    sql_agg_fn_t agg_fn;
    Dtype* computed_value;
    Aggregator *aggregator;
    bool alias_provided_by_user;
    char alias_name[SQL_ALIAS_NAME_LEN];
    
}qp_col_t;

typedef struct joined_row_ {

    // size : could be 1 when where is enforced on a single table OR
    // table_cnt when where is enforced on Joined Row
    int size;  
    BPluskey_t **key_array;
    void **rec_array;

} joined_row_t;

typedef struct exp_tree_data_src_ {

    int table_index;
    schema_rec_t *schema_rec;
    joined_row_t **joined_row;

} exp_tree_data_src_t;

#endif 
