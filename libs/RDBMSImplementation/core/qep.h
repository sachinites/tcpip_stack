#ifndef __QPLANNER__
#define __QPLANNER__

#include <list>
#include <vector>
#include <unordered_map>
#include "../Tree/libtree.h"
#include "../SqlParser/SqlEnums.h"
#include "sql_const.h"
#include "rdbms_struct.h"
#include "../c-hashtable/hashtable.h"

class Dtype;

typedef void (*sql_record_reader_fn_ptr)(void *, std::vector<Dtype *> *);

typedef struct catalog_table_value ctable_val_t ;
typedef struct schema_rec_ schema_rec_t ;
typedef struct catalog_ catalog_t;
typedef  struct hashtable hashtable_t;
typedef struct stack Stack_t;
typedef struct sql_exptree_ sql_exptree_t;
typedef struct table_iterators_  table_iterators_t;


typedef enum qp_stage_id {

    QP_NODE_SEQ_SCAN,
    QP_NODE_WHERE,
    QP_NODE_JOIN,
    QP_NODE_JOIN_PREDICATE,
    QP_NODE_GROUP_BY,
    QP_NODE_HAVING,
    QP_NODE_SELECT,
    QP_NODE_DISTINCT,
    QP_NODE_ORDER_BY,
    QP_NODE_LIMIT,
    QP_NODE_OUTPUT,
    QP_NODE_MAX

} qp_stage_id_t;


typedef struct qep_struct_ {
    
    sql_query_type_t query_type;

    struct {

        int table_cnt;

        struct {

            ctable_val_t *ctable_val;
            char alias_name[SQL_ALIAS_NAME_LEN];
            char table_name[SQL_TABLE_NAME_MAX_SIZE];

        } tables [SQL_MAX_TABLES_IN_JOIN_LIST];

        /* Hash Map to store mapping from alias -> table name*/
        std::unordered_map<std::string, std::string> *table_alias;

    } join;

    struct {
            
            sql_exptree_t *gexptree;
            sql_exptree_t *exptree_per_table[SQL_MAX_TABLES_IN_JOIN_LIST];

    } where;

    struct {

        int n;
        qp_col_t *col_list[SQL_MAX_COLS_IN_GROUPBY_LIST];
        hashtable_t *ht;
        int ht_key_size;

    } groupby;

    struct {

         sql_exptree_t *gexptree_phase1;
         sql_exptree_t *gexptree_phase2;

    } having;

    struct {

        int n;
        qp_col_t *sel_colmns[SQL_MAX_COLS_IN_SELECT_LIST];
        sql_record_reader_fn_ptr sql_record_reader;
        void *app_data;
        
    } select;

    struct {

        int n;
        struct {

            char col_name[SQL_COLUMN_NAME_MAX_SIZE]; // Read from parser
            schema_rec_t *schema_rec;   /* Schema record of this column*/
            sql_exptree_t *value_exptree;   /* Expression Tree of the value expression for this column, init by the parser*/

        } upd_colmns[SQL_MAX_COLS_IN_UPDATE_LIST];

    } update;

    struct {

        bool distinct;
        qp_col_t *col;

    } distinct;

    struct {

        bool asc;
        char column_name[SQL_FQCN_SIZE];
        int orderby_col_select_index; // At what index the order by column exist in select column list
        std::vector <std::vector <Dtype *> *> pVector;
        int iterator_index;
        
    } orderby;

    uint32_t limit;  /* 0 means no limit*/

    /* other variables*/
    bool is_join_started;
    bool is_join_finished;
    table_iterators_t *titer;

    joined_row_t *joined_row_tmplate;

    /* Remember, C objects cannot have STL C++ containers, but
        can have pointers to them as members */
    std::list<exp_tree_data_src_t *> *data_src_lst;

    catalog_t *catalog;

} qep_struct_t;

void
sql_process_select_query (catalog_t *tcatalog, qep_struct_t *qep);

void 
memset0_qep (qep_struct_t *qep);

void 
qep_deinit (qep_struct_t *qep);

bool 
qep_struct_record_table (qep_struct_t *qep,  char *table_name);

void 
sql_execute_qep (catalog_t *tcatalog, qep_struct_t *qep) ;

#endif 
