#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <memory.h>
#include <arpa/inet.h>
#include <list>
#include <vector>
#include "../stack/stack.h"
#include "../BPlusTreeLib/BPlusTree.h"
#include "qep.h"
#include "Catalog.h"
#include "sql_io.h"
#include "sql_utils.h"
#include "sql_select.h"
#include "sql_group_by.h"
#include "sql_update.h"
#include "sql_order_by.h"
#include "sql_where.h"
#include "sql_delete.h"
#include "sql_join.h"
#include "SqlMexprIntf.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

bool 
qep_struct_record_table (qep_struct_t *qep_struct, char *table_name) {

    strncpy(qep_struct->join.tables[qep_struct->join.table_cnt].table_name , 
                    table_name, SQL_TABLE_NAME_MAX_SIZE );
    return true;
}

static void 
qep_create_alias_to_table_name_mapping (qep_struct_t *qep) {

    int i;

    qep->join.table_alias = new std::unordered_map<std::string, std::string>();

    for (i = 0; i < qep->join.table_cnt; i++) {

        if (qep->join.tables[i].alias_name[0] != '\0') {
            qep->join.table_alias->insert (
                {  std::string (qep->join.tables[i].alias_name),   
                    std::string (qep->join.tables[i].table_name)} );
        }
    }
}

static bool
sql_query_init_execution_plan (qep_struct_t *qep, catalog_t *tcatalog) {

    int i;
    bool rc;
    qp_col_t *qp_col;

    /* initialize the containers first as remaining initialization code is dependent on 
        these two allocations */
    qep->joined_row_tmplate = (joined_row_t *)calloc (1, sizeof (joined_row_t));
    qep->data_src_lst = new std::list<exp_tree_data_src_t *>();

    qep->catalog = tcatalog;

    qep_create_alias_to_table_name_mapping (qep);
    
    rc = sql_query_initialize_join_clause (qep, tcatalog);
    if (!rc) return rc;

    /* Before we initialize anything, expand the select * first */
    rc = qep_resolve_select_asterisk (qep);
    if (!rc) return rc;
   
   /* The order in which we initializes the below clauses matters. Select
        clause must be initialized in the end because rest of the clauses clones
        expression trees of  select clause. */
    rc = sql_query_initialize_where_clause  (qep, tcatalog);
    if (!rc) return rc;

    rc = sql_query_initialize_groupby_clause (qep, tcatalog);
    if (!rc) return rc;

    rc = sql_query_initialize_having_clause (qep, tcatalog);
    if (!rc) return rc;

    rc = sql_query_initialize_select_column_list (qep, tcatalog) ;
    if (!rc) return rc;

    rc = sql_query_initialize_orderby_clause (qep, tcatalog) ;
    if (!rc) return rc;
    
    rc = sql_query_initialize_update_query (qep, tcatalog);
    if (!rc) return rc;

    /* initialize other variables*/
    qep->is_join_started = false;
    qep->is_join_finished = false;

    /* initialize Iterators*/
    table_iterators_init (qep, &qep->titer);

    /* Initialize Joined Row*/
    joined_row_t *joined_row_tmplate = qep->joined_row_tmplate;
    joined_row_tmplate->size = qep->join.table_cnt;
    joined_row_tmplate->key_array = (BPluskey_t **) calloc (qep->join.table_cnt, sizeof (BPluskey_t *));
    joined_row_tmplate->rec_array = (void **) calloc (qep->join.table_cnt, sizeof (void *));
    return true;
}


void 
sql_execute_qep (catalog_t *tcatalog, qep_struct_t *qep) {

    assert (tcatalog);

    if (!sql_query_init_execution_plan (qep, tcatalog)) {

        printf ("Error : Failed to initialize Query Execution Plan\n");
        return;
    }

    switch (qep->query_type) {

        case SQL_SELECT_Q:
            sql_process_select_query (qep);
            break;
        case SQL_DELETE_Q:
            sql_process_delete_query (qep);
            break;
        case SQL_UPDATE_Q:
            sql_process_update_query (qep);
            break;
        default:
            printf ("Error : Could not identify Query type\n");
            break;
    }
}

void 
memset0_qep (qep_struct_t *qep) {

    qep->query_type = SQL_UNSUPPORTED_Q;

    qep->join.table_cnt = 0;
    memset (qep->join.tables, 0, sizeof (qep->join.tables));
    qep->join.table_alias = NULL;

    qep->where.gexptree = NULL;
    memset (qep->where.exptree_per_table, 0, sizeof (qep->where.exptree_per_table));

    qep->groupby.n = 0;
    memset (qep->groupby.col_list, 0, sizeof (qep->groupby.col_list));
    qep->groupby.ht = NULL;
    qep->groupby.ht_key_size = 0;

    qep->having.gexptree_phase1 = NULL;
    qep->having.gexptree_phase2 = NULL;

    qep->select.n = 0;
    memset (qep->select.sel_colmns, 0, sizeof (qep->select.sel_colmns));
    qep->select.sql_record_reader = NULL;
    qep->select.app_data = NULL;

    qep->update.n = 0;
    memset (qep->update.upd_colmns, 0, sizeof (qep->update.upd_colmns));

    qep->distinct.distinct = false;
    qep->distinct.col = NULL;

    qep->orderby.asc = false;
    qep->orderby.column_name[0] = '\0';
    qep->orderby.orderby_col_select_index = 0;
    qep->orderby.pVector.clear();
    qep->orderby.iterator_index = 0;

    qep->limit = 0;

    qep->is_join_started = false;
    qep->is_join_finished = false;
    qep->titer = NULL;
    qep->joined_row_tmplate = NULL;
    qep->data_src_lst = NULL;
}

void 
qep_deinit (qep_struct_t *qep) {

    int i;
    qp_col_t *qp_col;
    struct hashtable_itr *itr;
    joined_row_t *joined_row;
    exp_tree_data_src_t *data_src;
    std::list<joined_row_t *> *record_lst;
    ht_group_by_record_t *ht_group_by_record;

    if (qep->where.gexptree) {
        
        sql_destroy_exp_tree (qep->where.gexptree);
        qep->where.gexptree = NULL;
    }

    if (qep->groupby.n) {

        for (i = 0; i < qep->groupby.n; i++) {

            qp_col = qep->groupby.col_list[i];

            if (qp_col->sql_tree) {
                sql_destroy_exp_tree (qp_col->sql_tree );
                qp_col->sql_tree = NULL;
                if (qp_col->computed_value) {
                    sql_destroy_Dtype_value_holder (qp_col->computed_value);
                    qp_col->computed_value = NULL;
                }
                else if (qp_col->aggregator){
                    sql_destroy_aggregator (qp_col);
                }
            }
            free(qp_col);
        }

        if (qep->groupby.ht) {

            itr = hashtable_iterator(qep->groupby.ht);

            do {

                ht_group_by_record =  (ht_group_by_record_t *)hashtable_iterator_value (itr);
                record_lst = ht_group_by_record->record_lst;

                while (!record_lst->empty()) {

                    joined_row = record_lst->front();
                    record_lst->pop_front();
                    free(joined_row->key_array);
                    free(joined_row->rec_array);
                    free(joined_row); 
                }
                delete  record_lst;
                ht_group_by_record->record_lst = NULL;

            } while (hashtable_iterator_advance(itr));

            free(itr);
            hashtable_destroy(qep->groupby.ht, 1);
            qep->groupby.ht = NULL;
        }
    }

    if (qep->having.gexptree_phase1) {
        sql_destroy_exp_tree (qep->having.gexptree_phase1);
        qep->having.gexptree_phase1 = NULL;
    }

    if (qep->having.gexptree_phase2) {
        sql_destroy_exp_tree (qep->having.gexptree_phase2);
        qep->having.gexptree_phase2 = NULL;
    }

    if (qep->select.n) {

        for (i = 0; i < qep->select.n; i++) {

            qp_col = qep->select.sel_colmns[i];
            if (qp_col->sql_tree) {
                 sql_destroy_exp_tree (qp_col->sql_tree);
                qp_col->sql_tree = NULL;
            }

            if (qp_col->computed_value) {
                sql_destroy_Dtype_value_holder(qp_col->computed_value);
                qp_col->computed_value = NULL;
            }
            else if (qp_col->aggregator){
                sql_destroy_aggregator (qp_col);
            }
            free(qp_col);            
        }
    }

    free (qep->titer);
    qep->titer = NULL;

    /* Free update query resources*/
    if (qep->update.n) {

        for (i = 0; i < qep->update.n; i++) {
            if (qep->update.upd_colmns[i].value_exptree) {
                sql_destroy_exp_tree (qep->update.upd_colmns[i].value_exptree);
                qep->update.upd_colmns[i].value_exptree = NULL;
            }
        }
        qep->update.n = 0;
    }

    if (qep->joined_row_tmplate) {
        free (qep->joined_row_tmplate->key_array);
        free (qep->joined_row_tmplate->rec_array);
        free(qep->joined_row_tmplate);
    }

    /* Free Data Srcs*/
    if (qep->data_src_lst) {

        while (!qep->data_src_lst->empty()) {

            data_src = qep->data_src_lst->front();
            qep->data_src_lst->pop_front();
            free(data_src);
        }
        delete qep->data_src_lst;
        qep->data_src_lst = NULL;
    }

    /* Free Alias Hashmap*/
    if (qep->join.table_alias) {

        qep->join.table_alias->clear();
        delete qep->join.table_alias;
        qep->join.table_alias = NULL;
    }

    /* Free order by Vector */
    for (i =0; i < qep->orderby.pVector.size(); i++) {

        std::vector < Dtype *> *cVector = qep->orderby.pVector.at(i);
        if (!cVector) continue;
        for (int j = 0; j < cVector->size(); j++) {
            sql_destroy_Dtype_value_holder (cVector->at(j));
        }
        delete cVector;
        qep->orderby.pVector[i] = NULL;
    }

     if (qep->orderby.pVector.size()) {
        qep->orderby.pVector.clear();
     }

}
