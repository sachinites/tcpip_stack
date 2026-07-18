#include <assert.h>
#include "sql_join.h"
#include "qep.h"
#include "rdbms_ds.h"
#include "Catalog.h"
#include "SqlMexprIntf.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

bool 
sql_query_initialize_join_clause  (qep_struct_t *qep, catalog_t *tcatalog) {

    int i;

    for (i = 0; i < qep->join.table_cnt; i++) {

        qep->join.tables[i].ctable_val = sql_catalog_table_lookup_by_table_name (
                                                                   tcatalog, qep->join.tables[i].table_name);

       if (!qep->join.tables[i].ctable_val) {
            printf ("Error : Could not find table %s\n", qep->join.tables[i].table_name);
            return false;
       }
    }

    return true;
}

void 
table_iterators_init (qep_struct_t *qep,
                                table_iterators_t **_titer) {

    int i;

    if (*_titer == NULL) {

        (*_titer) = (table_iterators_t *)calloc (1, 
                        sizeof (table_iterators_t) + 
                        (sizeof (table_iter_data_t) * qep->join.table_cnt));
    }
    
    table_iterators_t *titer = (*_titer);

    titer->table_cnt = qep->join.table_cnt;
    
    for (i = 0 ; i < titer->table_cnt ; i++) {
        titer->table_iter_data[i].cursor.node = NULL;
        titer->table_iter_data[i].cursor.index = 0;
        titer->table_iter_data[i].ctable_val  = qep->join.tables[i].ctable_val;
    }
}


bool
table_iterators_first (qep_struct_t *qep_struct, 
                                 table_iterators_t *titer ) {

    int i;
    bool rc;
    void *rec;
    BPluskey_t *bp_key;

    qep_struct->is_join_started = true;
    qep_struct->is_join_finished = false;

    for (i = 0; i < qep_struct->join.table_cnt; i++) {

        assert (titer->table_iter_data[i].cursor.node == NULL);
        assert(titer->table_iter_data[i].cursor.index == 0);

        do {

            rec = rdbms_ds_cursor_next(
                titer->table_iter_data[i].ctable_val->record_table,
                &titer->table_iter_data[i].cursor,
                &bp_key);

            if (!rec) {

                qep_struct->is_join_started = false;
                qep_struct->is_join_finished = true;
                return false;
            }

            qep_struct->joined_row_tmplate->key_array[i] = bp_key;
            qep_struct->joined_row_tmplate->rec_array[i] = rec;

            rc = sql_evaluate_conditional_exp_tree(
                qep_struct->where.exptree_per_table[i]);

        } while (!rc);
    }

    return true;
}


void
table_iterators_next (qep_struct_t *qep_struct, 
                                  table_iterators_t *titer, 
                                  int table_id) {

    bool rc = true;
    void *rec = NULL;
    BPluskey_t *bp_key;

    if (table_id < 0) return ;

    do
    {
        rec = rdbms_ds_cursor_next(
                    titer->table_iter_data[table_id].ctable_val->record_table,
                    &titer->table_iter_data[table_id].cursor,
                    &bp_key);

        if (!rec) break;

        qep_struct->joined_row_tmplate->key_array[table_id] = bp_key;
        qep_struct->joined_row_tmplate->rec_array[table_id] = rec;

        rc = sql_evaluate_conditional_exp_tree (
                  qep_struct->where.exptree_per_table[table_id]);

    } while (!rc);

    /* If record is found*/
    if (rec) {
            return;
    }
    else {
        qep_struct->joined_row_tmplate->key_array[table_id] = NULL;
        qep_struct->joined_row_tmplate->rec_array[table_id] = NULL;
        table_iterators_next(qep_struct, titer, table_id - 1);

        /* If We could not find qualified record in the top level table, abort the iteration */
        if (table_id == 0) {
            qep_struct->is_join_finished = true;
            return;
        }

        /* If secondary table finds that parent table could not find any qualified records, abort the iteration*/
        if (!qep_struct->joined_row_tmplate->rec_array[table_id - 1]) {
            qep_struct->is_join_finished = true;
            return;
        }

        /* It is guaranteed that we will find atleast one qualified record*/
        do {
            rec = rdbms_ds_cursor_next(
                            titer->table_iter_data[table_id].ctable_val->record_table,
                            &titer->table_iter_data[table_id].cursor,
                            &bp_key);

            assert(rec);

            qep_struct->joined_row_tmplate->key_array[table_id] = bp_key;
            qep_struct->joined_row_tmplate->rec_array[table_id] = rec;

            rc = sql_evaluate_conditional_exp_tree (
                    qep_struct->where.exptree_per_table[table_id]);

        } while (!rc);
    }
}



bool
qep_execute_join (qep_struct_t *qep_struct) {

   if (!qep_struct->is_join_started) {

        table_iterators_first (qep_struct, qep_struct->titer);

        /* We could not get Ist Qualified record from each joined tables*/
        if (qep_struct->is_join_finished) return false;
        return true;
   }

    table_iterators_next (qep_struct, qep_struct->titer, qep_struct->join.table_cnt -1);
    return !qep_struct->is_join_finished;
}