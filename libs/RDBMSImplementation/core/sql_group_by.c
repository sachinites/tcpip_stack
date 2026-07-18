#include <assert.h>
#include <list>
#include <memory.h>
#include "Catalog.h"
#include "qep.h"
#include "sql_group_by.h"
#include "sql_order_by.h"
#include "sql_io.h"
#include "sql_utils.h"
#include "SqlMexprIntf.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"
#include "sql_utils.h"
#include "sql_name.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

bool
sql_query_initialize_groupby_clause (qep_struct_t *qep, catalog_t *tcatalog) {

    bool rc;
    int i, j;
    int tindex;
    ctable_val_t *ctable_val;
    MexprNode *exptree_node;
    qp_col_t *gqp_col, *sqp_col;
    bool all_alias_resolved = false;
    char table_name_out [SQL_TABLE_NAME_MAX_SIZE];
    char lone_col_name [SQL_COLUMN_NAME_MAX_SIZE];

    if (qep->groupby.n == 0)  return true;

    /* Three cases :
    1. The group by column gqp_col is an alias name
    2. The group by column gqp_col is a table column name
    3. The group by column is an expression */

    for (i = 0; i < qep->groupby.n; i++) {

        gqp_col = qep->groupby.col_list[i];

        if (sql_is_single_operand_expression_tree (gqp_col->sql_tree)) {
            
            sqp_col = sql_get_qp_col_by_name (
                                qep->select.sel_colmns,
                                qep->select.n, 
                                QP_COL_NAME(gqp_col), true);

            // 1. The group by column gqp_col is an alias name
            if (sqp_col) {

                if (sqp_col->agg_fn != SQL_AGG_FN_NONE) {

                    printf ("Error : Aggregate fn cannot be applied on column %s\n", sqp_col->alias_name);
                    return false;
                }

                sql_tree_expand_all_aliases (qep, gqp_col->sql_tree);
                sql_tree_operand_names_to_fqcn (qep, gqp_col->sql_tree);

                rc =  (sql_resolve_exptree (tcatalog, 
                                                             gqp_col->sql_tree, 
                                                             qep,
                                                             &qep->joined_row_tmplate));

                if (!rc) {

                    printf ("Error : Group by Column %s could not be resolved\n", sqp_col->alias_name);
                    return false;
                }
            }

            else {
                /* gqp_col could be pure table column name,  which may or may not exist in select list
                    2. The group by column gqp_col is a table column name
                */
                sql_get_column_table_names (qep, 
                                QP_COL_NAME (gqp_col),
                                table_name_out, lone_col_name);
                
                tindex = sql_get_qep_table_index (qep, table_name_out);
                
                if ( tindex < 0 ) {
                    printf("Error : Table %s is not specified in Join list\n", table_name_out);
                    return false;
                }

                ctable_val = qep->join.tables[tindex].ctable_val;

                sql_tree_operand_names_to_fqcn (qep, gqp_col->sql_tree);
                rc = sql_resolve_exptree_against_table (qep,
                                                                                tcatalog,
                                                                                gqp_col->sql_tree, 
                                                                                ctable_val, 
                                                                                tindex,
                                                                                &qep->joined_row_tmplate, qep->data_src_lst);                
                if (!rc) {

                    printf ("Error : Group by column %s could not be resolved against table %s\n",
                                    QP_COL_NAME(gqp_col), ctable_val->table_name);
                    return false;
                }
            }
        }

        // 3. The group by column is an expression */

        sql_tree_expand_all_aliases (qep, gqp_col->sql_tree);
        sql_tree_operand_names_to_fqcn (qep, gqp_col->sql_tree);

        rc =  (sql_resolve_exptree (tcatalog, 
                                                    gqp_col->sql_tree, 
                                                    qep,
                                                    &qep->joined_row_tmplate));                

        if (!rc) {

            printf ("Error : Could not resolve Unnamed %dth group by Expression Tree\n", i);
            return false;
        }
    }

    return true;
}

/* In HAVING condidion, variables with aggrgated fn applied on them do not contribute
    to the evaluation of having condition in phase 1. Reformed the expression tree by
    getting rid of such variables */
static bool
sql_query_initialize_having_clause_phase1 (qep_struct_t *qep, catalog_t *tcatalog) {

    qp_col_t *sqp_col;
    std::string opnd_name;
    MexprNode *opnd_node;

     SqlExprTree_Iterator_Operands_Begin (qep->having.gexptree_phase1, opnd_node) {

        opnd_name = sql_get_opnd_variable_name (opnd_node);

        sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), true);
       
        if (sqp_col) {

            if(sqp_col->agg_fn != SQL_AGG_FN_NONE) {
                sql_opnd_node_mark_unresolvable(opnd_node);
            }
        }
        else {
            
             sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), false);

             if (sqp_col) {

                 if (sqp_col->agg_fn != SQL_AGG_FN_NONE) {

                     sql_opnd_node_mark_unresolvable(opnd_node);
                 }
             }
        }
     }

     sql_tree_expand_all_aliases (qep, qep->having.gexptree_phase1);
     sql_tree_operand_names_to_fqcn (qep, qep->having.gexptree_phase1);
     sql_resolve_exptree (tcatalog, qep->having.gexptree_phase1, qep, &qep->joined_row_tmplate);
     sql_tree_remove_unresolve_operands (qep->having.gexptree_phase1);
    return true;
}

static Dtype *
Wrapper_sql_column_get_aggregated_value (void *data_src) {

    qp_col_t *sqp_col = (qp_col_t *)data_src;
    Dtype  *res =  sql_column_get_aggregated_value (sqp_col);
    return Dtype_copy(res);
}

extern sql_dtype_t
mexpr_to_sql_dtype_converter (mexprcpp_dtypes_t dtype);

/* Phase 2 HAVING exp tree contains Operands ( Aliases Or Actual table column) on which
    some Agg fn is enforced. Rest of the operands are already marked as Unresolved. All these
    operands are necessary present in select column list.
    Data src will be : sqp_col
    compute fn : Wrapper over sql_column_get_aggregated_value ( )
*/

static bool
sql_resolve_exptree_having_phase2 (qep_struct_t *qep,
                                                            sql_exptree_t *exp_tree) {

    qp_col_t *sqp_col;
    std::string opnd_name;
    MexprNode *opnd_node;

    SqlExprTree_Iterator_Operands_Begin (qep->having.gexptree_phase2, opnd_node) {

        if (sql_opnd_node_is_unresolvable (opnd_node)) continue;

        opnd_name = sql_get_opnd_variable_name (opnd_node);

        sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), true);

        if (!sqp_col) {

            sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), false);
        }

        assert (sqp_col);

        InstallDtypeOperandProperties (
                    opnd_node, 
                    sql_dtype_get_type(sql_column_get_aggregated_value (sqp_col)),
                    (void *)sqp_col,
                    Wrapper_sql_column_get_aggregated_value);
    }

    sql_tree_remove_unresolve_operands (qep->having.gexptree_phase2);
    return true;
}

/* HAVING exp tree of phase 2 is exactly complementary ( opposite) to exp tree of phase 1.
    In this case, we keep operands on which Agg fn is applied, and get rid of the rest
*/
static bool
sql_query_initialize_having_clause_phase2 (qep_struct_t *qep) {

    qp_col_t *sqp_col;
    std::string opnd_name;
    MexprNode *opnd_node;

    if (!qep->having.gexptree_phase2) return true;

    SqlExprTree_Iterator_Operands_Begin (qep->having.gexptree_phase2, opnd_node) {

        opnd_name = sql_get_opnd_variable_name (opnd_node);

        sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), true);

        if (!sqp_col) {

            sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), false);
        }

        if (!sqp_col) {
            /* User has mentioned such a column in having condition which is not present in select
                list by alias name or table column name. This column could be present in group by list 
                but we have covered filtering based on that in phase 1 already. So, we dont need filtering
                based on this operand any more*/
            sql_opnd_node_mark_unresolvable(opnd_node);
            continue;
        }

        if (sqp_col->agg_fn == SQL_AGG_FN_NONE) {

             /* In phase 2, ignore filtering based on any operand which is not aggregated*/
            sql_opnd_node_mark_unresolvable(opnd_node);
        }
    }

    return sql_resolve_exptree_having_phase2 (qep, qep->having.gexptree_phase2);
}

bool
sql_query_initialize_having_clause (qep_struct_t *qep, catalog_t *tcatalog) {

    if (qep->having.gexptree_phase1 == NULL) return true;

    if (qep->having.gexptree_phase2 == NULL) {
        qep->having.gexptree_phase2 = sql_clone_expression_tree (qep->having.gexptree_phase1);
    }

    return sql_query_initialize_having_clause_phase1 (qep, tcatalog);
}

/* This fn setup the hashtable also if it is a first record we are grouping*/
void 
sql_group_by_clause_group_records_phase1 (qep_struct_t *qep) {
    
    int i;
    char *ht_key;  
    Dtype *dtype;
    qp_col_t *qp_col;
    int ht_key_size = 0;
    joined_row_t *joined_row;
    dtype_value_t dtype_value;
    unsigned int string_hash = 0;
    bool is_ht_exist = qep->groupby.ht ? true : false;
    ht_group_by_record_t  *ht_group_by_record = NULL;

    /* Filter unwanted records */
    if (!sql_evaluate_conditional_exp_tree (qep->having.gexptree_phase1)) {
        return;
    };

    ht_key = (char *)calloc (is_ht_exist ? qep->groupby.ht_key_size :  SQL_MAX_HT_KEY_SIZE, 1);

    for (i = 0; i < qep->groupby.n; i++) {

        qp_col = qep->groupby.col_list[i];
        dtype = sql_evaluate_exp_tree (qp_col->sql_tree);

        if (sql_dtype_get_type (dtype)== SQL_STRING) {
            /* String string are of verying sizes, therefore, we will compute a
            fixed size 4 B hashcode of the strings to store as key in HT. Hashtable
            can store keys of fixed size only*/
	        dtype_value = DTYPE_GET_VAUE(dtype);
            string_hash = hashfromkey ((void *)dtype_value.u.str_val);
            memcpy ((void *) (ht_key + ht_key_size), &string_hash, sizeof (string_hash));
            ht_key_size +=  sizeof (string_hash);
            sql_destroy_Dtype_value_holder(dtype);
            assert (ht_key_size < SQL_MAX_HT_KEY_SIZE);
            continue;
        }

        ht_key_size +=  sql_dtype_serialize (dtype, (void *)(ht_key + ht_key_size));
        sql_destroy_Dtype_value_holder(dtype);
        assert (ht_key_size < SQL_MAX_HT_KEY_SIZE);
    }

    if (!is_ht_exist) {
        
        ht_key = (char *)realloc ( (void *)ht_key, ht_key_size);

        qep->groupby.ht = create_hashtable(
                            ht_key_size,
                            hashfromkey, equalkeys);
    
        qep->groupby.ht_key_size = ht_key_size;
    }
    else {
        assert (ht_key_size ==  qep->groupby.ht_key_size);
    }

    /* Create a new joined_row to be inserted into HT*/
    joined_row = (joined_row_t *)calloc (1, sizeof (joined_row_t));
    memcpy (joined_row, qep->joined_row_tmplate, sizeof (joined_row_t));
    joined_row->key_array = (BPluskey_t **) calloc (joined_row->size,  sizeof (BPluskey_t *));
    joined_row->rec_array = (void **)calloc (joined_row->size, sizeof (void *));
    for (i = 0; i < joined_row->size; i++) {
        joined_row->key_array[i] =  qep->joined_row_tmplate->key_array[i];
        joined_row->rec_array[i] = qep->joined_row_tmplate->rec_array[i];
    }

    ht_group_by_record = (ht_group_by_record_t  *)hashtable_search (qep->groupby.ht , ht_key);

    if (ht_group_by_record) {
        ht_group_by_record->record_lst->push_back (joined_row);
    }
    else {
        ht_group_by_record = 
                (ht_group_by_record_t *)calloc (1, sizeof (ht_group_by_record_t));
        std::list<joined_row_t *> *record_lst = new std::list<joined_row_t *>();
        ht_group_by_record->record_lst = record_lst;
        record_lst->push_back (joined_row);
        assert((hashtable_insert (qep->groupby.ht, (void *)ht_key, (void *)ht_group_by_record)));
    }
}

static void 
 sql_group_by_compute_aggregation (qep_struct_t *qep) {

    int i;
    qp_col_t *sqp_col;
    Dtype *computed_value;

    for (i = 0; i < qep->select.n; i++) {

        sqp_col = qep->select.sel_colmns[i];
       
        if (sqp_col->agg_fn == SQL_AGG_FN_NONE) continue;

        if (!sqp_col->aggregator) {

            sqp_col->computed_value = sql_evaluate_exp_tree(sqp_col->sql_tree);
            sqp_col->aggregator = sql_get_aggregator(sqp_col->agg_fn, 
                                                 sql_dtype_get_type (sqp_col->computed_value));
            assert(sqp_col->aggregator);
            sql_column_value_aggregate(sqp_col, sqp_col->computed_value);
            sql_destroy_Dtype_value_holder(sqp_col->computed_value);
            sqp_col->computed_value = NULL;
        }
        else
        {
            computed_value = sql_evaluate_exp_tree(sqp_col->sql_tree);
            sql_column_value_aggregate(sqp_col, computed_value);
            sql_destroy_Dtype_value_holder(computed_value);
        }
    }

 }


void 
sql_group_by_clause_process_grouped_records_phase2 (qep_struct_t *qep) {

    int i;
    bool ht_itr;
    qp_col_t *sqp_col;
    struct hashtable_itr *itr;
    joined_row_t *first_record;
    joined_row_t *  joined_row_backup;
    int row_no = 0, qualified_row_no = 0;
    std::list<joined_row_t *> *record_lst;
    ht_group_by_record_t *ht_group_by_record;

    if (!qep->groupby.ht) return;

    itr = hashtable_iterator(qep->groupby.ht);

    /* Thank you qep->joined_row_tmplate ! Now you are not needed any more.
        We will rejuvenate you to point to joined rows stored in HT now !*/
    joined_row_backup = qep->joined_row_tmplate;
    qep->joined_row_tmplate = NULL;

    ht_itr = true;

    do {

        ht_group_by_record = (ht_group_by_record_t *)hashtable_iterator_value (itr);
        record_lst = ht_group_by_record->record_lst;
        row_no++;
        first_record = NULL;
        
        if (row_no == 1 && 
                qep->orderby.column_name[0] == '\0') {

            sql_print_hdr(qep, qep->select.sel_colmns, qep->select.n);
        }

        for (std::list<joined_row_t *>::iterator it = record_lst->begin(); 
                it != record_lst->end(); 
                ++it) {

            qep->joined_row_tmplate = *it;
            if (!first_record) first_record = *it;
            sql_group_by_compute_aggregation (qep);
        }

        qep->joined_row_tmplate = first_record;

        /* Compute non-aggregated columns in select list*/
        for (i = 0; i < qep->select.n; i++) {

            sqp_col = qep->select.sel_colmns[i];
            if (sqp_col->agg_fn != SQL_AGG_FN_NONE) continue;
            assert (!sqp_col->computed_value);
            sqp_col->computed_value =  sql_evaluate_exp_tree (sqp_col->sql_tree);
        }

        if (row_no == 1) {

            /* We have computed the first Aggregated record data, its time to resolve and
                initialize HAVING exp tree phase 2. We initialize this exp tree dynamically
                (i.e. while we are in join loop) because the  data type of aggregated select columns
                Would be known only after computation of Ist Aggrgated record */

            if (!sql_query_initialize_having_clause_phase2 (qep)) {
                printf ("Error : Failed to initialize HAVING clause phase 2 Exp tree\n");
                break;
            }
        }
    
        if (!sql_evaluate_conditional_exp_tree (qep->having.gexptree_phase2)) {

            sql_select_flush_computed_values (qep);
            if (hashtable_iterator_advance(itr)) continue;
            break;
        }

        /* Order by*/
        if (!qep_collect_dtypes_for_sorting(qep)) {

            sql_emit_select_output(qep, qep->select.n, qep->select.sel_colmns);
            sql_select_flush_computed_values (qep);
            qualified_row_no++;
            if (qep->limit == qualified_row_no) {
                break;
            }
        }

        ht_itr = !(hashtable_iterator_advance(itr) == 0);
    } while (ht_itr);

    free(itr);

    /* Implementing Order by Sorting*/
    qep_orderby_sort (qep);
    qep->orderby.iterator_index = 0;
    while (qep_order_by_reassign_select_columns (qep)) {
        if ( qep->orderby.iterator_index == 1) {
            sql_print_hdr(qep, qep->select.sel_colmns, qep->select.n);
        }
        sql_emit_select_output(qep, qep->select.n, qep->select.sel_colmns);
        sql_select_flush_computed_values (qep);
        qualified_row_no++;
        if (qep->limit == qep->orderby.iterator_index) {
            break;
        }
    }

    printf ("(%d rows)\n", qualified_row_no);
    qep->joined_row_tmplate = joined_row_backup;
}


