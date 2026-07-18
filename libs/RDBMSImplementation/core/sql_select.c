#include <stdbool.h>
#include <stdlib.h>
#include <memory.h>
#include "rdbms_struct.h"
#include "qep.h"
#include "../BPlusTreeLib/BPlusTree.h"
#include "../../MathExpressionParser/Dtype.h"
#include "SqlMexprIntf.h"
#include "Catalog.h"
#include "sql_utils.h"
#include "sql_where.h"
#include "sql_group_by.h"
#include "sql_order_by.h"
#include "sql_io.h"
#include "sql_join.h"
#include "sql_name.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

bool 
qep_resolve_select_asterisk (qep_struct_t *qep) {

    int i, j;
    qp_col_t *qp_col;    
    ctable_val_t *ctable_val;
    char opnd_name[SQL_FQCN_SIZE];

    if (qep->select.n ) return true;

    for (i = 0; i < qep->join.table_cnt; i++) {

        ctable_val = qep->join.tables[i].ctable_val;
        j = 0;

        while (ctable_val->column_lst[j][0] != '\0') {

            qp_col = (qp_col_t *)calloc (1, sizeof (qp_col_t));
            qp_col->agg_fn = SQL_AGG_FN_NONE;
            qp_col->alias_name[0] = '\0';
            qp_col->alias_provided_by_user = false;
            /* Will allocate at the time of computation in select query*/
            qp_col->computed_value = NULL;
            memset(opnd_name, 0, sizeof(opnd_name));
            snprintf(opnd_name, sizeof(opnd_name), "%s.%s",
                     ctable_val->table_name, ctable_val->column_lst[j]);
            qp_col->sql_tree = sql_create_exp_tree_for_one_operand(opnd_name);
            strncpy(qp_col->alias_name, opnd_name, sizeof(qp_col->alias_name));
            qep->select.sel_colmns[qep->select.n++] = qp_col;
            j++;
        }
    }

    return true;
 }

bool
sql_query_initialize_select_column_list (qep_struct_t *qep, catalog_t *tcatalog) {

    int i;
    qp_col_t *qp_col;
    char table_name_out [SQL_TABLE_NAME_MAX_SIZE];
    char lone_col_name [SQL_COLUMN_NAME_MAX_SIZE];

    if (qep->select.n == 0) {

        /* Expand * (asterisk) here */
        if (!qep_resolve_select_asterisk (qep)) {

            printf ("Error : Failed to resolve asterisk\n");
            return false;
        }
    }
    else {
        /* Fix up the alias name. For those qp_cols whose alias were not
            specified by the user, if those are single operand node, then take
            variable name as alias name*/
            for (i = 0; i < qep->select.n; i++) {

                qp_col = qep->select.sel_colmns[i];
                if (sql_is_single_operand_expression_tree (qp_col->sql_tree)
                        && qp_col->alias_name[0] == '\0') {

                    sql_get_column_table_names ( qep, QP_COL_NAME(qp_col),
                            table_name_out, lone_col_name);

                    snprintf (qp_col->alias_name,  sizeof (qp_col->alias_name),
                        "%s.%s",  table_name_out, lone_col_name);
                }
            }
    }

    /* Now Resolve Expressression Trees for all select columns*/
    for (i = 0; i < qep->select.n; i++) {

        sql_tree_expand_all_aliases (qep, qep->select.sel_colmns[i]->sql_tree);
        sql_tree_operand_names_to_fqcn (qep, qep->select.sel_colmns[i]->sql_tree);

        if (!sql_resolve_exptree (tcatalog, 
                                                qep->select.sel_colmns[i]->sql_tree,
                                                qep, &qep->joined_row_tmplate)) {
            
            printf ("Error : Failed to resolve Expression Tree for select column %s\n", 
                        qep->select.sel_colmns[i]->alias_name);
            return false;
        }
    }

    return true;
}


void 
sql_process_select_query (qep_struct_t *qep) {

    int i;
    int row_no = 0;
    qp_col_t *qp_col;
    Dtype *computed_value;
    int  qualified_row_no = 0;
    bool is_aggregation = false;

    while (qep_execute_join (qep)) {

        /* Optimization : If only one table is involved, no need to evaluate join-predicate*/
        if (qep->join.table_cnt > 1 &&
                !qep_execute_join_predicate(qep, qep->joined_row_tmplate)) {
            continue;
        }

        row_no++;

         /* Time for Grouping */

        /* Check if the query has group by clause */
        if (qep->groupby.n) {

            sql_group_by_clause_group_records_phase1 (qep);
            continue;
        }

        for (i = 0; i < qep->select.n; i++) {

            qp_col = qep->select.sel_colmns[i];

            if (qp_col->agg_fn == SQL_AGG_FN_NONE) {
                
                /* Flush the old result*/
                if (qp_col->computed_value ) {
                     sql_destroy_Dtype_value_holder (qp_col->computed_value);
                     qp_col->computed_value = NULL;
                }
                qp_col->computed_value = sql_evaluate_exp_tree (qp_col->sql_tree);
            }
            else {
                /* Process Agg fn*/

                is_aggregation = true;

                if (!qp_col->aggregator) {
                    qp_col->computed_value =  sql_evaluate_exp_tree (qp_col->sql_tree);
                    
                    qp_col->aggregator = sql_get_aggregator (
                            qp_col->agg_fn,
                            sql_dtype_get_type (qp_col->computed_value));

                    assert (qp_col->aggregator);
                    sql_column_value_aggregate  (qp_col,  qp_col->computed_value);
                    sql_destroy_Dtype_value_holder (qp_col->computed_value);
                    qp_col->computed_value = NULL;
                }
                else {
                    computed_value = sql_evaluate_exp_tree (qp_col->sql_tree);
                    sql_column_value_aggregate  (qp_col, computed_value);
                    sql_destroy_Dtype_value_holder (computed_value);
                }
                
            }
        }

        /* Output  */
        /* Case 1 :  No Group by Clause, Non-Aggregated Columns */
        if (!qep->groupby.n && !is_aggregation) {

            if (qep_collect_dtypes_for_sorting(qep)) continue;

            if (row_no == 1) {
                sql_print_hdr  (qep, qep->select.sel_colmns, qep->select.n);
            }

            sql_emit_select_output (qep, qep->select.n, qep->select.sel_colmns);

            if (qep->limit == row_no) {
                break;
            }
        }
    }  /* While ends */


    /* Handling group by Phase 2*/
    if (qep->groupby.n) {

        sql_group_by_clause_process_grouped_records_phase2 (qep); 
        return;
    }

    /* Case 2 :  No Group by Clause,  Aggregated Columns */
    if (!qep->groupby.n && is_aggregation) {

        sql_print_hdr(qep, qep->select.sel_colmns, qep->select.n);
        sql_emit_select_output(qep, qep->select.n, qep->select.sel_colmns);
        printf ("(1 rows)\n");
        return;
    }

    /* Order by*/
    qep_orderby_sort (qep);
    qep->orderby.iterator_index = 0;
    while (qep_order_by_reassign_select_columns (qep)) {

        if ( qep->orderby.iterator_index == 1) {
            sql_print_hdr(qep, qep->select.sel_colmns, qep->select.n);
        }
        sql_emit_select_output(qep, qep->select.n, qep->select.sel_colmns);
        sql_select_flush_computed_values (qep);
        if (qep->limit == qep->orderby.iterator_index) {
            break;
        }
    }
    printf ("(%d rows)\n", row_no);
}