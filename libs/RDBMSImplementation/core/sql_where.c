#include "sql_where.h"
#include "qep.h"
#include "rdbms_struct.h"
#include "SqlMexprIntf.h"

bool
qep_execute_join_predicate (qep_struct_t *qep_struct, joined_row_t *joined_row) {

   if (!qep_struct->where.gexptree) return true;
   return sql_evaluate_conditional_exp_tree (qep_struct->where.gexptree);
}

bool
sql_query_initialize_where_clause (qep_struct_t *qep, catalog_t *tcatalog) {

    int i;

    if (!qep->where.gexptree) return true;

    /* Initializing Where Clause
        Initializing Where clause in 3 steps :
        1. Check for operands in the where.gexptree, and if the operand is an Alias of columns specified in 
            select clause. Replace these operand nodes with select expression trees for that operand.
        2. Clone and Resolve where.gexptree to per-table expression trees for each table in join table list
        3. Resolve where.gexptree against all join tables put together
    */

    sql_tree_expand_all_aliases (qep, qep->where.gexptree);
    sql_tree_operand_names_to_fqcn (qep, qep->where.gexptree);

    for (i = 0; i < qep->join.table_cnt; i++) {

        qep->where.exptree_per_table[i] = sql_clone_expression_tree(qep->where.gexptree);

        if (!qep->where.exptree_per_table[i]) {

            printf("Error : Failed to create Exp Tree Clones of Where Clause\n");
            return false;
        }

        if (!sql_resolve_exptree_against_table(
                        qep,
                        tcatalog,
                        qep->where.exptree_per_table[i],
                        qep->join.tables[i].ctable_val, i, 
                        &qep->joined_row_tmplate,
                        qep->data_src_lst)) {

            printf("Error : Failed to resolve per table Where Expression Tree\n");
            return false;
        }
    }


    if (!sql_resolve_exptree(tcatalog,
                             qep->where.gexptree,
                             qep, &qep->joined_row_tmplate)) {

        printf("Error : Failed to resolve Global Where Expression Tree\n");
        return false;
    }

    return true;
}