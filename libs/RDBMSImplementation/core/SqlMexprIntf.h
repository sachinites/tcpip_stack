#ifndef __SQL_MEXPR_INTF__
#define __SQL_MEXPR_INTF__

#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <list>
#include "../SqlParser/SqlEnums.h"
#include "../../MathExpressionParser/MExprcppEnums.h"

typedef struct mexpr_parser_ mexpr_parser_t;

class MexprTree;
class Dtype;
class MexprNode;
class Aggregator;

typedef struct catalog_table_value ctable_val_t;
typedef struct catalog_ catalog_t ;
typedef struct joined_row_ joined_row_t;
typedef struct qep_struct_ qep_struct_t;
typedef struct qp_col_ qp_col_t;
typedef struct exp_tree_data_src_ exp_tree_data_src_t ;

typedef struct sql_exptree_ {

    MexprTree *tree;

} sql_exptree_t;

sql_exptree_t *
sql_create_exp_tree_compute (mexpr_parser_t *parser) ;

sql_exptree_t *
sql_create_exp_tree_conditional (mexpr_parser_t *parser) ;

bool 
sql_resolve_exptree (catalog_t *tcatalog,
                                  sql_exptree_t *sql_exptree,
                                  qep_struct_t *qep,
                                  joined_row_t **joined_row) ;

bool 
sql_resolve_exptree_against_table (qep_struct_t *qep,
                                                         catalog_t *tcatalog,
                                                         sql_exptree_t *sql_exptree, 
                                                         ctable_val_t * ctable_val, 
                                                         int table_id, joined_row_t **joined_row,
                                                         std::list<exp_tree_data_src_t *> *data_src_lst);
                                                         
bool 
sql_evaluate_conditional_exp_tree (sql_exptree_t *sql_exptree);

Dtype *
sql_evaluate_exp_tree (sql_exptree_t *sql_exptree);

sql_exptree_t *
sql_create_exp_tree_for_one_operand (char * opnd_name) ;

bool 
sql_is_single_operand_expression_tree (sql_exptree_t *sql_exptree);

bool 
sql_opnd_node_is_resolved (MexprNode *opnd_node);

bool 
sql_opnd_node_is_unresolvable (MexprNode *opnd_node) ;

void 
sql_opnd_node_mark_unresolvable (MexprNode *opnd_node) ;

uint8_t 
 sql_tree_remove_unresolve_operands(sql_exptree_t *sql_exptree);

std::string 
sql_get_opnd_variable_name (MexprNode *opnd_node);

sql_exptree_t *
sql_clone_expression_tree  (sql_exptree_t *src_tree);

bool 
sql_concatenate_expr_trees (sql_exptree_t *parent_tree, 
                                                MexprNode *opnd_node,
                                                sql_exptree_t *child_tree);

void 
sql_destroy_exp_tree (sql_exptree_t *tree);

MexprNode *
sql_tree_get_first_operand (sql_exptree_t *tree);

MexprNode *
sql_tree_get_next_operand (MexprNode *node);

#define SqlExprTree_Iterator_Operands_Begin(tree_ptr, node_ptr) \
    for (node_ptr = sql_tree_get_first_operand(tree_ptr) ;  \
            node_ptr;   \
            node_ptr = sql_tree_get_next_operand (node_ptr))

MexprNode *
sql_tree_get_root (sql_exptree_t *tree) ;

bool 
sql_tree_validate (sql_exptree_t *tree);

bool 
sql_tree_optimize (sql_exptree_t *tree);

void 
InstallDtypeOperandProperties (MexprNode *node, 
                                                    sql_dtype_t sql_dtype,
                                                    void *data_src, Dtype *(*compute_fn_ptr)(void *)) ;

mexprcpp_dtypes_t
sql_to_mexpr_dtype_converter (sql_dtype_t sql_dtype) ;

mexprcpp_agg_t 
sql_to_mexpr_agg_fn_converter (sql_agg_fn_t agg_fn) ;

Aggregator *
sql_get_aggregator (sql_agg_fn_t agg_fn, sql_dtype_t dtype);

void
sql_destroy_aggregator (qp_col_t *qp_col) ;

void 
sql_column_value_aggregate (qp_col_t *qp_col, Dtype *new_value);

void
sql_column_set_aggregated_value (qp_col_t *qp_col, Dtype *new_value) ;

int 
sql_dtype_serialize (Dtype *dtype, void *mem);

int
sql_tree_expand_all_aliases (qep_struct_t *qep, sql_exptree_t *sql_tree);

sql_dtype_t
mexpr_to_sql_dtype_converter (mexprcpp_dtypes_t dtype) ;

mexprcpp_agg_t 
sql_to_mexpr_agg_fn_converter (sql_agg_fn_t agg_fn);

mexprcpp_dtypes_t
sql_to_mexpr_dtype_converter (sql_dtype_t sql_dtype);

void 
sql_tree_operand_names_to_fqcn (qep_struct_t *qep, sql_exptree_t *sql_tree);

/* Dtype */
Dtype *
sql_column_get_aggregated_value (qp_col_t *qp_col) ;

void 
sql_destroy_Dtype_value_holder (Dtype *dtype);

sql_dtype_t
sql_dtype_get_type (Dtype *dtype ) ;

typedef struct dtype_value_ {

    sql_dtype_t dtype;

    union {
        int int_val;
        double d_val;
        bool b_val;
        const char *str_val;
        struct {
            const char *ipv4_addr_str;
            uint32_t ipv4_addr_int;
        } ipv4;
        struct {
            int lb;
            int ub;
            const char *interval_str;
        } interval;
    } u;
    
} dtype_value_t;

dtype_value_t 
DTYPE_GET_VAUE(Dtype *dtype) ;

Dtype *
Dtype_copy (Dtype *dtype) ;

bool 
Dtype_less_than_operator (Dtype *dtype1, Dtype *dtype2) ;

#endif 
