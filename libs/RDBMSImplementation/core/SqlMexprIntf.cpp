#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <list>
#include <string>
#include <arpa/inet.h>
#include "Catalog.h"
#include "sql_utils.h"
#include "SqlMexprIntf.h"
#include "../SqlParser/ParserExport.h"
#include "../../MathExpressionParser/Dtype.h"
#include "../../MathExpressionParser/Aggregators.h"
#include "qep.h"
#include "sql_name.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

/* Imports from ExpressionParser (libMexpr) */
parse_rc_t S (mexpr_parser_t *p); 
parse_rc_t Q (mexpr_parser_t *p); 
parse_rc_t E (mexpr_parser_t *p);  

extern lex_data_t **
mexpr_convert_infix_to_postfix (lex_data_t *infix, int sizein, int *size_out) ;

static void
postfix_lex_data_array_destroy (lex_data_t **postfix, int size) {
    
    int i;

    for (i = 0; i < size; i++) {

        /* postfix array may have holes !*/
        if (!postfix[i]) continue;

        switch (postfix[i]->token_code) {

            case MATH_CPP_STRING_LST: 
            {
                std::list<std::string *> *str_lst_ptr =
                    reinterpret_cast<std::list<std::string *> *>(postfix[i]->token_val);

                for (std::list<std::string *>::iterator it = str_lst_ptr->begin();
                    it != str_lst_ptr->end(); ++it) {
                    delete *it;
                }
                delete str_lst_ptr;
            }
            break;
            case MATH_CPP_INTERVAL:
            {
                std::list<int32_t> *int_lst_ptr = 
                     reinterpret_cast<std::list<int32_t > *>(postfix[i]->token_val);
                delete int_lst_ptr;
            }
            break;
            default:
            break;
        }

        free(postfix[i]);
    }
    free(postfix);
}

static MexprTree *
Parser_Mexpr_build_math_expression_tree (mexpr_parser_t *parser) {

    int i;
    std::string *string_ptr;
    MexprTree *tree = NULL; 

    int stack_chkp = parser->undo_stack.top + 1;

    parse_rc_t err = E(parser);

    if (err == PARSE_ERR) {
        return NULL;
    }

    int size_out = 0;
    lex_data_t **postfix = mexpr_convert_infix_to_postfix (
                                            &parser->undo_stack.data[stack_chkp], parser->undo_stack.top + 1 - stack_chkp, &size_out);
    
   tree = new MexprTree (postfix, size_out);
    postfix_lex_data_array_destroy (postfix, size_out);
    return tree; 
}


static MexprTree *
Parser_Mexpr_Condition_build_expression_tree (mexpr_parser_t *parser) {

    int i;
    MexprTree *tree = NULL; 

    int stack_chkp = parser->undo_stack.top + 1;

    parse_rc_t err = S(parser);

    do {

        if (err == PARSE_SUCCESS) break;
        err = Q(parser);
        if (err == PARSE_ERR) return NULL;

    } while (0);

    int size_out = 0;
    lex_data_t **postfix = mexpr_convert_infix_to_postfix (
                                            &parser->undo_stack.data[stack_chkp], parser->undo_stack.top + 1 - stack_chkp, &size_out);

    tree = new MexprTree(postfix, size_out);
    postfix_lex_data_array_destroy (postfix, size_out);
    return tree;
}

sql_exptree_t *
sql_create_exp_tree_compute (mexpr_parser_t *parser)  {

    sql_exptree_t *sql_exptree = (sql_exptree_t *) calloc (1, sizeof (sql_exptree_t ));
    sql_exptree->tree = Parser_Mexpr_build_math_expression_tree (parser);

    if (!sql_exptree->tree) {
        //printf ("Info : %s(%d) Expression Parsing Failed\n",   __FUNCTION__, __LINE__);
        free (sql_exptree) ;
        return NULL;
    }

    if (!sql_exptree->tree->validate(sql_exptree->tree->root)) {
        printf ("Error : %s(%d) Expression Tree doesnt pass Validation test\n", 
                __FUNCTION__, __LINE__);
        sql_exptree->tree->destroy(sql_exptree->tree->root);
        free (sql_exptree) ;
         return NULL;
    }

    sql_exptree->tree->optimize(sql_exptree->tree->root);
    return sql_exptree;
}

sql_exptree_t *
sql_create_exp_tree_conditional (mexpr_parser_t *parser) {

    sql_exptree_t *sql_exptree = (sql_exptree_t *) calloc (1, sizeof (sql_exptree_t ));
    sql_exptree->tree = Parser_Mexpr_Condition_build_expression_tree (parser);

    if (!sql_exptree->tree) {
        free (sql_exptree) ;
        return NULL;
    }
    if (!sql_exptree->tree->validate(sql_exptree->tree->root)) {
        printf ("Error : %s(%d) Expression Tree doesnt pass Validation test\n", 
                __FUNCTION__, __LINE__);
        sql_exptree->tree->destroy(sql_exptree->tree->root);
        free (sql_exptree) ;
         return NULL;
    }
    sql_exptree->tree->optimize(sql_exptree->tree->root);
    return sql_exptree;
}

static Dtype *
sql_column_value_resolution_fn (void *_data_src) {

    Dtype *dtype = NULL;

    exp_tree_data_src_t *data_src = (exp_tree_data_src_t *)_data_src;

    void *rec = (*data_src->joined_row)->rec_array[data_src->table_index];

    if (!rec) return NULL;

    void *val = (void *)((char *)rec + data_src->schema_rec->offset);

    switch (data_src->schema_rec->dtype) {
        
        case  SQL_STRING:
        {
            dtype =  Dtype::factory (MATH_CPP_STRING);
            Dtype_STRING *dtype_str = dynamic_cast <Dtype_STRING *> (dtype);
            dtype_str->dtype.str_val = std::string ((char *)val);
            dtype->is_resolved = true;
        }
        break;

        case SQL_INT:
        {
            dtype =  Dtype::factory (MATH_CPP_INT);
            Dtype_INT *dtype_int = dynamic_cast <Dtype_INT *> (dtype);
            dtype_int->dtype.int_val = *(int *)val;
            dtype->is_resolved = true;
        }
        break;

        case SQL_DOUBLE:
        {
            dtype =  Dtype::factory (MATH_CPP_DOUBLE);
            Dtype_DOUBLE *dtype_d = dynamic_cast <Dtype_DOUBLE *> (dtype);
            dtype_d->dtype.d_val = *(double *)val;
            dtype->is_resolved = true;
        }
        break;        

        case SQL_IPV4_ADDR:
        {
            char ipv4_str[16];
            dtype =  Dtype::factory (MATH_CPP_IPV4);
            Dtype_IPv4_addr *dtype_v4 = dynamic_cast <Dtype_IPv4_addr *> (dtype);
            dtype_v4->dtype.ipaddr_int= *(uint32_t *)val;
            inet_ntop ( AF_INET, &dtype_v4->dtype.ipaddr_int, ipv4_str, 16);
            dtype_v4->dtype.ip_addr_str = std::string (ipv4_str);
            dtype->is_resolved = true;
        }
        break;

        case SQL_INTERVAL:
        {
            dtype =  Dtype::factory (MATH_CPP_INTERVAL);
            Dtype_INTERVAL *dtype_ival = dynamic_cast <Dtype_INTERVAL *> (dtype);
            dtype_ival->dtype.lb = *(int *)val;
            dtype_ival->dtype.ub = *((int *)val + 1 );
            dtype->is_resolved = true;
        }
        break;

        default:
            assert(0);
    }
    return dtype;
}



/* Return true if all operands are resolved successfully,
    return false if atleast one operand is unresolved*/
bool 
sql_resolve_exptree (catalog_t *tcatalog,
                                  sql_exptree_t *sql_exptree,
                                  qep_struct_t *qep,
                                  joined_row_t **joined_row) {
    /* Algorithm : 
    1. Iterate over the operands opnd of the exptree
    2.  If opnd name is one word 'col_name', then resolve it against table_arr[0] only. Index = 0.
    3. if opnd_name is table_name.col_name then split 'table_name' and 'col_name'. 
            3.1 lookup table_name in tcatalog and get ctable_val_t *
            3.2 Now resolve 'col_name' against this found  'ctable_val_t *' only. Index = matching index in ctable_val_t ** array.
    4. lookup the schema_rec_t in  ctable_val_t -> schema_table using col_name as a key
    5. Prepare exp_tree_data_src_t object
            exp_tree_data_src_t *data_src = malloc () ..  
            data_src->table_index = Index;
            data_src->schema_rec = schema_rec; 
            data_src->joined_row = joined_row

    6. mexpt_tree_install_operand_properties (opnd_tree_node, <to be removed>, joined_row_t *, sql_column_value_resolution_fn);
    7. Any Column which could not be resolved should be removed from Exp Tree using API 
    mexpt_remove_unresolved_operands ( ) followed by mexpt_optimize( )
    */
   
    int tindex = 0, i;
    BPluskey_t bpkey;
    MexprNode *node;
    ctable_val_t *ctable_val;
    schema_rec_t *schema_rec = NULL;
    exp_tree_data_src_t *data_src = NULL;
    char table_name_out [SQL_TABLE_NAME_MAX_SIZE];
    char lone_col_name [SQL_COLUMN_NAME_MAX_SIZE];

   MexprTree_Iterator_Operands_Begin (sql_exptree->tree, node) {

        if (sql_opnd_node_is_resolved (node)) continue;
        if (sql_opnd_node_is_unresolvable (node)) continue;
        
        sql_get_column_table_names (qep, 
                    (char *)sql_get_opnd_variable_name(node).c_str(), 
                    table_name_out,
                    lone_col_name);

        assert (table_name_out[0] != '\0');

        tindex = sql_get_qep_table_index  (qep, table_name_out);

        if (tindex < 0) {
            printf("Error : %s(%d) Table %s does not exit\n", 
                __FUNCTION__, __LINE__, table_name_out);
            return false;
        }

        ctable_val = qep->join.tables[tindex].ctable_val;

        bpkey.key = lone_col_name;
        bpkey.key_size = SQL_COLUMN_NAME_MAX_SIZE;
        schema_rec = (schema_rec_t *)rdbms_ds_query(ctable_val->schema_table, &bpkey);

        if (!schema_rec) {
            printf("Error : %s(%d) : Column %s could not be found in table %s\n", 
                __FUNCTION__, __LINE__,
                sql_get_opnd_variable_name(node).c_str(), ctable_val->table_name);
            return false;
        }
        
        data_src = (exp_tree_data_src_t *)calloc(1, sizeof(exp_tree_data_src_t)); 
        qep->data_src_lst->push_back (data_src);
        data_src->table_index = tindex;
        data_src->schema_rec = schema_rec;
        data_src->joined_row = joined_row;
        InstallDtypeOperandProperties (node, schema_rec->dtype,
                        data_src, sql_column_value_resolution_fn);
    
   } MexprTree_Iterator_Operands_End;

   assert (sql_exptree->tree->validate(sql_exptree->tree->root));
   sql_exptree->tree->optimize (sql_exptree->tree->root);
   return true;
}

bool 
sql_resolve_exptree_against_table ( qep_struct_t *qep,
                                                           catalog_t *tcatalog,
                                                           sql_exptree_t *sql_exptree, 
                                                           ctable_val_t *ctable_val, 
                                                           int table_id, 
                                                           joined_row_t **joined_row,
                                                           std::list<exp_tree_data_src_t *> *data_src_lst) {

    BPluskey_t bpkey;
    MexprNode *node;
    schema_rec_t *schema_rec = NULL;
    exp_tree_data_src_t *data_src = NULL;
    Dtype_VARIABLE *opnd_var = NULL;
    char table_name_out [SQL_TABLE_NAME_MAX_SIZE];
    char lone_col_name [SQL_COLUMN_NAME_MAX_SIZE];

   MexprTree_Iterator_Operands_Begin (sql_exptree->tree, node) {

        opnd_var = dynamic_cast <Dtype_VARIABLE *> (node);

        if (sql_opnd_node_is_resolved (opnd_var)) continue;
        if (sql_opnd_node_is_unresolvable (opnd_var)) continue;

        sql_get_column_table_names (qep, 
                    (char *)sql_get_opnd_variable_name(node).c_str(), 
                    table_name_out,
                    lone_col_name);

        if (strncmp((const char *)table_name_out,
                    (const char *)ctable_val->table_name,
                    SQL_TABLE_NAME_MAX_SIZE)) {
            continue;
        }
        
        bpkey.key = lone_col_name;
        bpkey.key_size = SQL_COLUMN_NAME_MAX_SIZE;
        schema_rec = (schema_rec_t *)rdbms_ds_query(ctable_val->schema_table, &bpkey);

        if (!schema_rec) {
                printf("Info (%s) : Operand %s could not be resolved against table %s\n", 
                        __FUNCTION__,
                        opnd_var->dtype.variable_name.c_str(), ctable_val->table_name);
                continue;
        }
        data_src = (exp_tree_data_src_t *)calloc(1, sizeof(exp_tree_data_src_t));
        data_src_lst->push_back(data_src);
        data_src->table_index = table_id,
        data_src->schema_rec = schema_rec;
        data_src->joined_row = joined_row;
        opnd_var->ResolveOperand (
                        sql_to_mexpr_dtype_converter (schema_rec->dtype), 
                        data_src,
                        sql_column_value_resolution_fn);

   } MexprTree_Iterator_Operands_End;

   sql_exptree->tree->RemoveUnresolveOperands();
   assert (sql_exptree->tree->validate(sql_exptree->tree->root));
   sql_exptree->tree->optimize (sql_exptree->tree->root);
   return true;
}

void 
sql_tree_operand_names_to_fqcn (qep_struct_t *qep, sql_exptree_t *sql_tree) {

    char *old_name;
    MexprNode *node;
    Dtype_VARIABLE *dvar;
    char new_name [SQL_FQCN_SIZE];
    char table_name[SQL_TABLE_NAME_MAX_SIZE];
    char column_name[SQL_COLUMN_NAME_MAX_SIZE];

     MexprTree_Iterator_Operands_Begin (sql_tree->tree, node) {

        dvar = dynamic_cast<Dtype_VARIABLE *> (node); 
        old_name = (char *)dvar->dtype.variable_name.c_str();
        memset (new_name, 0, sizeof (new_name));
        memset (table_name, 0, sizeof (table_name));
        memset (column_name, 0, sizeof (column_name));
        sql_get_column_table_names (qep, old_name, table_name, column_name);
        snprintf (new_name, sizeof(new_name), "%s.%s", table_name, column_name);
        dvar->dtype.variable_name.assign(std::string(new_name));

     } MexprTree_Iterator_Operands_End;
}


bool 
sql_evaluate_conditional_exp_tree (sql_exptree_t *sql_exptree) {

    bool rc;
    Dtype *res;
    Dtype_BOOL *d_bool;

    if (!sql_exptree) return true;
    res = sql_exptree->tree->evaluate (sql_exptree->tree->root);
    d_bool = dynamic_cast <Dtype_BOOL *> (res);
    rc = d_bool->dtype.b_val;
    delete d_bool;
    return rc;
}

Dtype *
sql_evaluate_exp_tree (sql_exptree_t *sql_exptree) {

    return sql_exptree->tree->evaluate (sql_exptree->tree->root);
}

sql_exptree_t *
sql_create_exp_tree_for_one_operand (char *opnd_name) {

    Dtype_VARIABLE *dtype_var = new Dtype_VARIABLE(std::string (opnd_name));
    dtype_var->is_resolved = false;
    sql_exptree_t *sql_exptree = (sql_exptree_t *)calloc(1, sizeof(sql_exptree_t));
    sql_exptree->tree = new MexprTree();
    sql_exptree->tree->root = dtype_var;
    sql_exptree->tree->lst_head = sql_exptree->tree->root;
    return sql_exptree;
}

bool 
sql_opnd_node_is_resolved (MexprNode *opnd_node) {

    Dtype *dtype = dynamic_cast <Dtype *> (opnd_node);
    return dtype->is_resolved;
}

bool 
sql_opnd_node_is_unresolvable (MexprNode *opnd_node) {

    Dtype *dtype = dynamic_cast <Dtype *> (opnd_node);
    return dtype->unresolvable;
}

void 
sql_opnd_node_mark_unresolvable (MexprNode *opnd_node) {

    Dtype *dtype = dynamic_cast <Dtype *> (opnd_node);
    dtype->unresolvable = true;
}

std::string 
sql_get_opnd_variable_name (MexprNode *opnd_node) {

    Dtype_VARIABLE *dtype = dynamic_cast <Dtype_VARIABLE *> (opnd_node);
    return dtype->dtype.variable_name;
}

sql_exptree_t *
sql_clone_expression_tree (sql_exptree_t *src_tree) {

    if (!src_tree) return NULL;
    sql_exptree_t * sql_exptree = (sql_exptree_t *) calloc (1, sizeof (sql_exptree_t));
    if (src_tree->tree == NULL) return sql_exptree;
    sql_exptree->tree = src_tree->tree->clone(src_tree->tree->root);
    return sql_exptree;
}

bool 
sql_concatenate_expr_trees (sql_exptree_t *parent_tree, 
                                                MexprNode *opnd_node,
                                                sql_exptree_t *child_tree) {

    bool rc = parent_tree->tree->concatenate (opnd_node, child_tree->tree);
    free (child_tree);
    return rc;
}

void 
sql_destroy_exp_tree (sql_exptree_t *tree) {

    tree->tree->destroy(tree->tree->root);
    free(tree);
}

MexprNode *
sql_tree_get_first_operand (sql_exptree_t *tree) {

    if (!tree->tree) return NULL;
    return tree->tree->lst_head;
}

MexprNode *
sql_tree_get_next_operand (MexprNode *node) {

    if (!node) return node;
    assert (dynamic_cast <Dtype_VARIABLE *> (node) ); 
    return node->lst_right;
}

bool 
sql_is_single_operand_expression_tree (sql_exptree_t *sql_exptree) {

    return sql_exptree->tree->IsLoneVariableOperandNode();
}

MexprNode *
sql_tree_get_root (sql_exptree_t *tree) {
    
    if (!tree->tree || !tree->tree->root) return NULL;
    return tree->tree->root;
}

uint8_t  
sql_tree_remove_unresolve_operands(sql_exptree_t *sql_exptree) {

    if (!sql_exptree || !sql_exptree->tree) return 0;
    return sql_exptree->tree->RemoveUnresolveOperands();
}

void 
sql_destroy_Dtype_value_holder (Dtype *dtype) {

    delete dtype;
}

Aggregator *
sql_get_aggregator (sql_agg_fn_t agg_fn, sql_dtype_t dtype) {

    if (agg_fn == SQL_AGG_FN_NONE) return NULL;
    
    Aggregator *aggregator = Aggregator::factory (
                    sql_to_mexpr_agg_fn_converter (agg_fn),  // which agg fn we need
                    sql_to_mexpr_dtype_converter(dtype)); // what is the data type to aggregate
    
    return aggregator;
}

void
sql_destroy_aggregator (qp_col_t *qp_col) {

    delete qp_col->aggregator;
    qp_col->aggregator = NULL;
}

void 
sql_column_value_aggregate (qp_col_t *qp_col, Dtype *new_value) {

    qp_col->aggregator->aggregate (new_value);
}

Dtype *
sql_column_get_aggregated_value (qp_col_t *qp_col) {

    return qp_col->aggregator->getAggregatedValue();
}

sql_dtype_t
sql_dtype_get_type (Dtype *dtype ) {

    return mexpr_to_sql_dtype_converter(dtype->did);
}

void
sql_column_set_aggregated_value (qp_col_t *qp_col, Dtype *new_value) {

    qp_col->aggregator->aggregator = new_value;
}


bool 
sql_tree_validate (sql_exptree_t *tree) {

    return tree->tree->validate (tree->tree->root);
}

bool 
sql_tree_optimize (sql_exptree_t *tree) {

    return tree->tree->optimize (tree->tree->root);
}

int 
sql_dtype_serialize (Dtype *dtype, void *mem) {

    return dtype->serialize (mem);
}

int
sql_tree_expand_all_aliases (qep_struct_t *qep, sql_exptree_t *sql_tree) {

    int count = 0;
    qp_col_t *sqp_col;
    std::string opnd_name;
    MexprNode *opnd_node;
    bool all_alias_expanded = false;

    while (!all_alias_expanded) {
        
        all_alias_expanded = true;

        SqlExprTree_Iterator_Operands_Begin (sql_tree, opnd_node) {

            if (sql_opnd_node_is_unresolvable (opnd_node)) continue;

            opnd_name = sql_get_opnd_variable_name (opnd_node);

            sqp_col = sql_get_qp_col_by_name (
                                             qep->select.sel_colmns,
                                             qep->select.n, 
                                             (char *)opnd_name.c_str(), true);

            if (!sqp_col ) continue;

            all_alias_expanded = false;

            sql_concatenate_expr_trees (sql_tree, 
                                                          opnd_node, 
                                                          sql_clone_expression_tree( sqp_col->sql_tree ));

            count++;
            break;
        }
    }
    return count;
}

void 
InstallDtypeOperandProperties (MexprNode *node, 
                                                    sql_dtype_t sql_dtype,
                                                    void *data_src, Dtype *(*compute_fn_ptr)(void *))  {

    Dtype_VARIABLE *dtype_var = 
                dynamic_cast <Dtype_VARIABLE *> (node);

    dtype_var->ResolveOperand (
                sql_to_mexpr_dtype_converter (sql_dtype), 
                data_src,
                compute_fn_ptr );

}

dtype_value_t 
DTYPE_GET_VAUE(Dtype *dtype)   {

    dtype_value_t  dtype_value;

    dtype_value.dtype = sql_dtype_get_type (dtype);

    switch (sql_dtype_get_type (dtype)) {

        case SQL_INT: 
           dtype_value.u.int_val =  (dynamic_cast <Dtype_INT *>(dtype))->dtype.int_val;
           break;

        case SQL_STRING:
            dtype_value.u.str_val = (dynamic_cast <Dtype_STRING *>(dtype))->dtype.str_val.c_str();
            break;

        case SQL_DOUBLE:
            dtype_value.u.d_val = (dynamic_cast <Dtype_DOUBLE *>(dtype))->dtype.d_val;
            break;

        case SQL_BOOL:
            dtype_value.u.b_val = (dynamic_cast <Dtype_BOOL *>(dtype))->dtype.b_val;
            break;

        case SQL_IPV4_ADDR:
            dtype_value.u.ipv4.ipv4_addr_str = (dynamic_cast <Dtype_IPv4_addr *>(dtype))->dtype.ip_addr_str.c_str();
            dtype_value.u.ipv4.ipv4_addr_int = (dynamic_cast <Dtype_IPv4_addr *>(dtype))->dtype.ipaddr_int;
            break;

        case SQL_INTERVAL:
        {
             Dtype_STRING *dtype_str;
             dtype_str = (dynamic_cast <Dtype_INTERVAL *>(dtype))->toString();
             dtype_value.u.interval.interval_str = dtype_str->dtype.str_val.c_str();
             dtype_value.u.interval.lb = (dynamic_cast <Dtype_INTERVAL *>(dtype))->dtype.lb;
             dtype_value.u.interval.ub = (dynamic_cast <Dtype_INTERVAL *>(dtype))->dtype.ub;
        }
        break;

        default:
            assert(0);
    }
    return dtype_value;
}


Dtype *
Dtype_copy (Dtype *dtype) {

    return dynamic_cast<Dtype *> (dtype->clone());
}

bool 
Dtype_less_than_operator (Dtype *dtype1, Dtype *dtype2) {

    return *dtype1 < *dtype2;
}