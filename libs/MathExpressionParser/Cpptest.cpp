#include <stdio.h>
#include <assert.h>
#include <string>
#include "MExprcppEnums.h"
#include "Dtype.h"
#include "ParserExport.h"
#include "../RDBMSImplementation/core/SqlMexprIntf.h"

static  Dtype *
compute_opd_value_fn (void *data_src) {

    Dtype *res;

    if ((char)data_src == 'a') {
        Dtype_INT *res_int = new Dtype_INT(1);
        res = res_int;
    }

    else if ((char)data_src == 'b') {
        Dtype_DOUBLE *res_d = new Dtype_DOUBLE(2);
        res = res_d;
    }

    else if ((char)data_src == 'c') {
        Dtype_DOUBLE *res_d = new Dtype_DOUBLE(3);
        res = res_d;
    }

    else if ((char)data_src == 'd') {
        Dtype_STRING *res_str = new Dtype_STRING();
        res_str->dtype.str_val = std::string ((char *)"Sagar");
        res = res_str;
    }

    return res;
}

int 
main (int argc, char **argv) {

    parse_init();

    sql_exptree_t * tree;
    Dtype *res;

    while (1) {
        
        printf ("OOPsCalc : ");
        
        fgets ( (char *)lex_buffer, sizeof (lex_buffer), stdin);

        if (lex_buffer[0] == '\n') {
            lex_buffer[0] = 0;
            continue;
        }

        lex_set_scan_buffer ( (const char *)lex_buffer);

        tree = sql_create_exp_tree_conditional ();

        if (!tree) {
            tree = sql_create_exp_tree_compute ();
        }

        if (!tree) {
            printf ("Error : Exp Tree could not built\n");
            continue;
        }

    #if 0
        mexpr_debug_print_expression_tree (tree->root);
        tree = mexpt_clone (tree);
        printf ("\nPrinting Clone :\n");
        mexpr_debug_print_expression_tree (tree->root);
        printf ("\n");
    #endif

        if (!tree->tree->validate(tree->tree->root)) {
            
            printf ("Error : Exp Tree Validation Failed\n");

            tree->tree->destroy (tree->tree->root);
            free(tree);
            Parser_stack_reset();
            continue;
        }
        printf ("Exp Tree Successfully Validated prior to resolution\n");

#if 0
        printf ("Print Exp Tree Before Optimization\n");
        mexpr_debug_print_expression_tree (tree->root);
        printf("\n");
        mexpt_optimize (tree->root);
        printf ("Print Exp Tree After Optimization\n");
        mexpr_debug_print_expression_tree (tree->root);
        printf ("\n");
#endif 

#if 1
        {
            MexprNode *opnd_node;
            SqlExprTree_Iterator_Operands_Begin(tree, opnd_node)
            {

                if (sql_get_opnd_variable_name(opnd_node) == std::string("a"))
                {
                    InstallDtypeOperandProperties(opnd_node, (void *)'a', compute_opd_value_fn);
                }

                if (sql_get_opnd_variable_name(opnd_node) == std::string("b"))
                {
                    InstallDtypeOperandProperties(opnd_node, (void *)'b', compute_opd_value_fn);
                }

                if (sql_get_opnd_variable_name(opnd_node) == std::string("c"))
                {
                    InstallDtypeOperandProperties(opnd_node, (void *)'c', compute_opd_value_fn);
                }
            }

            if (sql_get_opnd_variable_name(opnd_node) == std::string("d"))
            {
                InstallDtypeOperandProperties(opnd_node, (void *)'d', compute_opd_value_fn);
            }
        }
#endif

#if 0
        if (!tree->tree->validate(tree->tree->root)) {
            
            printf ("Error : Exp Tree Validation Failed\n");
            tree->tree->destroy (tree->tree->root);
            free(tree);
            Parser_stack_reset();
            continue;
        }
        printf ("Exp Tree Successfully Validated after resolution\n");
#endif 
#if 1
        uint8_t cnt = sql_tree_remove_unresolve_operands (tree);
        printf ("No of unresolved operands removed = %d\n", cnt);

        if (cnt) {
            //tree->tree->optimize (tree->tree->root);
            //printf ("Print Exp Tree After Optimization\n");
            //mexpr_debug_print_expression_tree (tree->root);
        }
#endif 
        res = sql_evaluate_exp_tree(tree);
        
        if (!res || res->did == MATH_CPP_DTYPE_INVALID) {

            printf ("Error : Exp Tree Evaluation Failed\n");

                    tree->tree->destroy (tree->tree->root);
                    free(tree);
                    Parser_stack_reset();
                    continue;
        }

        switch (res->did) {

            case MATH_CPP_INT:
            {
                Dtype_INT *res_int = dynamic_cast <Dtype_INT *> (res);
                printf ("= %d\n",  res_int->dtype.int_val);
            }
            break;
            case MATH_CPP_DOUBLE:
            {
                Dtype_DOUBLE *res_d = dynamic_cast <Dtype_DOUBLE *> (res);
                printf ("= %lf\n",  res_d->dtype.d_val);
            }
            break;
            case MATH_CPP_STRING:
            {
                Dtype_STRING *res_str = dynamic_cast <Dtype_STRING *> (res);
                printf ("%s\n",  res_str->dtype.str_val.c_str());
            }
            break;
            case MATH_CPP_BOOL:
            {
                Dtype_BOOL *res_b = dynamic_cast <Dtype_BOOL *> (res);
                if (res_b->dtype.b_val) {
                     printf(" = TRUE\n");
                }
                else {
                    printf(" = FALSE\n");
                }
            }
            break;
            case MATH_CPP_IPV4:
            {
                Dtype_IPv4_addr *res_v4 = dynamic_cast <Dtype_IPv4_addr *> (res);
                printf ("%s\n", res_v4->dtype.ip_addr_str.c_str());
            }
            break;

            default:
                assert(0);
        }


        tree->tree->destroy (tree->tree->root);
        free(tree);
        Parser_stack_reset();
    }

    return 0;
}
