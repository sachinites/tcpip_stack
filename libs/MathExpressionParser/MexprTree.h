#ifndef __MEXPR_TREE__
#define __MEXPR_TREE__

#include <stdbool.h>
#include <stdint.h>
#include "MExprcppEnums.h"

class Dtype;

class MexprNode {

    private:
    protected:
        uint8_t flags;
        /* Must be instantiated by the derieved class only*/
        MexprNode ();
    public:
        virtual ~MexprNode ();
        virtual Dtype* compute(Dtype *dtype1, Dtype *dtype2) = 0;
        virtual mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) = 0;
        virtual MexprNode * clone() = 0;
        bool IsInequalityOperator();
        void SetFlag(uint8_t flag_bit);
        void UnSetFlag(uint8_t flag_bit);
        bool IsFlagSet(uint8_t flag_bit);
        MexprNode *parent;
        MexprNode *left;
        MexprNode *right;
        MexprNode *lst_left;
        MexprNode *lst_right;
};

typedef struct lex_data_ lex_data_t;

class MexprTree {

    private:
    mexprcpp_dtypes_t validate_internal(MexprNode *root);
    void CloneNodesRecursively  (      MexprNode *src_node, 
                                                             MexprNode *new_node, int child);
                                                             
    void CreateOperandList (MexprNode *node);
    void CreateOperandList ();
    void destroy_internal(MexprNode *root);
    void NodeRemoveFromList (MexprNode *node);

    public:
        MexprNode *root;
        MexprNode *lst_head;
        MexprTree();
        MexprTree(lex_data_t **postfix_lex_data_array, int size);
        virtual ~MexprTree();
        bool validate(MexprNode *root);
        Dtype *evaluate();
        Dtype *evaluate(MexprNode *root);
        MexprTree *clone(MexprNode *root);
        bool concatenate (MexprNode *leaf_node, MexprTree *child_tree);
        void destroy(MexprNode *root);
        bool optimize(MexprNode *root);
        MexprNode *GetUnResolvedOperandNode();
        uint8_t  RemoveUnresolveOperands();
        bool IsLoneVariableOperandNode();
};

#define MexprTree_Iterator_Operands_Begin(tree_ptr, node_ptr)  \
    { MexprNode *_next_node = NULL; \
    for (node_ptr = tree_ptr->lst_head;  node_ptr; node_ptr = _next_node){ \
        _next_node = node_ptr->lst_right;

#define MexprTree_Iterator_Operands_End }}

#endif 