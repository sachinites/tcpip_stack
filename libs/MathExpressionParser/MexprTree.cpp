#include <assert.h>
#include <memory.h>
#include <string>
#include "MexprTree.h"
#include "Dtype.h"
#include "Operators.h"
#include <stack>

typedef struct lex_data_ {

    int token_code;
    int token_len;
    uint8_t *token_val;
} lex_data_t;


MexprNode::MexprNode() {

    this->flags = 0;
    this->parent = NULL;
    this->left = NULL;
    this->right = NULL;
    this->lst_left = NULL;
    this->lst_right = NULL;
}

MexprNode::~MexprNode() {

}

void
MexprNode::SetFlag(uint8_t flag_bit) {

    this->flags |= flag_bit;
}
        
void 
MexprNode::UnSetFlag(uint8_t flag_bit) {

    this->flags &= ~flag_bit;
}

bool
MexprNode::IsFlagSet(uint8_t flag_bit) {

    return (this->flags & flag_bit);
}


/*  MexprTree  */

MexprTree:: MexprTree() {

    this->root = NULL;
    this->lst_head = NULL;
 }

MexprTree::MexprTree(lex_data_t **postfix_lex_data_array, int size) {

    int i;
    bool is_operator;
    this->root = NULL;
    this->lst_head = NULL;

    std::stack<MexprNode *> stack;

    for (i = 0; i < size; i++) {

        is_operator = Math_cpp_is_operator (postfix_lex_data_array[i]->token_code);
                                
        do {

            if (is_operator) break;

            MexprNode *node = Dtype::factory ((mexprcpp_dtypes_t)(postfix_lex_data_array[i]->token_code));
            Dtype *dtype = dynamic_cast<Dtype *> (node);
            Dtype_VARIABLE *dvar = dynamic_cast<Dtype_VARIABLE *> (node); 

            if (dvar) {
                assert (!dvar->is_resolved);
                dvar->dtype.variable_name.assign(std::string((char *)postfix_lex_data_array[i]->token_val));
                node->lst_right = this->lst_head;
                if ( this->lst_head) this->lst_head->lst_left = node;
                this->lst_head = node;
            }
            else {
                 dtype->SetValue ((void *)postfix_lex_data_array[i]->token_val);
            }

            stack.push(node);

        } while (0);

        if (!is_operator) continue;

        Operator *opr = Operator::factory (( mexprcpp_operators_t)postfix_lex_data_array[i]->token_code);

        if (opr->is_unary == false){

            MexprNode *right = stack.top(); stack.pop();
            MexprNode *left = stack.top(); stack.pop();
            MexprNode *opNode = opr;

            opNode->left = left;
            opNode->right = right;
            left->parent = opNode;
            right->parent = opNode;
            stack.push (opNode);
        }
        else {

            MexprNode *left = stack.top(); stack.pop();
            MexprNode * opNode = opr;
            opNode->left = left;
            opNode->right = NULL;
            left->parent = opNode;
            stack.push (opNode);
        }
    }

    this->root = stack.top(); stack.pop();
    assert (stack.empty());
    assert(!this->root->parent);    
}

 MexprTree::~ MexprTree() {

    this->destroy_internal (this->root);
    this->root = NULL;
    assert (!this->lst_head);
 }


mexprcpp_dtypes_t
MexprTree::validate_internal (MexprNode *root) {

   mexprcpp_dtypes_t res = MATH_CPP_DTYPE_INVALID;
    
    mexprcpp_dtypes_t lrc, rrc;

    if (!root) {
        return res;
    }   

    lrc = validate_internal (root->left);
    rrc = validate_internal (root->right);

    /* If i am leaf*/ 
    if (!root->left && !root->right) {

        return root->ResultStorageType(MATH_CPP_DTYPE_INVALID, 
                                                            MATH_CPP_DTYPE_INVALID);
    }

    /* If I am Half node*/
    if (root->left && !root->right) {

        return root->ResultStorageType(lrc, MATH_CPP_DTYPE_INVALID);
    }

    return root->ResultStorageType (lrc, rrc);
}

bool
MexprTree::validate (MexprNode *root) {

    mexprcpp_dtypes_t dtype = validate_internal (root);
    return (dtype != MATH_CPP_DTYPE_INVALID);
}


Dtype *
MexprTree::evaluate (MexprNode  *root) {

    Dtype *res = NULL;

    if (!root) return NULL;

    Dtype *lrc =  evaluate (root->left);
    Dtype *rrc =  evaluate (root->right); 

    /* If I am leaf */ 
    if (!root->left && !root->right) {

        res = root->compute(NULL, NULL);
    }

    /* If I am half node*/
    else if (root->left && !root->right) {

        res = root->compute(lrc, NULL);
        delete lrc;
    }

    /* Full Node*/
    else {

        res = root->compute(lrc, rrc);
        delete lrc;
        delete rrc;
    }

    if (!res) return NULL;
    if (res->did == MATH_CPP_DTYPE_INVALID) {
        delete res;
        return NULL;
    }

    return res;
}


Dtype *
MexprTree::evaluate () {

    if (!this->root) return NULL;
    return this->evaluate(this->root);
}

void 
MexprTree::CreateOperandList (MexprNode *node) {

    if (!node) return;

    Dtype_VARIABLE *dtype = dynamic_cast <Dtype_VARIABLE *>(node);

    if (dtype) {

        if (!this->lst_head) {
           this->lst_head = node;
        }
        else {
            node->lst_right = this->lst_head;
            this->lst_head->lst_left = node;
            this->lst_head = node;
        }
    }

    CreateOperandList (node->left);
    CreateOperandList (node->right);
}

void 
MexprTree::CreateOperandList (){

    this->CreateOperandList (this->root);
}

void
MexprTree::CloneNodesRecursively (MexprNode *src_node, 
                                                             MexprNode *new_node, int child) {

    MexprNode *temp;

    if (!src_node) return;

    if (child == 0) {

        this->root = src_node->clone();
        new_node = this->root ;
    }
    else if (child == -1) {

        temp = src_node->clone();
        new_node->left = temp;
        temp->parent = new_node;
        new_node = temp;
    }
    else if (child == 1) {

        temp = src_node->clone();
        new_node->right = temp;
        temp->parent = new_node;
        new_node = temp;
    }    

    CloneNodesRecursively (src_node->left, new_node, -1);
    CloneNodesRecursively (src_node->right, new_node, 1);
}


MexprTree *
MexprTree::clone(MexprNode *root) {

    MexprTree *clone_tree = new MexprTree();
    clone_tree->CloneNodesRecursively (root, NULL, 0);
    clone_tree->CreateOperandList( );
    return clone_tree;
}

bool
MexprTree::concatenate (MexprNode *leaf_node,
                                         MexprTree *child_tree) {

    MexprNode *curr_node;
    Dtype_VARIABLE *dtype_var;
    
    MexprTree *parent_tree = this;

    assert (leaf_node->left == NULL && leaf_node->right == NULL);
    assert (child_tree->root);
    dtype_var = dynamic_cast <Dtype_VARIABLE *> (leaf_node);
    assert (dtype_var);
    assert (!dtype_var->is_resolved);

    if (!leaf_node->parent) {
        assert (parent_tree->root == leaf_node);
        delete(leaf_node);
        parent_tree->root = child_tree->root;
        child_tree->root = NULL;
        parent_tree->lst_head = child_tree->lst_head;
        child_tree->lst_head = NULL;
        delete child_tree;
        return true;
    }

   MexprNode *parent_node = leaf_node->parent;

    if (parent_node->left == leaf_node)
        parent_node->left = child_tree->root;
    else
        parent_node->right = child_tree->root;

    child_tree->root->parent = parent_node;
    child_tree->root = NULL;

    this->NodeRemoveFromList (leaf_node);
    delete leaf_node;

    MexprTree_Iterator_Operands_Begin (parent_tree, curr_node) {

        if (!curr_node->lst_right) break;

    } MexprTree_Iterator_Operands_End;

     if (curr_node) {
        curr_node->lst_right = child_tree->lst_head;
        if (curr_node->lst_right) curr_node->lst_right->lst_left = curr_node;
     }
     else {
        parent_tree->lst_head = child_tree->lst_head;
     }

     child_tree->lst_head = NULL;
     delete child_tree;

     if (!parent_tree->validate (parent_tree->root)) return false;
     this->optimize (parent_tree->root);
     return true;
}

void 
MexprTree::NodeRemoveFromList (MexprNode *node) {

    if (node->lst_left == NULL) {

        /* Is is Ist node in the list*/
        assert(this->lst_head == node);
        this->lst_head = node->lst_right;
        if (this->lst_head)
            this->lst_head->lst_left = NULL;
    }
    else {

        node->lst_left->lst_right = node->lst_right;
        if (node->lst_right)
            node->lst_right->lst_left = node->lst_left;
    }

    node->lst_left = NULL;
    node->lst_right = NULL;
}


void 
MexprTree::destroy_internal(MexprNode *root) {

    Dtype_VARIABLE *dtype_var;

    if (!root) return;

    destroy_internal (root->left);
    destroy_internal (root->right);

    dtype_var = dynamic_cast <Dtype_VARIABLE *> (root);

    if (dtype_var)  this->NodeRemoveFromList (root);
    /* Mexpr Lib never release the data src, it is application
        responsibility to delete the data srcs*/
    delete root;
}

void 
MexprTree::destroy(MexprNode *root) {

    bool rc = this->root == root;

    MexprNode *parent = root->parent;

    if (parent) {

        if (parent->left == root) parent->left = NULL;
        if (parent->right == root) parent->right = NULL;
        root->parent = NULL;
    }

    destroy_internal (root);

    if (rc) {
        this->root = NULL;
        assert(!this->lst_head);
        delete this;
    }
}

bool
MexprTree::optimize(MexprNode *root) {

    bool rc = false;
    MexprNode *lchild, *rchild;

    if (!root) return false;

    bool lrc = this->optimize  (root->left);
    bool rrc = this->optimize  (root->right);

    return true;
}


MexprNode *
MexprTree::GetUnResolvedOperandNode() {

    MexprNode *opnd_node;
    Dtype_VARIABLE *dvar_node;

    MexprTree_Iterator_Operands_Begin (this, opnd_node) {

        dvar_node = dynamic_cast<Dtype_VARIABLE *> (opnd_node);
        assert (dvar_node) ;
        if (dvar_node->is_resolved ) continue;
        return dvar_node;

    } MexprTree_Iterator_Operands_End;

    return NULL;
}

bool 
MexprNode::IsInequalityOperator () {

    Operator *opr = dynamic_cast<Operator *> (this);
    
    if (!opr) return false;

    switch (opr->opid) {

        case MATH_CPP_EQ:
        case MATH_CPP_NEQ:
        case MATH_CPP_LESS_THAN:
        case MATH_CPP_LESS_THAN_EQ:
        case MATH_CPP_GREATER_THAN:
        case MATH_CPP_IN:
            return true;
        default:
            return false;
    }
    return false;
}


uint8_t 
MexprTree::RemoveUnresolveOperands() {

    Operator *opr;
    uint8_t count = 0;
    Dtype_BOOL *dtype_b;
    MexprNode *opnd_node;
    
    while ((opnd_node = this->GetUnResolvedOperandNode())) {

        while (opnd_node && !opnd_node->IsInequalityOperator()) {
            opnd_node = opnd_node->parent;
        }

        if (!opnd_node) return count;

        opr = dynamic_cast <Operator *> (opnd_node);
        assert (opr);

        this->destroy_internal (opnd_node->left);
        this->destroy_internal (opnd_node->right);
        opnd_node->left = NULL;
        opnd_node->right = NULL;
        opr->is_optimized = true;
        dtype_b = new Dtype_BOOL();
        dtype_b->dtype.b_val = true;
        opr->optimized_result = dtype_b;
        count++;
    }
    this->validate (this->root);
    this->optimize(this->root);
    return count;    
}

bool 
MexprTree::IsLoneVariableOperandNode() {

    MexprNode *opnd_node;

    if (!this->root) return false;
    if (this->root->left || this->root->right) return false;

    opnd_node = this->lst_head;
    if (!opnd_node) return false;

    Dtype_VARIABLE *d_var = dynamic_cast <Dtype_VARIABLE *>(opnd_node);
    assert (d_var);
    assert (this->root == opnd_node);
    return true;
}
