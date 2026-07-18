#include <cstddef>
#include <assert.h>
#include <string>
#include <math.h>
#include <regex>
#include "Operators.h"
#include "Dtype.h"

Operator::Operator() { 

    opid = MATH_CPP_OPR_MAX;
    is_unary = false;
    is_optimized = false;
    optimized_result = NULL;
}

Operator::~Operator() { 

    if (this->optimized_result) {
        delete this->optimized_result;
    }
}



/* MOD operator */

OperatorMod::OperatorMod() { 

     opid =  MATH_CPP_MOD;
     name = "Mod";
     is_unary = false;
}

OperatorMod::~OperatorMod() {  }

mexprcpp_dtypes_t
OperatorMod::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_INT;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype *
OperatorMod::compute(Dtype *dtype1, Dtype *dtype2) {

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    if (res_did == MATH_CPP_DTYPE_INVALID) return NULL;

    /* This Operator Supports only int results*/
    assert (res_did == MATH_CPP_INT);
    Dtype *res = Dtype::factory(res_did);
    Dtype_INT *res_int = dynamic_cast <Dtype_INT *> (res);
    Dtype_INT *dtype1_int = dynamic_cast <Dtype_INT *> (dtype1);
    Dtype_INT *dtype2_int = dynamic_cast <Dtype_INT *> (dtype2);
    res_int->dtype.int_val = dtype1_int->dtype.int_val % dtype2_int->dtype.int_val;
    return res;
}

MexprNode * 
OperatorMod::clone() {

    OperatorMod *obj = new OperatorMod();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* PLUS operator */

OperatorPlus::OperatorPlus() { 

     opid =  MATH_CPP_PLUS;
     name = "Plus";
     is_unary = false;
}

OperatorPlus::~OperatorPlus() {  }

mexprcpp_dtypes_t
OperatorPlus::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => int  
        int, double => double
        double, int => double
        double, double => double
        string, string => string
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_INT;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DOUBLE;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }            


        case MATH_CPP_STRING:
            if (did2 == MATH_CPP_STRING || 
                    did2 == MATH_CPP_DTYPE_WILDCRAD) return MATH_CPP_STRING;
            return MATH_CPP_DTYPE_INVALID;


        case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_STRING:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return did2;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorPlus::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) return NULL;

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_INT);
                    Dtype_INT *res_int = dynamic_cast<Dtype_INT *> (res);
                    res_int->dtype.int_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val + 
                                                            dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val +
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val +
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val +
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            


    case MATH_CPP_STRING:

            switch (dtype2->did) {

                case MATH_CPP_STRING:
                {
                    res = Dtype::factory (MATH_CPP_STRING);
                    Dtype_STRING *res_str = dynamic_cast<Dtype_STRING *> (res);
                    res_str->dtype.str_val = dynamic_cast<Dtype_STRING *> (dtype1)->dtype.str_val +
                                                           dynamic_cast<Dtype_STRING *> (dtype2)->dtype.str_val;
                    return res;
                }
                default:
                    return NULL;
            }        
        break;


        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorPlus::clone() {

    OperatorPlus *obj = new OperatorPlus();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* MINUS operator */

OperatorMinus::OperatorMinus() {

    opid = MATH_CPP_MINUS;
    name = "Minus";
    is_unary = false;
}

OperatorMinus::~OperatorMinus() { }

mexprcpp_dtypes_t
OperatorMinus::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => int  
        int, double => double
        double, int => double
        double, double => double
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_INT;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DOUBLE;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }            


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return did2;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorMinus::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) return NULL;

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_INT);
                    Dtype_INT *res_int = dynamic_cast<Dtype_INT *> (res);
                    res_int->dtype.int_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val -
                                                            dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val -
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val -
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val -
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorMinus::clone() {

    OperatorMinus *obj = new OperatorMinus();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* MUL operator */

OperatorMul::OperatorMul() {

    opid = MATH_CPP_MUL;
    name = "Mul";
    is_unary = false;
}

OperatorMul::~OperatorMul() {

}

Dtype *
OperatorMul::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
       return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) return NULL;    

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_INT);
                    Dtype_INT *res_int = dynamic_cast<Dtype_INT *> (res);
                    res_int->dtype.int_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val *
                                                            dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val *
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val *
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val *
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        default:
            return NULL;

    }    
}

mexprcpp_dtypes_t
OperatorMul::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => int  
        int, double => double
        double, int => double
        double, double => double
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_INT;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DOUBLE;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }            


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return did2;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

MexprNode *
OperatorMul::clone() {

    OperatorMul *obj = new OperatorMul();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* DIV operator */

OperatorDiv::OperatorDiv() {

    opid = MATH_CPP_DIV;
    name = "Div";
    is_unary = false;
}

OperatorDiv::~OperatorDiv() {

}

Dtype *
OperatorDiv::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) return NULL;    

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val /
                                                            (double)((dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val == 0) ? 1 : \
                                                            dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val );
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val /
                                                        (dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val == 0 ? 1 : \
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val );
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = (dynamic_cast<Dtype_DOUBLE *> (dtype1))->dtype.d_val /
                                                        (double)((double)(dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val) == 0 ? 1 : \
                                                        (dynamic_cast<Dtype_INT *> (dtype2))->dtype.int_val) ;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    res = Dtype::factory (MATH_CPP_DOUBLE);
                    Dtype_DOUBLE *res_d = dynamic_cast<Dtype_DOUBLE *> (res);
                    res_d->dtype.d_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val /
                                                        (dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val == 0 ? 1 : \
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val);
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        default:
            return NULL;

    }    
}

mexprcpp_dtypes_t
OperatorDiv::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => int  
        int, double => double
        double, int => double
        double, double => double
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_INT;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DOUBLE;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }            


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DOUBLE;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

MexprNode *
OperatorDiv::clone() {

    OperatorDiv *obj = new OperatorDiv();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}



/* Sqr operator */

OperatorSqr::OperatorSqr() {

    opid = MATH_CPP_SQR;
    name = "sqr";
    is_unary = true;
}

OperatorSqr::~OperatorSqr() { }


mexprcpp_dtypes_t
OperatorSqr::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:
        case MATH_CPP_DOUBLE:
        case MATH_CPP_DTYPE_WILDCRAD:
            return did1;
        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype *
OperatorSqr::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    switch (dtype1->did) {

        case MATH_CPP_INT:
        {
            Dtype_INT *dtype1_int = dynamic_cast <Dtype_INT *> (dtype1);
            res = new Dtype_INT (dtype1_int->dtype.int_val * dtype1_int->dtype.int_val);
            return res;
        }
        break;

        case MATH_CPP_DOUBLE:
        {
             Dtype_DOUBLE *dtype1_d = dynamic_cast <Dtype_DOUBLE *> (dtype1);
             res = new Dtype_DOUBLE (dtype1_d->dtype.d_val * dtype1_d->dtype.d_val);
             return res;
        }
        break;

        default:
            return NULL;
    }
}

MexprNode * 
OperatorSqr::clone() {

    OperatorSqr *obj = new OperatorSqr();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* Sqrt operator */

OperatorSqrt::OperatorSqrt() {

    opid = MATH_CPP_SQRT;
    name = "sqrt";
    is_unary = true;
}

OperatorSqrt::~OperatorSqrt() { }


mexprcpp_dtypes_t
OperatorSqrt::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:
        case MATH_CPP_DOUBLE:
            return MATH_CPP_DOUBLE;
        case MATH_CPP_DTYPE_WILDCRAD:
            return did1;
        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype *
OperatorSqrt::compute(Dtype *dtype1, Dtype *dtype2) {

    Dtype *res;

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    switch (dtype1->did) {

        case MATH_CPP_INT:
        {
            Dtype_INT *dtype1_int = dynamic_cast <Dtype_INT *> (dtype1);
            res = new Dtype_DOUBLE (sqrt (dtype1_int->dtype.int_val));
            return res;
        }
        break;

        case MATH_CPP_DOUBLE:
        {
             Dtype_DOUBLE *dtype1_d = dynamic_cast <Dtype_DOUBLE *> (dtype1);
             res = new Dtype_DOUBLE (sqrt (dtype1_d->dtype.d_val));
             return res;
        }
        break;

        default:
            return NULL;
    }
}

MexprNode * 
OperatorSqrt::clone() {

    OperatorSqrt *obj = new OperatorSqrt();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




/* EQ operator */

OperatorEq::OperatorEq() {

    opid = MATH_CPP_EQ;
    name = "=";
    is_unary = false;
}

OperatorEq::~OperatorEq() { }

mexprcpp_dtypes_t
OperatorEq::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => bool
        int, double => bool
        double, int => bool
        double, double => bool
        string, string => bool
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }            


            case MATH_CPP_STRING:

            switch (did2) {

                case MATH_CPP_STRING:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }                


            case MATH_CPP_IPV4:

            switch (did2) {

                case MATH_CPP_IPV4:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }      


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_STRING:
                case MATH_CPP_IPV4:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorEq::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) {
    
        return NULL;
    }

  Dtype *res = Dtype::factory (MATH_CPP_BOOL);

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val ==
                                                        dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val ==
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val ==
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val ==
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        case MATH_CPP_STRING:

            switch (dtype2->did) {

                case MATH_CPP_STRING:
                {
                     Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_STRING *> (dtype1)->dtype.str_val ==
                                                        dynamic_cast<Dtype_STRING *> (dtype2)->dtype.str_val;
                    return res_b;
                }
            }
            break;


        case MATH_CPP_IPV4:

            switch (dtype2->did) {

                case MATH_CPP_IPV4:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_IPv4_addr *> (dtype1)->dtype.ipaddr_int == 
                                                        dynamic_cast<Dtype_IPv4_addr *> (dtype2)->dtype.ipaddr_int ;
                    return res_b;
                }
                break;
            }

        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorEq::clone() {

    OperatorEq *obj = new OperatorEq();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}


/* Neq operator */

OperatorNeq::OperatorNeq() {

    opid = MATH_CPP_NEQ;
    name = "!=";
    is_unary = false;
}

OperatorNeq::~OperatorNeq() { }

mexprcpp_dtypes_t
OperatorNeq::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    /* Allowed Combinations 

        int , int  => bool
        int, double => bool
        double, int => bool
        double, double => bool
        string, string => bool
    */

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }


            case MATH_CPP_STRING:

            switch (did2) {

                case MATH_CPP_STRING:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }                


            case MATH_CPP_IPV4:

            switch (did2) {

                case MATH_CPP_IPV4:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }      


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_STRING:
                case MATH_CPP_IPV4:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorNeq::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) {
    
        return NULL;
    }

  Dtype *res = Dtype::factory (MATH_CPP_BOOL);

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val !=
                                                        dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val !=
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val !=
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val !=
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        case MATH_CPP_STRING:

            switch (dtype2->did) {

                case MATH_CPP_STRING:
                {
                     Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_STRING *> (dtype1)->dtype.str_val !=
                                                        dynamic_cast<Dtype_STRING *> (dtype2)->dtype.str_val;
                    return res_b;
                }
            }
            break;


        case MATH_CPP_IPV4:

            switch (dtype2->did) {

                case MATH_CPP_IPV4:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_IPv4_addr *> (dtype1)->dtype.ipaddr_int != 
                                                        dynamic_cast<Dtype_IPv4_addr *> (dtype2)->dtype.ipaddr_int ;
                    return res_b;
                }
                break;
            }

        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorNeq::clone() {

    OperatorNeq *obj = new OperatorNeq();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




/* LessThan operator */

OperatorLessThan::OperatorLessThan() {

    opid = MATH_CPP_LESS_THAN;
    name = "<";
    is_unary = false;
}

OperatorLessThan::~OperatorLessThan() { }

mexprcpp_dtypes_t
OperatorLessThan::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorLessThan::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) {
    
        return NULL;
    }

  Dtype *res = Dtype::factory (MATH_CPP_BOOL);

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val <
                                                        dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val <
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val <
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val <
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorLessThan::clone() {

    OperatorLessThan *obj = new OperatorLessThan();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




/* GreaterThan operator */

OperatorGreaterThan::OperatorGreaterThan() {

    opid = MATH_CPP_LESS_THAN;
    name = ">";
    is_unary = false;
}

OperatorGreaterThan::~OperatorGreaterThan() { }

mexprcpp_dtypes_t
OperatorGreaterThan::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_INT:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }

        case MATH_CPP_DOUBLE:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default: 
                    return MATH_CPP_DTYPE_INVALID;
            }


           case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_INT:
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                case MATH_CPP_DTYPE_INVALID:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

Dtype*
OperatorGreaterThan::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    mexprcpp_dtypes_t res_did = this->ResultStorageType (dtype1->did, dtype2->did);
    
    if (res_did == MATH_CPP_DTYPE_INVALID || 
         res_did == MATH_CPP_DTYPE_WILDCRAD) {
    
        return NULL;
    }

  Dtype *res = Dtype::factory (MATH_CPP_BOOL);

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val = dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val >
                                                        dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = (double)dynamic_cast<Dtype_INT *> (dtype1)->dtype.int_val >
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;


        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                     res_b->dtype.b_val = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val >
                                                        (double)dynamic_cast<Dtype_INT *> (dtype2)->dtype.int_val;
                    return res;                
                }
                case MATH_CPP_DOUBLE:
                {
                    Dtype_BOOL *res_b = dynamic_cast<Dtype_BOOL *> (res);
                    res_b->dtype.b_val  = dynamic_cast<Dtype_DOUBLE *> (dtype1)->dtype.d_val >
                                                        dynamic_cast<Dtype_DOUBLE *> (dtype2)->dtype.d_val;
                    return res;
                }
                default:
                    return NULL;
            }
            break;            

        default:
            return NULL;

    }
    
    return NULL;
}

MexprNode * 
OperatorGreaterThan::clone() {

    OperatorGreaterThan *obj = new OperatorGreaterThan();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




/* IN Operator*/

OperatorIn::OperatorIn() {

    opid = MATH_CPP_IN;
    name = "in";
    is_unary = false;
}

OperatorIn::~OperatorIn() { }

Dtype* 
OperatorIn::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    switch (dtype1->did ) {

        case MATH_CPP_STRING:
        {

                switch (dtype2->did) {

                    case MATH_CPP_STRING_LST:
                    {
                            Dtype_BOOL *res = dynamic_cast <Dtype_BOOL *>( Dtype::factory (MATH_CPP_BOOL));
                            res->dtype.b_val = false;
                            Dtype_STRING_LST *str_lst = dynamic_cast <Dtype_STRING_LST *> (dtype2);
                            Dtype_STRING *str = dynamic_cast <Dtype_STRING *> (dtype1);
                            Dtype_STRING *elem;

                            for (std::list<Dtype_STRING *>::iterator it = str_lst->dtype.str_lst.begin(); 
                                    it != str_lst->dtype.str_lst.end(); ++it) {

                                elem = *it;

                                if (elem->dtype.str_val == str->dtype.str_val) {
                                    res->dtype.b_val = true;
                                    return res;
                                }
                            }
                            return res;    
                    }
                    break;
                }
        }
        break;


        case MATH_CPP_INT:
        {
            switch (dtype2->did) {

                case MATH_CPP_INTERVAL:
                {

                    Dtype_BOOL *res = dynamic_cast <Dtype_BOOL *>( Dtype::factory (MATH_CPP_BOOL));
                    res->dtype.b_val = false;
                    Dtype_INT *dtype1_int = dynamic_cast <Dtype_INT *> (dtype1);
                    Dtype_INTERVAL *dtype2_ival = dynamic_cast <Dtype_INTERVAL *> (dtype2);
                    int a = dtype1_int->dtype.int_val;
                    int lb = dtype2_ival->dtype.lb;
                    int ub = dtype2_ival->dtype.ub;
                    if (a >= lb && a <= ub)  res->dtype.b_val  = true;
                    return res;
                }
                break;
            }
        }
        break;

        default:
            assert(0);
    }

    return NULL;
}

mexprcpp_dtypes_t
OperatorIn::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized)
    {
        return this->optimized_result->did;
    }

    switch (did1)
    {

    case MATH_CPP_VARIABLE:
    {
        switch (did2)
        {

        case MATH_CPP_STRING_LST:
        case MATH_CPP_INTERVAL:
        case MATH_CPP_DTYPE_WILDCRAD:
            return MATH_CPP_BOOL;
        default:
            return MATH_CPP_DTYPE_INVALID;
        }
    }
    break;

    case MATH_CPP_STRING:

        switch (did2)
        {

        case MATH_CPP_STRING_LST:
        case MATH_CPP_DTYPE_WILDCRAD:
            return MATH_CPP_BOOL;
        default:
            return MATH_CPP_DTYPE_INVALID;
        }
        break;

    case MATH_CPP_INT:

        switch (did2)
        {

        case MATH_CPP_INTERVAL:
        case MATH_CPP_DTYPE_WILDCRAD:
            return MATH_CPP_BOOL;
        default:
            return MATH_CPP_DTYPE_INVALID;
        }
        break;

    case MATH_CPP_DTYPE_WILDCRAD:

        switch (did2)
        {

        case MATH_CPP_INTERVAL:
        case MATH_CPP_STRING_LST:
            return MATH_CPP_BOOL;
        case MATH_CPP_DTYPE_WILDCRAD:
            return MATH_CPP_DTYPE_WILDCRAD;
        default:
            return MATH_CPP_DTYPE_INVALID;
        }

    default:
        return MATH_CPP_DTYPE_INVALID;
    }
}

MexprNode * 
OperatorIn::clone() {

    OperatorIn *obj = new OperatorIn();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}





/* LIKE Operator*/

OperatorLIKE::OperatorLIKE() {

    opid = MATH_CPP_LIKE;
    name = "LIKE";
    is_unary = false;
}

OperatorLIKE::~OperatorLIKE() { }

Dtype* 
OperatorLIKE::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    assert (dtype2->did == MATH_CPP_STRING);

    Dtype_STRING *text = dtype1->toString();
    
    if (!text) {
        printf ("Error : LIKE left operand could not be stringified\n");
        return NULL;
    }

    Dtype_BOOL *res = dynamic_cast <Dtype_BOOL *>( Dtype::factory (MATH_CPP_BOOL));
    res->dtype.b_val = false;
    
    Dtype_STRING *regex = dynamic_cast <Dtype_STRING *>(dtype2);

    std::regex pattern(regex->dtype.str_val);

    if (std::regex_search(text->dtype.str_val, pattern)) {
        res->dtype.b_val = true;
    }

    delete text;
    return res;
}

mexprcpp_dtypes_t 
OperatorLIKE::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_DTYPE_INVALID:
        case MATH_CPP_STRING_LST:
        case MATH_CPP_BOOL:
            return MATH_CPP_DTYPE_INVALID;

        default: // On left hand side all data types are supported for LIKE except above
            {
                switch (did2) {

                    case MATH_CPP_STRING:
                        return MATH_CPP_BOOL;
                    default:
                        return MATH_CPP_DTYPE_INVALID;
                }
            }
    }
}

MexprNode * 
OperatorLIKE::clone() {

    OperatorLIKE *obj = new OperatorLIKE();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}





/* AND Operator*/

OperatorAnd::OperatorAnd() {

    opid = MATH_CPP_AND;
    name = "and";
    is_unary = false;
}

OperatorAnd::~OperatorAnd() { }

Dtype* 
OperatorAnd::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    assert (dtype1->did == MATH_CPP_BOOL &&
               dtype2->did == MATH_CPP_BOOL);

    Dtype_BOOL *res = dynamic_cast <Dtype_BOOL *>( Dtype::factory (MATH_CPP_BOOL));
    res->dtype.b_val = false;

    Dtype_BOOL *dtype1_res = dynamic_cast <Dtype_BOOL *> (dtype1);
    Dtype_BOOL *dtype2_res = dynamic_cast <Dtype_BOOL *> (dtype2);

    res->dtype.b_val = dtype1_res->dtype.b_val && dtype2_res->dtype.b_val ;

    return res;
}

mexprcpp_dtypes_t 
OperatorAnd::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_BOOL:

            switch (did2) {

                case MATH_CPP_BOOL:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
            break;

        case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_BOOL:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

MexprNode * 
OperatorAnd::clone() {

    OperatorAnd *obj = new OperatorAnd();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}



/* OR Operator*/

OperatorOr::OperatorOr() {

    opid = MATH_CPP_OR;
    name = "or";
    is_unary = false;
}

OperatorOr::~OperatorOr() { }

Dtype* 
OperatorOr::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    assert (dtype1->did == MATH_CPP_BOOL &&
               dtype2->did == MATH_CPP_BOOL);

    Dtype_BOOL *res = dynamic_cast <Dtype_BOOL *>( Dtype::factory (MATH_CPP_BOOL));
    res->dtype.b_val = false;

    Dtype_BOOL *dtype1_res = dynamic_cast <Dtype_BOOL *> (dtype1);
    Dtype_BOOL *dtype2_res = dynamic_cast <Dtype_BOOL *> (dtype2);

    res->dtype.b_val = dtype1_res->dtype.b_val || dtype2_res->dtype.b_val ;

    return res;
}

mexprcpp_dtypes_t 
OperatorOr::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {

        case MATH_CPP_BOOL:

            switch (did2) {

                case MATH_CPP_BOOL:
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_BOOL;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
            break;

        case MATH_CPP_DTYPE_WILDCRAD:

            switch (did2) {

                case MATH_CPP_BOOL:
                    return MATH_CPP_BOOL;
                case MATH_CPP_DTYPE_WILDCRAD:
                    return MATH_CPP_DTYPE_WILDCRAD;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }

        default:
            return MATH_CPP_DTYPE_INVALID;
    }
}

MexprNode * 
OperatorOr::clone() {

    OperatorOr *obj = new OperatorOr();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}





/* Max Operator*/

OperatorMax::OperatorMax() {

    opid = MATH_CPP_MAX;
    name = "hmax";
    is_unary = false;
}

OperatorMax::~OperatorMax() { }

Dtype* 
OperatorMax::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_INT *Dtype_dtyp1_int = dynamic_cast<Dtype_INT *>(dtype1);
                    Dtype_INT *Dtype_dtyp2_int = dynamic_cast<Dtype_INT *>(dtype2);
                    int max =  Dtype_dtyp1_int->dtype.int_val < Dtype_dtyp2_int->dtype.int_val ? \
                                      Dtype_dtyp2_int->dtype.int_val : \
                                      Dtype_dtyp1_int->dtype.int_val;
                    Dtype_INT *res = dynamic_cast<Dtype_INT *> (Dtype::factory (MATH_CPP_INT));
                    res->dtype.int_val = max;
                    return res;
                }
                break;

                case MATH_CPP_DOUBLE:
                {
                    Dtype_INT *Dtype_dtyp1_int = dynamic_cast<Dtype_INT *>(dtype1);
                    Dtype_DOUBLE *Dtype_dtyp2_d = dynamic_cast<Dtype_DOUBLE *>(dtype2);
                    double max =  (double)Dtype_dtyp1_int->dtype.int_val < Dtype_dtyp2_d->dtype.d_val ? \
                                      Dtype_dtyp2_d->dtype.d_val : \
                                      (double)Dtype_dtyp1_int->dtype.int_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = max;
                    return res;                    
                }
                break;

                default:
                    return NULL;
            } 
        break;

        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_DOUBLE *Dtype_dtyp1_d = dynamic_cast<Dtype_DOUBLE *>(dtype1);
                    Dtype_INT *Dtype_dtyp2_int = dynamic_cast<Dtype_INT *>(dtype2);
                    double max =  Dtype_dtyp1_d->dtype.d_val < (double)Dtype_dtyp2_int->dtype.int_val ? \
                                             (double)Dtype_dtyp2_int->dtype.int_val : \
                                              Dtype_dtyp1_d->dtype.d_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = max;
                    return res;
                }
                break;


                case MATH_CPP_DOUBLE:
                {
                    Dtype_DOUBLE *Dtype_dtyp1_d = dynamic_cast<Dtype_DOUBLE *>(dtype1);
                    Dtype_DOUBLE *Dtype_dtyp2_d = dynamic_cast<Dtype_DOUBLE *>(dtype2);
                    double max =  Dtype_dtyp1_d->dtype.d_val < Dtype_dtyp2_d->dtype.d_val ? \
                                            Dtype_dtyp2_d->dtype.d_val : \
                                            Dtype_dtyp1_d->dtype.d_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = max;
                    return res;                    
                }
                break;

                default:
                    return NULL;
            } 
        break;

        case MATH_CPP_STRING:

            switch (dtype2->did) {

                case MATH_CPP_STRING:
                {
                    Dtype_STRING *Dtype_dtyp1_str = dynamic_cast<Dtype_STRING *>(dtype1);
                    Dtype_STRING *Dtype_dtyp2_str = dynamic_cast<Dtype_STRING *>(dtype2);                    
                    Dtype_STRING *res = dynamic_cast<Dtype_STRING *> (Dtype::factory (MATH_CPP_STRING));
                    res->dtype.str_val = Dtype_dtyp1_str->dtype.str_val.length() < Dtype_dtyp2_str->dtype.str_val.length() ?   \
                                                        Dtype_dtyp2_str->dtype.str_val :    \
                                                        Dtype_dtyp1_str->dtype.str_val;
                    return res;
                }
                break;
            }
        break;

        default:
            return NULL;
    }

    return NULL;
}

mexprcpp_dtypes_t 
OperatorMax::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {


        case MATH_CPP_INT:
        {
            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
        }
        break; 


        case MATH_CPP_DOUBLE:
        {

            switch (did2) {

                    case MATH_CPP_INT:
                    case MATH_CPP_DOUBLE:
                        return MATH_CPP_DOUBLE;
                    default:
                         return MATH_CPP_DTYPE_INVALID;
            }
        }
        break;


        case MATH_CPP_STRING:
        {
            switch (did2) {

                case MATH_CPP_STRING:
                    return MATH_CPP_STRING;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
        }
        break;

    }

    return MATH_CPP_DTYPE_INVALID;
}

MexprNode * 
OperatorMax::clone() {

    OperatorMax *obj = new OperatorMax();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




/* Min Operator*/

OperatorMin::OperatorMin() {

    opid = MATH_CPP_MIN;
    name = "hmin";
    is_unary = false;
}

OperatorMin::~OperatorMin() { }

Dtype* 
OperatorMin::compute(Dtype *dtype1, Dtype *dtype2) {

    if (this->is_optimized) {
        return dynamic_cast<Dtype *> (this->optimized_result->clone() );
    }

    switch (dtype1->did) {

        case MATH_CPP_INT:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_INT *Dtype_dtyp1_int = dynamic_cast<Dtype_INT *>(dtype1);
                    Dtype_INT *Dtype_dtyp2_int = dynamic_cast<Dtype_INT *>(dtype2);
                    int min =  Dtype_dtyp1_int->dtype.int_val > Dtype_dtyp2_int->dtype.int_val ? \
                                      Dtype_dtyp2_int->dtype.int_val : \
                                      Dtype_dtyp1_int->dtype.int_val;
                    Dtype_INT *res = dynamic_cast<Dtype_INT *> (Dtype::factory (MATH_CPP_INT));
                    res->dtype.int_val = min;
                    return res;
                }
                break;


                case MATH_CPP_DOUBLE:
                {
                    Dtype_INT *Dtype_dtyp1_int = dynamic_cast<Dtype_INT *>(dtype1);
                    Dtype_DOUBLE *Dtype_dtyp2_d = dynamic_cast<Dtype_DOUBLE *>(dtype2);
                    double min =  (double)Dtype_dtyp1_int->dtype.int_val > Dtype_dtyp2_d->dtype.d_val ? \
                                      Dtype_dtyp2_d->dtype.d_val : \
                                      (double)Dtype_dtyp1_int->dtype.int_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = min;
                    return res;                    
                }
                break;

                default:
                    return NULL;
            } 
        break;



        case MATH_CPP_DOUBLE:

            switch (dtype2->did) {

                case MATH_CPP_INT:
                {
                    Dtype_DOUBLE *Dtype_dtyp1_d = dynamic_cast<Dtype_DOUBLE *>(dtype1);
                    Dtype_INT *Dtype_dtyp2_int = dynamic_cast<Dtype_INT *>(dtype2);
                    double min =  Dtype_dtyp1_d->dtype.d_val > (double)Dtype_dtyp2_int->dtype.int_val ? \
                                             (double)Dtype_dtyp2_int->dtype.int_val : \
                                              Dtype_dtyp1_d->dtype.d_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = min;
                    return res;
                }
                break;


                case MATH_CPP_DOUBLE:
                {
                    Dtype_DOUBLE *Dtype_dtyp1_d = dynamic_cast<Dtype_DOUBLE *>(dtype1);
                    Dtype_DOUBLE *Dtype_dtyp2_d = dynamic_cast<Dtype_DOUBLE *>(dtype2);
                    double min =  Dtype_dtyp1_d->dtype.d_val > Dtype_dtyp2_d->dtype.d_val ? \
                                            Dtype_dtyp2_d->dtype.d_val : \
                                            Dtype_dtyp1_d->dtype.d_val;
                    Dtype_DOUBLE *res = dynamic_cast<Dtype_DOUBLE *> (Dtype::factory (MATH_CPP_DOUBLE));
                    res->dtype.d_val = min;
                    return res;                    
                }
                break;

                default:
                    return NULL;
            } 
        break;


        case MATH_CPP_STRING:

            switch (dtype2->did) {

                case MATH_CPP_STRING:
                {
                    Dtype_STRING *Dtype_dtyp1_str = dynamic_cast<Dtype_STRING *>(dtype1);
                    Dtype_STRING *Dtype_dtyp2_str = dynamic_cast<Dtype_STRING *>(dtype2);                    
                    Dtype_STRING *res = dynamic_cast<Dtype_STRING *> (Dtype::factory (MATH_CPP_STRING));
                    res->dtype.str_val = Dtype_dtyp1_str->dtype.str_val.length() > Dtype_dtyp2_str->dtype.str_val.length() ?   \
                                                        Dtype_dtyp2_str->dtype.str_val :    \
                                                        Dtype_dtyp1_str->dtype.str_val;
                    return res;
                }
                break;
            }
        break;

        default:
            return NULL;

    }

    return NULL;
}

mexprcpp_dtypes_t 
OperatorMin::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_optimized) {
        return this->optimized_result->did;
    }

    switch (did1) {


        case MATH_CPP_INT:
        {
            switch (did2) {

                case MATH_CPP_INT:
                    return MATH_CPP_INT;
                case MATH_CPP_DOUBLE:
                    return MATH_CPP_DOUBLE;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
        }
        break; 


        case MATH_CPP_DOUBLE:
        {

            switch (did2) {

                    case MATH_CPP_INT:
                    case MATH_CPP_DOUBLE:
                        return MATH_CPP_DOUBLE;
                    default:
                         return MATH_CPP_DTYPE_INVALID;
            }
        }
        break;


        case MATH_CPP_STRING:
        {
            switch (did2) {

                case MATH_CPP_STRING:
                    return MATH_CPP_STRING;
                default:
                    return MATH_CPP_DTYPE_INVALID;
            }
        }
        break;

    }

    return MATH_CPP_DTYPE_INVALID;
}

MexprNode * 
OperatorMin::clone() {

    OperatorMin *obj = new OperatorMin();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}




Operator* 
Operator::factory (mexprcpp_operators_t opr_code) {

    switch (opr_code) {

        case MATH_CPP_MOD:
            return new OperatorMod();
        case MATH_CPP_PLUS:
            return new OperatorPlus();
        case MATH_CPP_MINUS:
            return new OperatorMinus();
        case MATH_CPP_MUL:
            return new OperatorMul();
        case MATH_CPP_DIV:
            return new OperatorDiv();
        case MATH_CPP_EQ:
            return new OperatorEq();
        case MATH_CPP_NEQ:
            return new OperatorNeq();
        case MATH_CPP_LESS_THAN:
            return new OperatorLessThan();
        case MATH_CPP_GREATER_THAN:
            return new OperatorGreaterThan();
        case MATH_CPP_IN:
            return new OperatorIn();
        case MATH_CPP_LIKE:
            return new OperatorLIKE();
        case MATH_CPP_OR:
            return new OperatorOr();
        case MATH_CPP_AND:
            return new OperatorAnd();
        case MATH_CPP_SQR:
            return new OperatorSqr();
        case MATH_CPP_SQRT:
            return new OperatorSqrt();           
        case MATH_CPP_MAX:
            return new OperatorMax();
        case MATH_CPP_MIN:
            return new OperatorMin(); 
        default:
            return NULL;
    }
    return NULL;
}

