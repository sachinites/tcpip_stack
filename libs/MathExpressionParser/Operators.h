#ifndef __OPERATORS__
#define __OPERATORS__

#include <stdbool.h>
#include "MexprTree.h"
#include "MExprcppEnums.h"

class Operator : public MexprNode {

private:
    
protected:
    Operator();
    virtual ~Operator();
public:
    int opid;
    std::string name;
    bool is_unary;
    bool is_optimized;
    Dtype *optimized_result;
   virtual Dtype* compute(Dtype *dtype1, Dtype *dtype2) = 0;
   virtual mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) = 0;
   virtual MexprNode * clone() = 0;
   static Operator* factory (mexprcpp_operators_t opr_code);
};


/* MOD operator */

class OperatorMod : public Operator {

private:

public:
     OperatorMod();
     ~OperatorMod();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};


/* PLUS operator */

class OperatorPlus : public Operator {

private:

public:
    OperatorPlus();
     ~OperatorPlus();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};



/* MINUS operator */

class OperatorMinus : public Operator {

private:

public:
    OperatorMinus();
    ~OperatorMinus();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};


/* MUL operator */

class OperatorMul : public Operator {

private:

public:
    OperatorMul();
    ~OperatorMul();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};


/* DIV operator */

class OperatorDiv : public Operator {

private:

public:
    OperatorDiv();
    ~OperatorDiv();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};


/* Sqr operator */

class OperatorSqr : public Operator {

private:

public:
    OperatorSqr();
    ~OperatorSqr();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};


/* Sqrt operator */

class OperatorSqrt : public Operator {

private:

public:
    OperatorSqrt();
    ~OperatorSqrt();
    Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    MexprNode * clone() override;
};




/* EQ operator */

class OperatorEq : public Operator {

    private:

    public:
        OperatorEq();
        ~OperatorEq();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};


/* NOT-EQ operator */

class OperatorNeq : public Operator {

    private:

    public:
        OperatorNeq();
        ~OperatorNeq();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};


/* LessThan operator */

class OperatorLessThan : public Operator {

    private:

    public:
        OperatorLessThan();
        ~OperatorLessThan();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};


/* GreaterThan operator */

class OperatorGreaterThan : public Operator {

    private:

    public:
        OperatorGreaterThan();
        ~OperatorGreaterThan();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};




/* IN Operator*/

class OperatorIn : public Operator {

    private:

    public:
        OperatorIn();
        ~OperatorIn();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};



/* LIKE Operator*/

class OperatorLIKE : public Operator {

    private:

    public:
        OperatorLIKE();
        ~OperatorLIKE();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};



/* And Operator*/

class OperatorAnd : public Operator {

    private:

    public:
        OperatorAnd();
        ~OperatorAnd();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};



/* Or Operator*/

class OperatorOr : public Operator {

    private:

    public:
        OperatorOr();
        ~OperatorOr();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};



/* Max Operator*/

class OperatorMax : public Operator {

    private:

    public:
        OperatorMax();
        ~OperatorMax();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};


/* Min Operator*/

class OperatorMin : public Operator {

    private:

    public:
        OperatorMin();
        ~OperatorMin();
        Dtype* compute(Dtype *dtype1, Dtype *dtype2) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        MexprNode * clone() override;
};



#endif 