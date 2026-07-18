#ifndef __DTYPE__
#define __DTYPE__

#include <stdint.h>
#include <string>
#include <list>
#include <stdbool.h>
#include "MexprTree.h"
#include "MExprcppEnums.h"

class Dtype_STRING;

class Dtype : public MexprNode {

protected:
    Dtype();

public:
    bool is_resolved;
    mexprcpp_dtypes_t did;
    bool unresolvable;
    
    virtual ~Dtype();
    static Dtype * factory(mexprcpp_dtypes_t did);
    virtual Dtype *compute(Dtype *dtype1, Dtype *dtype2) =0;
    virtual mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) ;
    virtual MexprNode * clone() = 0;
    virtual void SetValue(void *value) = 0;
    virtual void SetValue(Dtype *) = 0;
    virtual int serialize(void *mem) = 0;
    virtual Dtype_STRING *toString() = 0;
    /* Operator overloading*/
    virtual bool operator< (Dtype& ) ;
    virtual void operator+= (Dtype& ) ;
};


/* Dtype : Dtype_IPv4_addr*/ 

class Dtype_IPv4_addr : public Dtype {

public:
    
    struct {
        std::string ip_addr_str;
        uint32_t ipaddr_int;
    } dtype;

    Dtype_IPv4_addr();
    ~Dtype_IPv4_addr();
    Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
    MexprNode * clone() override;
    void SetValue(void *value) override;
    virtual void SetValue(Dtype *) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    virtual int serialize(void *mem) override;
    virtual Dtype_STRING *toString() override;
};


/* Dtype : Dtype_INT*/ 

class Dtype_INT : public Dtype {

public:
    
    struct {
        int int_val;
    } dtype;

    Dtype_INT();
    Dtype_INT(int val);
    ~Dtype_INT();
    Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
    MexprNode * clone() override;
    void SetValue(void *value) override;
    virtual void SetValue(Dtype *) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    virtual int serialize(void *mem) override;
    virtual Dtype_STRING *toString() override;
    virtual bool operator< (Dtype& ) override;
    virtual void operator+= (Dtype& ) override;
};


/* Dtype : Dtype_DOUBLE*/ 


class Dtype_DOUBLE : public Dtype {

public:
    
    struct {
        double d_val;
    } dtype;

    Dtype_DOUBLE();
    ~Dtype_DOUBLE();
    Dtype_DOUBLE(double val);
    Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
    MexprNode * clone() override;
    void SetValue(void *value) override;
    virtual void SetValue(Dtype *) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    virtual int serialize(void *mem) override;
    virtual Dtype_STRING *toString() override;
    virtual bool operator< (Dtype& ) override;
    virtual void operator+= (Dtype&) override;
};


/* Dtype : Dtype_STRING*/
 
class Dtype_STRING : public Dtype {

public:
    
    struct {
        std::string str_val;
    } dtype;

    Dtype_STRING();
    ~Dtype_STRING();
    Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
    MexprNode * clone() override;
    void SetValue(void *value) override;
    void SetValue(std::string *string_ptr);
    virtual void SetValue(Dtype *) override;
    mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
    virtual int serialize(void *mem) override;
    virtual Dtype_STRING *toString() override;
    virtual bool operator< (Dtype&) override;
    virtual void operator+= (Dtype&) override;
};


/* Dtype : Dtype_WILDCARD*/

class Dtype_WILDCARD : public Dtype {

    public:
        Dtype_WILDCARD();
        ~Dtype_WILDCARD();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};



/* Dtype : Dtype_BOOL*/

class Dtype_BOOL : public Dtype {

    public:

        struct {
            bool b_val;
        } dtype;

        Dtype_BOOL();
        ~Dtype_BOOL();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};




/* Dtype : Dtype_INVALID*/

class Dtype_INVALID : public Dtype {

    public:
        Dtype_INVALID();
        ~Dtype_INVALID();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};



/* Dtype : Dtype_VARIABLE*/

class Dtype_VARIABLE : public Dtype {

    public:
        struct {
            std::string variable_name;
        } dtype;
        void *data_src;
        Dtype *(*compute_fn_ptr)(void *);
        mexprcpp_dtypes_t resolved_did;

        Dtype_VARIABLE(std::string var_name);
        Dtype_VARIABLE();
        ~Dtype_VARIABLE();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void  ResolveOperand (
                mexprcpp_dtypes_t resolved_did,
                void *data_src,
                Dtype *(*compute_fn_ptr)(void *)) ;

        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};


/* Dtype : Dtype_STRING_LST*/

class Dtype_STRING_LST : public Dtype {

    public:

        struct {
            std::list<Dtype_STRING *> str_lst;
        } dtype;
        
        Dtype_STRING_LST();
        ~Dtype_STRING_LST();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};


/* Dtype : Dtype_INTERVAL */

class Dtype_INTERVAL : public Dtype {

    public:

        struct {
           int lb;
           int ub;
        } dtype;
        
        Dtype_INTERVAL();
        ~Dtype_INTERVAL();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};




template <class T>
class Dtype_LIST_TEMPLATE : public Dtype {

    public:

        struct {

            std::list <T * > str_lst;
        } dtype;

        Dtype_LIST_TEMPLATE(mexprcpp_dtypes_t did);
        ~Dtype_LIST_TEMPLATE();
        Dtype *compute(Dtype *dtype1, Dtype *dtype2) override;
        MexprNode * clone() override;
        void SetValue(void *value) override;
        virtual void SetValue(Dtype *) override;
        mexprcpp_dtypes_t ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) override;
        virtual int serialize(void *mem) override;
        virtual Dtype_STRING *toString() override;
};

template <class T>
 Dtype_LIST_TEMPLATE<T>::Dtype_LIST_TEMPLATE(mexprcpp_dtypes_t did) {

    this->did = did;
    is_resolved = true;
    dtype.str_lst = NULL;
 }

 template <class T>
 Dtype_LIST_TEMPLATE<T>::~Dtype_LIST_TEMPLATE() {}

 template <class T>
 Dtype *
 Dtype_LIST_TEMPLATE<T>::compute (Dtype *dtype1, Dtype *dtype2)  {

    return this;
 };

template <class T>
MexprNode * 
Dtype_LIST_TEMPLATE<T>::clone() {

    T *elem ;

    Dtype_LIST_TEMPLATE<T> *obj = new Dtype_LIST_TEMPLATE<T>();
    
    for (typename std::list <T *>::iterator it = this->dtype.str_lst.begin();     
            it != this->dtype.str_lst.end(); ++it ) {

        elem = *it;

        T *clone_elem = elem->clone ();

        obj->dtype.str_lst.push_back (clone_elem);
    }

    return obj;
 };


template <class T>
void 
Dtype_LIST_TEMPLATE<T>::SetValue(void *value) {


}

template <class T>
void 
Dtype_LIST_TEMPLATE<T>::SetValue(Dtype *value) {


}


template <class T>
 mexprcpp_dtypes_t 
 Dtype_LIST_TEMPLATE<T>::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_DTYPE_INVALID;
 }

template <class T> 
int  
Dtype_LIST_TEMPLATE<T>::serialize(void *mem) { return 0;}



template <class T>
Dtype_STRING *
Dtype_LIST_TEMPLATE<T>::toString() { return NULL ; }


#endif 