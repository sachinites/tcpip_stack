#include <cstddef>
#include <assert.h>
#include <arpa/inet.h>
#include <algorithm>
#include <list>
#include <memory.h>
#include "Dtype.h"

class MexprNode;
class Dtype_STRING;

Dtype::Dtype() {

    this->did = MATH_CPP_DTYPE_INVALID;
    this->is_resolved = false;
    unresolvable = false;
} 

Dtype::~Dtype() {}

mexprcpp_dtypes_t 
Dtype::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return this->did;
}

bool
Dtype::operator< (Dtype& new_data)  {

    printf ("Order by on this Expression is not supported\n");
    return false;
}

void
Dtype::operator+= (Dtype& new_data) {

    assert(0);
}







/* Dtype_INT */

Dtype_INT::Dtype_INT() {

    did = MATH_CPP_INT;
    this->is_resolved = true;
    this->dtype.int_val = 0;
}

Dtype_INT::~Dtype_INT() {

}

 Dtype_INT::Dtype_INT(int val) {

        this->did = MATH_CPP_INT;
        this->dtype.int_val = val;
        this->is_resolved = true;
 }

Dtype *
Dtype_INT::compute(Dtype *dtype1, Dtype *dtype2) {

        return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_INT::clone() {

    Dtype_INT *obj = new Dtype_INT();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_INT::SetValue(void *value) {

    int val = atoi ( (const char *) value);
    this->dtype.int_val = val;
    this->is_resolved = true;
}

void 
Dtype_INT::SetValue(Dtype *value) {

    this->dtype.int_val = dynamic_cast <Dtype_INT *> (value)->dtype.int_val;
    this->is_resolved = true;
}

mexprcpp_dtypes_t 
Dtype_INT::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_INT;
}

int 
Dtype_INT::serialize(void *mem) {

    memcpy (mem, &this->dtype.int_val, sizeof (this->dtype.int_val));
    return sizeof (this->dtype.int_val);
}

Dtype_STRING *
Dtype_INT::toString () {

    int val = this->dtype.int_val;
    
    Dtype_STRING *stringify = dynamic_cast<Dtype_STRING *> (Dtype::factory(MATH_CPP_STRING));
    stringify->dtype.str_val = std::to_string (val);
    stringify->is_resolved = true;
    return stringify;
}

bool
Dtype_INT::operator< (Dtype& new_data)  {

    Dtype_INT *data = dynamic_cast <Dtype_INT *> (&new_data);
    return this->dtype.int_val < data->dtype.int_val;
}

void
Dtype_INT::operator+= (Dtype&  new_data) {

    Dtype_INT *data = dynamic_cast <Dtype_INT *> (&new_data);
    this->dtype.int_val += data->dtype.int_val ;
}





/* Dtype_DOUBLE */

Dtype_DOUBLE::Dtype_DOUBLE() {

    did = MATH_CPP_DOUBLE;
    this->is_resolved = true;
}

 Dtype_DOUBLE::Dtype_DOUBLE(double val) {

        this->did = MATH_CPP_DOUBLE;
        this->dtype.d_val = val;
        this->is_resolved = true;
 }


Dtype_DOUBLE::~Dtype_DOUBLE() {

}

Dtype *
Dtype_DOUBLE::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_DOUBLE::clone() {

    Dtype_DOUBLE *obj = new Dtype_DOUBLE();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_DOUBLE::SetValue(void *value) {

    double val = (double)atof ( (const char *) value);
    this->dtype.d_val = val;
    this->is_resolved = true;
}

void 
Dtype_DOUBLE::SetValue(Dtype *value) {

    this->dtype.d_val = dynamic_cast <Dtype_DOUBLE *> (value)->dtype.d_val;
    this->is_resolved = true;
}

mexprcpp_dtypes_t 
Dtype_DOUBLE::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_DOUBLE;
}

int 
Dtype_DOUBLE::serialize(void *mem) {

    memcpy (mem, &this->dtype.d_val, sizeof (this->dtype.d_val));
    return sizeof (this->dtype.d_val);
}

Dtype_STRING *
Dtype_DOUBLE::toString () {

    double val = this->dtype.d_val;

    Dtype_STRING *stringify = dynamic_cast<Dtype_STRING *> (Dtype::factory(MATH_CPP_STRING));
    stringify->dtype.str_val = std::to_string (val);
    stringify->is_resolved = true;
    return stringify;
}

bool
Dtype_DOUBLE::operator< (Dtype& new_data)  {

    Dtype_DOUBLE *data = dynamic_cast <Dtype_DOUBLE *> (&new_data);
    return this->dtype.d_val < data->dtype.d_val;
}

void
Dtype_DOUBLE::operator+= (Dtype& new_data) {

    Dtype_DOUBLE *data = dynamic_cast <Dtype_DOUBLE *> (&new_data);
    this->dtype.d_val += data->dtype.d_val ;
}




/* Dtype_STRING */

Dtype_STRING::Dtype_STRING() {

    did = MATH_CPP_STRING;
    this->is_resolved = true;
}

Dtype_STRING::~Dtype_STRING() {

}

Dtype *
Dtype_STRING::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_STRING::clone() {

    Dtype_STRING *obj = new Dtype_STRING();
    obj->dtype.str_val = this->dtype.str_val;
    obj->flags = this->flags;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_STRING::SetValue(void *value) {

    this->dtype.str_val.assign(std::string ((char *)value));
    
    this->dtype.str_val.erase(
            std::remove(this->dtype.str_val.begin(), this->dtype.str_val.end(), '\"'), 
            this->dtype.str_val.end());
    this->dtype.str_val.erase(
            std::remove(this->dtype.str_val.begin(), this->dtype.str_val.end(), '\''), 
            this->dtype.str_val.end());
    this->is_resolved = true;
}

void 
Dtype_STRING::SetValue(Dtype *value) {

    Dtype_STRING *value_str = dynamic_cast<Dtype_STRING *> (value);
    this->SetValue (&value_str->dtype.str_val);
}

void 
Dtype_STRING::SetValue(std::string *string_ptr) {

    this->dtype.str_val.assign(*string_ptr);
    
    this->dtype.str_val.erase(
            std::remove(this->dtype.str_val.begin(), this->dtype.str_val.end(), '\"'), 
            this->dtype.str_val.end());
    this->dtype.str_val.erase(
            std::remove(this->dtype.str_val.begin(), this->dtype.str_val.end(), '\''), 
            this->dtype.str_val.end());
    this->is_resolved = true;
}

mexprcpp_dtypes_t 
Dtype_STRING::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_STRING;
}

int 
Dtype_STRING::serialize(void *mem) {

    memcpy (mem, this->dtype.str_val.c_str(), this->dtype.str_val.length());
    return this->dtype.str_val.length();
}

Dtype_STRING *
Dtype_STRING::toString () {

    return dynamic_cast<Dtype_STRING *> (this->clone());
}

bool
Dtype_STRING::operator< (Dtype& new_data)  {

    Dtype_STRING *data = dynamic_cast <Dtype_STRING *> (&new_data);
    return this->dtype.str_val < data->dtype.str_val;
}

void
Dtype_STRING::operator+= (Dtype& new_data) {

    Dtype_STRING *data = dynamic_cast <Dtype_STRING *> (&new_data);
    this->dtype.str_val.append(data->dtype.str_val) ;
}





/* Dtype : Dtype_IPv4_addr */

Dtype_IPv4_addr::Dtype_IPv4_addr() {

    did = MATH_CPP_IPV4;
    dtype.ip_addr_str = "";
    dtype.ipaddr_int = 0;
    this->is_resolved = true;
}

Dtype_IPv4_addr::~Dtype_IPv4_addr() {

}

Dtype *
Dtype_IPv4_addr::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_IPv4_addr::clone() {

    Dtype_IPv4_addr *obj = new Dtype_IPv4_addr();
    *obj = *this; 
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_IPv4_addr::SetValue(void *value) {

    this->dtype.ip_addr_str.assign (std::string ((char *)value));
    inet_pton (AF_INET, (const char *)value, &this->dtype.ipaddr_int);
    this->is_resolved = true;
}

void 
Dtype_IPv4_addr::SetValue(Dtype *value) {

    Dtype_IPv4_addr *value_d = dynamic_cast <Dtype_IPv4_addr *> (value);
    this->dtype.ip_addr_str.assign (value_d->dtype.ip_addr_str);
    this->dtype.ipaddr_int = value_d->dtype.ipaddr_int;
    this->is_resolved = true;
}


mexprcpp_dtypes_t 
Dtype_IPv4_addr::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_IPV4;
}

int 
Dtype_IPv4_addr::serialize(void *mem) {

    memcpy (mem, &this->dtype.ipaddr_int, sizeof (this->dtype.ipaddr_int));
    return sizeof (this->dtype.ipaddr_int);
}

Dtype_STRING *
Dtype_IPv4_addr::toString () {

    Dtype_STRING *stringify = 
        dynamic_cast<Dtype_STRING *> (Dtype::factory(MATH_CPP_STRING));

    stringify->dtype.str_val = this->dtype.ip_addr_str;
    return stringify;
}




/* Dtype : Dtype_BOOL */

Dtype_BOOL::Dtype_BOOL () {

    did = MATH_CPP_BOOL;
    this->dtype.b_val = false;
    this->is_resolved = true;
}

Dtype_BOOL::~Dtype_BOOL() {

}

Dtype *
Dtype_BOOL::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_BOOL::clone() {

    Dtype_BOOL *obj = new Dtype_BOOL();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_BOOL::SetValue (void *_value) {

    char *value = (char *)_value;
    if (value[0] == 't' || value[0] == 'T' ) {
        this->dtype.b_val = true;
    }
    else {
        this->dtype.b_val = false;
    }
    this->is_resolved = true;
}

void 
Dtype_BOOL::SetValue(Dtype *value) {

    Dtype_BOOL *value_d = dynamic_cast <Dtype_BOOL *> (value);
    this->dtype.b_val = value_d->dtype.b_val;
    this->is_resolved = true;
}


mexprcpp_dtypes_t 
Dtype_BOOL::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_BOOL;
}

int 
Dtype_BOOL::serialize(void *mem) {

    uint8_t val = this->dtype.b_val == true ? 1 : 0;
    memcpy (mem, &val, 1);
    return 1;
}

Dtype_STRING *
Dtype_BOOL::toString () {

    return NULL;
}







/* Dtype : Dtype_WILDCARD */

Dtype_WILDCARD::Dtype_WILDCARD() {

    did = MATH_CPP_DTYPE_WILDCRAD;
    is_resolved = true;
}

Dtype_WILDCARD::~Dtype_WILDCARD() {

}

Dtype *
Dtype_WILDCARD::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_WILDCARD::clone() {

    Dtype_WILDCARD *obj = new Dtype_WILDCARD();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_WILDCARD::SetValue (void *value) {

}
void 
Dtype_WILDCARD::SetValue (Dtype *value) {

}

mexprcpp_dtypes_t 
Dtype_WILDCARD::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_DTYPE_WILDCRAD;
}

int 
Dtype_WILDCARD::serialize(void *mem) {

    return 0;
}

Dtype_STRING *
Dtype_WILDCARD::toString () {

    return NULL;
}





/* Dtype : Dtype_INVALID */

Dtype_INVALID::Dtype_INVALID() {

    did = MATH_CPP_DTYPE_INVALID;
    is_resolved = true;
}

Dtype_INVALID::~Dtype_INVALID() {

}

Dtype *
Dtype_INVALID::compute(Dtype *dtype1, Dtype *dtype2) {

    return NULL;
}

MexprNode * 
Dtype_INVALID::clone() {

    Dtype_INVALID *obj = new Dtype_INVALID();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_INVALID::SetValue (void *value) {

}

void 
Dtype_INVALID::SetValue (Dtype *value) {

}

mexprcpp_dtypes_t 
Dtype_INVALID::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_DTYPE_INVALID;
}

int 
Dtype_INVALID::serialize(void *mem) {

    return 0;
}

Dtype_STRING *
Dtype_INVALID::toString () {

    return NULL;
}




/* Dtype : Dtype_VARIABLE*/

Dtype_VARIABLE::Dtype_VARIABLE(std::string var_name) {

    did = MATH_CPP_VARIABLE;
    this->dtype.variable_name.assign(var_name);
    this->is_resolved = false;
    this->resolved_did = MATH_CPP_DTYPE_WILDCRAD;
}

Dtype_VARIABLE::Dtype_VARIABLE() {

    did = MATH_CPP_VARIABLE;
    this->dtype.variable_name.assign("");
    this->is_resolved = false;
    this->resolved_did = MATH_CPP_DTYPE_WILDCRAD;
}

Dtype_VARIABLE::~Dtype_VARIABLE() {

}

Dtype *
Dtype_VARIABLE::compute(Dtype *dtype1, Dtype *dtype2) {

   if (!this->is_resolved)  return NULL;
    Dtype *res =  this->compute_fn_ptr(this->data_src);
    return res;
}

MexprNode * 
Dtype_VARIABLE::clone() {

    Dtype_VARIABLE *obj = new Dtype_VARIABLE(this->dtype.variable_name);
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void  
Dtype_VARIABLE::ResolveOperand (
                mexprcpp_dtypes_t resolved_did,
                void *data_src,
                Dtype *(*compute_fn_ptr)(void *))  {

    assert (!this->is_resolved);
    this->data_src = data_src;
    this->compute_fn_ptr = compute_fn_ptr;
    this->is_resolved = true;
    this->resolved_did = resolved_did;
}

void 
Dtype_VARIABLE::SetValue (void *value) {

}
void 
Dtype_VARIABLE::SetValue (Dtype *value) {

}

mexprcpp_dtypes_t 
Dtype_VARIABLE::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    if (this->is_resolved) return this->resolved_did;
    return MATH_CPP_DTYPE_WILDCRAD;
}

int 
Dtype_VARIABLE::serialize(void *mem) {

    return 0;
}

Dtype_STRING *
Dtype_VARIABLE::toString () {

    return NULL;
}





/* Dtype : Dtype_STRING_LST*/

Dtype_STRING_LST::Dtype_STRING_LST() {

    this->did = MATH_CPP_STRING_LST;
    this->is_resolved = true;
}

Dtype_STRING_LST::~Dtype_STRING_LST() {

    Dtype_STRING *elem;

    while (!this->dtype.str_lst.empty()) {

        elem = this->dtype.str_lst.front();
        this->dtype.str_lst.pop_front();
        delete elem;
    }
}

Dtype *
Dtype_STRING_LST::compute(Dtype *dtype1, Dtype *dtype2) {

    return dynamic_cast <Dtype *>(clone() );
}

MexprNode * 
Dtype_STRING_LST::clone() {
    
    Dtype_STRING *elem;
    Dtype_STRING_LST *cpy_list_dst = new Dtype_STRING_LST();

    cpy_list_dst->flags = this->flags;

    for (std::list<Dtype_STRING *>::iterator it = this->dtype.str_lst.begin(); 
            it != this->dtype.str_lst.end(); ++it) {

            elem = *it;
            cpy_list_dst->dtype.str_lst.push_back(
                   dynamic_cast <Dtype_STRING *> (elem->clone()));
    } 

    return cpy_list_dst ;
}

void
Dtype_STRING_LST::SetValue(void *value) {

    std::string *str_ptr;
    Dtype_STRING *dtype_str;

    std::list<std::string *> *str_lst_ptr = reinterpret_cast <std::list<std::string *> *> (value);

    for (std::list<std::string *>::iterator it = str_lst_ptr->begin(); 
            it != str_lst_ptr->end(); ++it) {

        str_ptr = *it;
        dtype_str = new Dtype_STRING();
        dtype_str->SetValue (str_ptr);
        this->dtype.str_lst.push_back (dtype_str);
    }
    this->is_resolved = true;
}

void
Dtype_STRING_LST::SetValue(Dtype *value) {

    std::string *str_ptr;
    Dtype_STRING *dtype_str;
    Dtype_STRING *dtype_str_clone;

    Dtype_STRING_LST *value_d = dynamic_cast<Dtype_STRING_LST *>(value);

    std::list<Dtype_STRING *> *str_lst_ptr = &value_d->dtype.str_lst;

    for (std::list<Dtype_STRING *>::iterator it = str_lst_ptr->begin(); 
            it != str_lst_ptr->end(); ++it) {

        dtype_str = *it;
        dtype_str_clone = reinterpret_cast<Dtype_STRING *> (dtype_str->clone());
        this->dtype.str_lst.push_back (dtype_str_clone);
    }    
     this->is_resolved = true;
}


mexprcpp_dtypes_t 
Dtype_STRING_LST::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_STRING_LST;
}


int
Dtype_STRING_LST::serialize(void *mem) {

    int offset = 0;
    Dtype_STRING *dtype_str;

    for (std::list<Dtype_STRING *>::iterator it = this->dtype.str_lst.begin(); 
            it != this->dtype.str_lst.end(); ++it) {

            dtype_str = *it;
            offset += dtype_str->serialize ((void *)((char *)mem + offset));
    } 

    return offset;
}

Dtype_STRING *
Dtype_STRING_LST::toString () {

    return NULL;
}



 Dtype_INTERVAL:: Dtype_INTERVAL() 
 {
    this->did = MATH_CPP_INTERVAL;
    this->dtype.lb = 0;
    this->dtype.ub = 0;
    this->is_resolved = true;
}

 Dtype_INTERVAL::~Dtype_INTERVAL() { }

 Dtype *
Dtype_INTERVAL::compute(Dtype *dtype1, Dtype *dtype2) {

     return dynamic_cast <Dtype *>(clone() );
 }

MexprNode * 
Dtype_INTERVAL::clone() {

    Dtype_INTERVAL *obj = new Dtype_INTERVAL();
    *obj = *this;
    obj->parent = NULL;
    obj->left = NULL;
    obj->right = NULL;
    obj->lst_left = NULL;
    obj->lst_right = NULL;
    return obj;
}

void 
Dtype_INTERVAL::SetValue(void *value) {

    std::list<int32_t> *int_lst_ptr = reinterpret_cast <std::list<int32_t> *>(value);
    this->dtype.lb = int_lst_ptr->front();
    this->dtype.ub = int_lst_ptr->back();
     this->is_resolved = true;
}

void 
Dtype_INTERVAL::SetValue(Dtype *value) {

    Dtype_INTERVAL *value_interval = dynamic_cast <Dtype_INTERVAL *>(value);
    this->dtype.lb = value_interval->dtype.lb;
    this->dtype.ub = value_interval->dtype.ub;
     this->is_resolved = true;
}

mexprcpp_dtypes_t 
Dtype_INTERVAL::ResultStorageType(mexprcpp_dtypes_t did1, mexprcpp_dtypes_t did2) {

    return MATH_CPP_INTERVAL;
}

 int
Dtype_INTERVAL::serialize(void *mem) {

    int rc = 0;
    memcpy ( (char *)mem + rc, &this->dtype.lb, sizeof ( this->dtype.lb));
    rc += sizeof ( this->dtype.lb);
    memcpy ( (char *)mem + rc, &this->dtype.ub, sizeof ( this->dtype.ub));
    rc += sizeof ( this->dtype.ub);
    return rc;
 }


Dtype_STRING *
Dtype_INTERVAL::toString() {

    Dtype_STRING * rc = new Dtype_STRING();
    rc->dtype.str_val = "[" + std::to_string(this->dtype.lb) + "," + std::to_string(this->dtype.ub) + "]"; 
    return rc;
}


Dtype * 
Dtype::factory(mexprcpp_dtypes_t did) {

    switch (did) {

        case MATH_CPP_INT:
            return new Dtype_INT();
        case MATH_CPP_DOUBLE:
            return new Dtype_DOUBLE();
        case MATH_CPP_STRING:
            return new Dtype_STRING();
        case MATH_CPP_BOOL:
            return new Dtype_BOOL();
        case MATH_CPP_IPV4:
            return new Dtype_IPv4_addr();
        case MATH_CPP_VARIABLE:
            return new Dtype_VARIABLE();
        case MATH_CPP_STRING_LST:
            return new Dtype_STRING_LST();
        case MATH_CPP_INTERVAL:
            return new Dtype_INTERVAL();
        case MATH_CPP_DTYPE_WILDCRAD:
            return new Dtype_WILDCARD();
        case MATH_CPP_DTYPE_INVALID:
            return new Dtype_INVALID();
        case MATH_CPP_DTYPE_MAX:
            return NULL;
        default:
            assert(0);
    }
    return NULL;
}
