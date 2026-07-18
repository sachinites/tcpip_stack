#ifndef __SQL_ENUMS__
#define __SQL_ENUMS__

typedef enum sql_entity_ {

    SQL_IDENTIFIER, 
    SQL_IDENTIFIER_IDENTIFIER,
    SQL_QUERY_TYPE,
    SQL_AGG_FN,
    SQL_KEYWORD ,
    SQL_OPERATOR,
    SQL_DTYPE,
    SQL_ENTITY_MAX
    
} sql_entity_type_t;

typedef enum sql_query_type_{

    SQL_SELECT_Q = SQL_ENTITY_MAX + 1,
    SQL_UPDATE_Q ,
    SQL_CREATE_Q,
    SQL_DELETE_Q,
    SQL_INSERT_Q ,
    SQL_DROP_TABLE_Q,
    SQL_SHOW_CATALOG_Q,
    SQL_UNSUPPORTED_Q

} sql_query_type_t;

typedef enum sql_agg_fn_ {

    SQL_SUM = SQL_UNSUPPORTED_Q + 1,
    SQL_MIN,
    SQL_MAX,
    SQL_COUNT,
    SQL_AVG,
    SQL_AGG_FN_NONE
 
} sql_agg_fn_t;

typedef enum sql_keywords_ {

    SQL_FROM = SQL_AGG_FN_NONE + 1 ,
    SQL_WHERE,
    SQL_GROUP_BY,
    SQL_HAVING,
    SQL_ORDER_BY,
    SQL_LIMIT,
    SQL_PRIMARY_KEY,
    SQL_NOT_NULL,
    SQL_SELECT,
    SQL_AS,
    SQL_SET,
    SQL_KEYWORD_MAX
    
} sql_keywords_t;

typedef enum sql_op_ {

    SQL_LESS_THAN = SQL_KEYWORD_MAX + 1 ,
    SQL_LESS_THAN_EQ,
    SQL_GREATER_THAN, 
    SQL_EQ, 
    SQL_NOT_EQ,
    SQL_AND,
    SQL_OR,
    SQL_GREATER_THAN_EQ,
    SQL_NOT,
    SQL_IN,
    SQL_LIKE,
    SQL_BETWEEN, 
    SQL_OP_MAX

} sql_op_t;

typedef enum sql_dtype_{

    SQL_DTYPE_FIRST = SQL_OP_MAX + 1,
    SQL_STRING,
    SQL_INT,
    SQL_DOUBLE,
    SQL_BOOL,
    SQL_IPV4_ADDR,
    SQL_INTERVAL,
    SQL_DTYPE_MAX

} sql_dtype_t;

typedef enum sql_dtype_attr_ {

    SQL_DTYPE_LEN = SQL_DTYPE_MAX + 1,
    SQL_DTYE_ATTR_MAX

} sql_dtype_attr_t;

typedef enum sql_ident_type_ {

    SQL_INTEGER_VALUE =  SQL_DTYE_ATTR_MAX + 1,
    SQL_STRING_VALUE,
    SQL_DOUBLE_VALUE,
    SQL_IPV4_ADDR_VALUE,
    SQL_INTERVAL_VALUE,
    SQL_IDNT_TYPE_MAX

} sql_identifier_type_t;


/* Math Functions */
typedef enum math_fns_ {

    SQL_MATH_MAX = SQL_IDNT_TYPE_MAX + 1,              // max(a,b)
    SQL_MATH_MIN,                // min(a,b)
    SQL_MATH_PLUS,              //  a + b
    SQL_MATH_MINUS,           //  a - b
    SQL_MATH_MUL,               //  a * b
    SQL_MATH_DIV,                 // a / b
    SQL_MATH_SQRT,              // sqrt (a)
    SQL_MATH_SQR,               // sqr(a)
    SQL_MATH_SIN,                // sin(a)
    SQL_MATH_COS,               // cos(a)
    SQL_MATH_POW,              // pow(a,b) : a power b
    SQL_MATH_MOD ,            // a % b
    SQL_MATH_FNS_MAX

} math_fns_t;

typedef enum sql_order_ {

    SQL_ORDERBY_ASC = SQL_MATH_FNS_MAX + 1,
    SQL_ORDERBY_DSC,
    SQL_ORDER_BY_MAX

} sql_order_t;


typedef enum sql_misc_ {

    SQL_COMMA = SQL_ORDER_BY_MAX + 1 ,
    SQL_BRACKET_START,
    SQL_BRACKET_END,
    SQL_QUOTATION_MARK,
    SQL_SHOW_DB_TABLES

} sql_misc_t;

static inline int
sql_valid_dtype (int dtype) {

    switch (dtype) {
        case SQL_STRING:
        case SQL_INT:
        case SQL_DOUBLE:
        case SQL_IPV4_ADDR:
        case SQL_INTERVAL:
        return 1;
    }
    return 0;
}

static inline const char *
sql_dtype_str (sql_dtype_t dtype) {

    switch (dtype) {
        case SQL_STRING:
            return "SQL_STRING";
        case SQL_INT:
            return "SQL_INT";
        case SQL_DOUBLE:
            return "SQL_DOUBLE";
        case SQL_IPV4_ADDR:
            return "SQL_IPV4_ADDR";
        case SQL_INTERVAL:
            return "SQL_INTERVAL";
    }
    return 0;    
}

static inline int
sql_dtype_size (sql_dtype_t dtype) {

    switch (dtype)
    {
    case SQL_STRING:
        return 1;
    case SQL_INT:
        return 4;
    case SQL_DOUBLE:
        return sizeof(double);
    case SQL_IPV4_ADDR:
        return 4;
    case SQL_INTERVAL:
        return 8;
    }
    return 0;
}

static inline const char *
sql_agg_fn_tostring (sql_agg_fn_t agg_fn) {

    switch (agg_fn) {
        case SQL_SUM:
            return "sum";
        case SQL_MIN:
            return "min";
        case SQL_MAX:
            return "max";
        case SQL_COUNT:
            return "count";
        case SQL_AVG:
            return "avg";
    }
    return "";
}

#endif 
