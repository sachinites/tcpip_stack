#ifndef __MEXPR_ENUMS__
#define __MEXPR_ENUMS__

#include <assert.h>

/* Update the values of these enums to match with the values used by 
    External project which is using this MathExpression Library*/

#define MEXPR_TREE_OPERAND_LEN_MAX  192
#define MEXPR_MAX_STRING_VAL_LEN    256
#define MAX_EXPR_LEN    512
#define MEXPR_INVALID_ID   INT32_MAX

typedef enum mexpr_opr_enums_ {

    MATH_LESS_THAN_EQ,
    MATH_LESS_THAN,
    MATH_GREATER_THAN,
    MATH_EQ,
    MATH_NOT_EQ,
    MATH_OR,
    MATH_AND,
    MATH_MUL,
    MATH_DIV,
    MATH_SQR,
    MATH_SQRT,
    MATH_MAX,
    MATH_MIN,
    MATH_PLUS,
    MATH_MINUS,
    MATH_SIN,
    MATH_COS,
    MATH_POW,
    /* Insert new Operators in the end*/
    
    /* If you have good reason to change the sequence
        of above operators, pls change the array order in
        MexprDb.c also*/
    MATH_BRACKET_START,
    MATH_BRACKET_END,
    MATH_OPR_MAX

} mexpr_opr_enums_t;

typedef enum mexpr_opnd_enums_ {

    MATH_INTEGER_VALUE = MATH_OPR_MAX + 1,
    MATH_DOUBLE_VALUE,
    MATH_STRING_VALUE,
    MATH_BOOL_VALUE,
    MATH_OPRND_MAX
    
} mexpr_opnd_enums_t;

typedef enum mexpr_generic_enums_ {

    MATH_IDENTIFIER = MATH_OPRND_MAX + 1,
    MATH_IDENTIFIER_IDENTIFIER,
    MATH_COMMA,
    MATH_MAX_CODE

} mexpr_generic_enums_t;

#define MEXPR_LIB_MAX_CODE_USED MATH_MAX_CODE


typedef enum mexpr_dtypes_ {

    MEXPR_DTYPE_INT,
    MEXPR_DTYPE_DOUBLE,
    MEXPR_DTYPE_STRING,
    MEXPR_DTYPE_BOOL,
    MEXPR_DTYPE_MAX,
    // Dont below below enums above MAX, it will
    // disrupt the MexprDb
    MEXPR_DTYPE_UNKNOWN,
    MEXPR_DTYPE_INVALID

} mexpr_dtypes_t;

/* Conversion of Data types ID which are parsed by lex code to internal
    data types. Internal Dtypes are usedbecause are used as indices into an array,
    hence, has to start from zero.*/
static inline mexpr_dtypes_t
mexpr_get_dtype_from_value_token_code (int token_code) {

    switch (token_code) {

        case MATH_INTEGER_VALUE:
            return MEXPR_DTYPE_INT;
        case MATH_DOUBLE_VALUE:
            return MEXPR_DTYPE_DOUBLE;
        case MATH_STRING_VALUE:
            return MEXPR_DTYPE_STRING;
        case MATH_BOOL_VALUE:
            return MEXPR_DTYPE_BOOL;
        default:
            return MEXPR_DTYPE_INVALID;
    }
}

#include <stdbool.h>

typedef struct mexpr_var {

    mexpr_dtypes_t dtype;

    union {

        int int_val;
        double d_val;
        unsigned char *str_val;
        bool b_val;

    } u;
} mexpr_var_t;


#endif 
