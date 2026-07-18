#include <assert.h>
#include "ParserExport.h"
#include "SqlEnums.h"
#include "../../MathExpressionParser/MExprcppEnums.h"

int 
Appln_to_Mexpr_enum_converter (int token_code);

int 
Appln_to_Mexpr_enum_converter (int token_code) {

    switch (token_code) {

        /* Operators first */
        case SQL_MATH_MINUS:
            return MATH_CPP_MINUS;

        case SQL_MATH_PLUS:
            return MATH_CPP_PLUS;

        case SQL_MATH_MOD:
            return MATH_CPP_MOD;

        case SQL_MATH_MUL:
            return MATH_CPP_MUL;

        case SQL_MATH_DIV:
            return MATH_CPP_DIV;
            
        case SQL_EQ:
            return MATH_CPP_EQ;

        case SQL_NOT_EQ:
            return MATH_CPP_NEQ;

        case SQL_LESS_THAN:
            return MATH_CPP_LESS_THAN;

        case SQL_GREATER_THAN:
            return MATH_CPP_GREATER_THAN;

        case SQL_IN:
            return MATH_CPP_IN;
        case SQL_LIKE:
            return MATH_CPP_LIKE;

            
        case SQL_BRACKET_START:
            return MATH_CPP_BRACKET_START;
        case SQL_BRACKET_END:
             return MATH_CPP_BRACKET_END;

        case SQL_OR:
            return MATH_CPP_OR;
        case SQL_AND:
                return MATH_CPP_AND;

        case SQL_MATH_SQR:
            return MATH_CPP_SQR;
        case SQL_MATH_SQRT:
             return MATH_CPP_SQRT;

        case SQL_MATH_MAX:
            return MATH_CPP_MAX;
        case SQL_MATH_MIN:
            return MATH_CPP_MIN;


        /* Operands */
        case SQL_INTEGER_VALUE:
            return MATH_CPP_INT;

        case SQL_DOUBLE_VALUE:
            return MATH_CPP_DOUBLE;

        case SQL_STRING_VALUE:
            return MATH_CPP_STRING;

        case SQL_IPV4_ADDR_VALUE:
            return MATH_CPP_IPV4;

        case SQL_IDENTIFIER:
        case SQL_IDENTIFIER_IDENTIFIER:
            return MATH_CPP_VARIABLE;

        case SQL_INTERVAL_VALUE:
             return MATH_CPP_INTERVAL;

        /* Extras */
        case SQL_COMMA:
             return MATH_CPP_COMMA;

        default:
            return PARSER_INVALID_CODE;
    }

    return PARSER_INVALID_CODE;
}
