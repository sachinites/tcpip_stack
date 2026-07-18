# MathExpressionParser
Calculation of Mathematical Expressions

If you are integrating your own application with this Library, pls follow the below steps :

1. Your application must come with its own Parser.l and ParserExport.h separate files. Copy them from 
    ParserLib/Parser.l and ParserLib/ParserExport.h into your application


2. Change the below line in UserParserL.h file :
    from 
        #include "ParserExport.h"
    to
        #include "path to applications's ParserExport.h"

3. Assuming your application has its own header file which lists all tokens enums and IDs,
    overwrite the values of enums/IDs in application's hdr file with those menthoned in MexprEnums.h.
    For example, if application file is app_tokens.h as below :
        
        typedef enum app_tokens_ {

            APP_OR,
            APP_PLUS,
            APP_MINUS 

        } app_tokens_t;

    then #include MexprEnums.h into app_tokens.h, and reassign values :

        typedef enum app_tokens_ {

            APP_OR = MATH_OR,
            APP_PLUS = MATH_PLUS,
            APP_MINUS = MATH_MINUS

        } app_tokens_t;

4. Token ID values from 5001 to 5050 is reserved by this library, do not use the same in your application. See MexprEnums.h. Also, IDs [10000 - 10002] is reserved by Parser. see ParserExport.h.

5. You need to #include ParserMexpr.h into your application's Src file to use the functions provided by this library to work with MathExpression parsing. This is the User API for this library.

6. You must compile an link below 3 source files from this library into your application binary :

gcc -g -c MExpr.c -o MExpr.o
gcc -g -c ExpressionParser.c -o ExpressionParser.o
gcc -g -c ParserMexpr.c -o ParserMexpr.o

7. Revisit below #define values defined in Mexpr.h if you want to update them as per your aplication needs :

#define MEXPR_TREE_OPERAND_LEN_MAX  128
#define MAX_EXPR_LEN    512