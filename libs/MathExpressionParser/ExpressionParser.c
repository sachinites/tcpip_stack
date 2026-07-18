
/* This file implements the SQL Parser which accespts all SQL queries satisfying the below Grammar 

A Grammar to parse mathematical expression !

1. E -> E + T | E - T | T
2. T -> T * F | T / F | F
3. F -> ( E ) | INTEGER | DECIMAL | VAR | 'SENTENCE'

Grammar for Inequalities : 

Add this production Rule as Ist rule to above Grammar 
0. Q -> E Ineq E | (Q)  

Overall Grammar is :
1. Q -> E Ineq E | (Q)  
2. E -> E + T | E - T | T
3. T -> T * F | T / F | F
4. F -> ( E ) | INTEGER | DECIMAL | VAR | 'SENTENCE'

Now remove left recursion from it :

2. E -> E + T | E - T | T

E ->  T E'
E' -> + T E' | - T E' |  $   ( $ represents epsilon)

3. T -> T * F | T / F | F

T -> F T'
T' -> * F T' |   / F T'  |  $

Combining everything, final grammar is for computing one Inequality
==================================================

1. Q  ->   E Ineq E  | INCLAUSE | ( Q )
2. E  ->   T E'
3. E'  ->  + T E' | - T E' |  $
4. T  ->   F T'
5. T' ->   * F T' |   / F T'  |  $
6. F  ->   ( E ) |  P ( E ) | INTEGER | DECIMAL | VAR | G ( E, E) | 'SENTENCE'
7. P -> sqrt | sqr | sin        // urinary fns
8. G -> max | min | pow   // binary functions 

Implementing Logical Operators also (and , or ) which combines various inequalities

1. S -> S or J | J
2. J -> J and K | K 
3. K -> (S) | D | K lop Q | Q lop K
4. D -> Q lop Q
5. lop -> and | or

Removing Left Recursion :
1. S -> S or J | J
    S -> J S'
    S' -> or J S' | $
2. J -> J and K | K
    J -> K J'
    J' -> and K J' | $
3. K -> (S) | D | K lop Q | Q lop K
    K -> (S) K' |  D K' |  Q lop K K'
    K' -> lop Q K' | $

Overall Grammar will be :
===================
1. S -> J S'
2. S' -> or J S' | $
3. J -> K J'
4. J' -> and K J' | $
5. K -> (S) K' | D K' | Q lop K K'
6. K' -> lop Q K' | $
7. D -> Q lop Q
8. lop -> and | or

The above is the Grammar we will use to finally implement Logical Expression Parsing.
The predence of 'and' and 'or' will be handled at the infix to postfix conversion.

Overall Grammar to  represent an expression containing atleast two inequalities
joined by Logical operaration(s)  is below.
For example :   salary > amount and age > 30
                         (salary > amount and age > 30 ) or ( pin_code = 560103 or age > 60)


Rules for Grammar Parsing :

1. For a Production Rule, A -> BC | DE , Rule contains two alternatives :
        A -> BC   or   A -> DE 
        Explore A -> BC, if success , return SUCCESS
        if fails, try second alternative (A ->DE), if success return SUCCESS, else return ERROR
        i.e. we apply alternatives until we succeed. Alternatives could be applied in any order.

2.    For a Production Rule, A -> BC | DE | $, Rule contains three alternatives :
        A -> BC   or   A -> DE    or     A -> $
        Explore A -> BC, if success , return SUCCESS
        if fails, try second alternative A -> DE, if success return SUCCESS, else return SUCCESS
        i.e. we apply alternatives until we succeed. Alternatives could be applied in any order.
        If all alternatives failed, then return SUCCESS ($ means, return SUCCESS even if none of the alternatives succeed)

3. For a Production Rule, A -> BCD, 
        Non Terminal Symbol C is explored only when previous one B has succeeded.
        Non Terminal Symbol D is explored only when previous one C has succeeded.
        At any point, the exploration fails, We are done with A -> BCD production rule and return Error,
        and look for exploration of alterntive rule if present , eg, A -> EF

4. While Returning an Error, POP all elements of the stack that was pushed as a result of exploration  
    of production rule which has failed. This will be done automatically by 'RETURN_PARSE_ERROR' macro.
*/

/* This file represents the application whiich make use of Parser library (Parser.l/ParserExport.h) files to
    write parsing code */
#include <stdlib.h>
#include <assert.h>

// Must include ParserExport.h
#include "ParserExport.h"

// must include application specific hdr file which contains token IDs.
// This file need tobe included in Parser.l file as well.
#include "MExprcppEnums.h"

extern int
Appln_to_Mexpr_enum_converter (int token_code);

/* Wrapper for Ease */
static int 
cnvrt (mexpr_parser_t *p, int external_code) {

    return Appln_to_Mexpr_enum_converter  (external_code);
}

parse_rc_t INCLAUSE (mexpr_parser_t *p) ;
parse_rc_t IDENT_LST (mexpr_parser_t *p) ;  // ("abc" , "def" , "ghi")

parse_rc_t Ineq (mexpr_parser_t *p) ;
parse_rc_t G (mexpr_parser_t *p);
parse_rc_t P (mexpr_parser_t *p);
parse_rc_t F (mexpr_parser_t *p);
parse_rc_t T_dash (mexpr_parser_t *p) ;
parse_rc_t T (mexpr_parser_t *p) ;
parse_rc_t E_dash (mexpr_parser_t *p) ;
parse_rc_t E (mexpr_parser_t *p) ;

parse_rc_t Q (mexpr_parser_t *p) ;

parse_rc_t D (mexpr_parser_t *p);
parse_rc_t K (mexpr_parser_t *p);
parse_rc_t K_dash (mexpr_parser_t *p);
parse_rc_t J_dash (mexpr_parser_t *p) ;
parse_rc_t J (mexpr_parser_t *p) ;
parse_rc_t  S_dash (mexpr_parser_t *p) ;
parse_rc_t  S (mexpr_parser_t *p) ;

parse_rc_t 
IDENT_LST (mexpr_parser_t *p) {

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_STRING ) RETURN_PARSE_ERROR;

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_COMMA) {
        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(IDENT_LST);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

/* Parse the  ' in ' operator 
    INCALUSE ->  Identifier in (IDENT_LST) | Identifier in [<integer>,<integer>]
    IDENT_LST -> "Word(s)" | "Word(s)" , IDENT_LST
*/
parse_rc_t 
INCLAUSE (mexpr_parser_t *p) {

    parse_init(p);
    int initial_chkp;

    //  INCALUSE ->  Identifier in (IDENT_LST)
    do {

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_VARIABLE)  RETURN_PARSE_ERROR;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_IN) RETURN_PARSE_ERROR;

        CHECKPOINT(p, initial_chkp);

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_START) break;

        err = PARSER_CALL(IDENT_LST);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    //  INCALUSE ->  Identifier in [<integer>,<integer>]
    do {

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_INTERVAL) break;

        RETURN_PARSE_SUCCESS;
        
    } while (0);

    RETURN_PARSE_ERROR;
}


parse_rc_t
Ineq (mexpr_parser_t *p) {

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    switch(token_code) {
        case MATH_CPP_LESS_THAN:
	    case MATH_CPP_LESS_THAN_EQ:
        case MATH_CPP_GREATER_THAN:
        case MATH_CPP_EQ:
        case MATH_CPP_NEQ:
        case MATH_CPP_LIKE:
            break;
        default:
            RETURN_PARSE_ERROR;
    }

    RETURN_PARSE_SUCCESS;
}

/* Parse the Binary Math functions */
parse_rc_t
G (mexpr_parser_t *p) {

     parse_init(p);

     token_code = cnvrt (p, cyylex(p) );

     switch (token_code) {

        case MATH_CPP_MAX:
        case MATH_CPP_MIN:
        case MATH_CPP_POW:
            RETURN_PARSE_SUCCESS;
        default:
            RETURN_PARSE_ERROR;
     }

}

/* Parse the unary Math functions */
parse_rc_t
P (mexpr_parser_t *p) {

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    switch (token_code) {

        case MATH_CPP_SQRT:
        case MATH_CPP_SQR:
        case MATH_CPP_SIN:
	    case MATH_CPP_COS:
            RETURN_PARSE_SUCCESS;
        default:
            RETURN_PARSE_ERROR;
    }
}

/* F  ->   ( E ) |  P ( E ) | INTEGER | DECIMAL | VAR | IPV4 | G ( E, E) */
parse_rc_t
F (mexpr_parser_t *p) {

    parse_init(p);

    int initial_chkp;
    CHECKPOINT(p, initial_chkp);

    token_code = cnvrt (p, cyylex(p) );

    // ( E )
    do {
        
        if (token_code != MATH_CPP_BRACKET_START) break;

        err = PARSER_CALL(E);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    // INTEGER | DECIMAL | VAR | 'SENTENCE' | IPV4
    do {

        token_code = cnvrt (p, cyylex(p) );

        switch (token_code) {
            
            case MATH_CPP_INT:
            case MATH_CPP_DOUBLE:
            case MATH_CPP_VARIABLE:
            case MATH_CPP_STRING:
            case MATH_CPP_IPV4:
                RETURN_PARSE_SUCCESS;
            default:
                break;
        }
    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    // P ( E ) 
    do {

        err = PARSER_CALL(P);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_START) break;

        err = PARSER_CALL(E);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    // G ( E, E)

    do {

        err = PARSER_CALL(G);

        if (err == PARSE_ERR) RETURN_PARSE_ERROR;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_START) RETURN_PARSE_ERROR;

        err = PARSER_CALL(E);

        if (err == PARSE_ERR) RETURN_PARSE_ERROR;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_COMMA) RETURN_PARSE_ERROR;

        err = PARSER_CALL(E);

        if (err == PARSE_ERR) RETURN_PARSE_ERROR;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) RETURN_PARSE_ERROR;

        RETURN_PARSE_SUCCESS;

    } while (0);
}

/* T' ->   * F T' |   / F T'  |  $ */
parse_rc_t
T_dash (mexpr_parser_t *p) {

    parse_init(p);

    int initial_chkp;
    CHECKPOINT(p, initial_chkp);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_MUL &&
            token_code != MATH_CPP_DIV) {
        
        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(F);

    if (err == PARSE_ERR) {

        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(T_dash);

    if (err == PARSE_ERR) {

        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;        
    }

    RETURN_PARSE_SUCCESS;
}

// 4. T  ->   F T'
parse_rc_t
T (mexpr_parser_t *p) {

    parse_init(p);

    err = PARSER_CALL(F);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    err = PARSER_CALL(T_dash);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

//  E'  ->  + T E' | - T E' |  $
parse_rc_t
E_dash (mexpr_parser_t *p) {

    parse_init(p);

    int initial_chkp;
    CHECKPOINT(p, initial_chkp);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_PLUS &&
            token_code !=  MATH_CPP_MINUS) {
        
        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(T);

    if (err == PARSE_ERR) {

        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(E_dash);

    if (err == PARSE_ERR) {

        RESTORE_CHKP(p, initial_chkp);
        RETURN_PARSE_SUCCESS;        
    }

    RETURN_PARSE_SUCCESS;
}

/* E  ->   T E' */
parse_rc_t
E (mexpr_parser_t *p) {

    parse_init(p);

    err = PARSER_CALL(T);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    err = PARSER_CALL(E_dash);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

/* Q  ->   E Ineq E  | ( Q ) |  INCLAUSE */

parse_rc_t
Q (mexpr_parser_t *p) {

    parse_init(p);
    int chkp_initial;
    
    CHECKPOINT(p, chkp_initial);

     // Q -> (Q)
    do {

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_START) break;

        err = PARSER_CALL(Q);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, chkp_initial);

    do {
        // E Ineq E
        err = PARSER_CALL(E);

        if (err == PARSE_ERR) break;

        err = PARSER_CALL(Ineq);

        if (err == PARSE_ERR) break;

        err = PARSER_CALL(E);

        if (err == PARSE_ERR) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, chkp_initial);

    //INCLAUSE
    err = PARSER_CALL( INCLAUSE);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}


// D -> Q lop Q
parse_rc_t
D (mexpr_parser_t *p) {

    parse_init(p);

    err = PARSER_CALL(Q);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_OR &&
            token_code != MATH_CPP_AND) {

        RETURN_PARSE_ERROR;
    }

    err = PARSER_CALL(Q);

     if (err == PARSE_ERR) RETURN_PARSE_ERROR;

     RETURN_PARSE_SUCCESS;
}

// K' -> lop Q K' | $
parse_rc_t
K_dash (mexpr_parser_t *p) {

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_AND &&
        token_code != MATH_CPP_OR) {

        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(Q);

    if (err == PARSE_ERR) {
        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(K_dash);

    if (err == PARSE_ERR) {
        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    RETURN_PARSE_SUCCESS;
}

/* K -> (S) K' | D K'  | Q lop K K'  */
parse_rc_t
K (mexpr_parser_t *p) {

    parse_init(p);

    int initial_chkp;
    CHECKPOINT(p, initial_chkp);

    //  (S) K'
    do {

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_START) break;

        err = PARSER_CALL(S);

        if (err == PARSE_ERR) break;

        token_code = cnvrt (p, cyylex(p) );

        if (token_code != MATH_CPP_BRACKET_END) break;

        err = PARSER_CALL(K_dash);

        if (err == PARSE_ERR) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);
    // D K' 
    do {

        err = PARSER_CALL(D);

        if (err == PARSE_ERR) break;

        err = PARSER_CALL(K_dash);

        if (err == PARSE_ERR) break;

        RETURN_PARSE_SUCCESS;

    } while (0);

    RESTORE_CHKP(p, initial_chkp);

    // Q lop K K' 
    err = PARSER_CALL(Q);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_OR &&
        token_code != MATH_CPP_AND) {

        RETURN_PARSE_ERROR;
    }

    err = PARSER_CALL(K);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    err = PARSER_CALL(K_dash);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}

/*  J' -> and K J' | $ */
parse_rc_t
J_dash (mexpr_parser_t *p) {

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_AND) {
        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(K);

    if (err == PARSE_ERR) RETURN_PARSE_SUCCESS;

    err = PARSER_CALL(J_dash);

    if (err == PARSE_ERR) RETURN_PARSE_SUCCESS;

    RETURN_PARSE_SUCCESS;
}

/* J -> K J' */
parse_rc_t
J (mexpr_parser_t *p) {

    parse_init(p);

    err = PARSER_CALL(K);

    if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    err = PARSER_CALL(J_dash);

     if (err == PARSE_ERR) RETURN_PARSE_ERROR;

     RETURN_PARSE_SUCCESS;
}


/* S' -> or J S' | $ */
parse_rc_t
S_dash (mexpr_parser_t *p) {   

    parse_init(p);

    token_code = cnvrt (p, cyylex(p) );

    if (token_code != MATH_CPP_OR) {
        yyrewind(p, 1);
        RETURN_PARSE_SUCCESS;
    }

    err = PARSER_CALL(J);

    if (err == PARSE_ERR) RETURN_PARSE_SUCCESS;

    err = PARSER_CALL(S_dash);

    if (err == PARSE_ERR) RETURN_PARSE_SUCCESS;

    RETURN_PARSE_SUCCESS;
}

 /*S -> J S'  */
parse_rc_t
S (mexpr_parser_t *p) {     

    parse_init(p);

   err = PARSER_CALL(J);

   if (err == PARSE_ERR) RETURN_PARSE_ERROR;

   err = PARSER_CALL(S_dash);

   if (err == PARSE_ERR) RETURN_PARSE_ERROR;

    RETURN_PARSE_SUCCESS;
}
