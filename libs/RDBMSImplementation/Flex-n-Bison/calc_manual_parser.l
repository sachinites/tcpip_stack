%{

#include <stdio.h>

enum {

    ADD = 265,
    SUB,
    MUL,
    DIV,
    ABS,
    NUMBER,
    EOL
};

int token_val;
int TOKEN_TYPE;

%}

%%

"+" {return ADD; }
"-" {return SUB;}
"*" {return MUL;}
"/" {return DIV;}
"|" {return ABS;}
[0-9]+ { token_val = atoi (yytext); return NUMBER;}
\n {return EOL;}
[ ] { /* ignore white space */ }
[\t] { /* ignore white space */ } 
. {printf ("Mysterious char %c\n", *yytext); }

%%

void yyerror(const char* error_message) {
    printf("Syntax error: %s\n", error_message);
}

static int term() {
    int result;
    switch (TOKEN_TYPE = yylex()) {
        case NUMBER:
            result = token_val;
            break;
        case ABS:
            result = term();
            if (result < 0)
                result = -result;
            break;
        default:
            break;
    }
    return result;
}

static int factor() {
    int result = term();
    switch (TOKEN_TYPE = yylex()) {
        case MUL:
            result *= term();
            break;
        case DIV:
            result /= term();
            break;
        default:
           break;
    }
    return result;
}


static int expr() {
    int result = factor();
    switch (TOKEN_TYPE = yylex()) {
        case ADD:
            result += factor();
            break;
        case SUB:
            result -= factor();
            break;
        default:
            break;
    }
    return result;
}


static int calclist() {
    int result;
    switch (TOKEN_TYPE = yylex()) {
        case EOL:
            printf("Nothing to compute\n");
            return 0;
        default:
            result = expr();
            if ((TOKEN_TYPE = yylex()) != EOL) {
                yyerror("Expected newline after expression");
                return -1;
            }
            printf("= %d\n", result);
            return result;
    }
}

static int yyparse() {
    return calclist();
}

int main(int argc, char **argv) {
    #if 1
    yyparse();
    #else
    int k;
    while ((k = yylex()) != EOL) {
        printf ("Token Type = %d\n", k);
    }
    #endif
    return 0;
}