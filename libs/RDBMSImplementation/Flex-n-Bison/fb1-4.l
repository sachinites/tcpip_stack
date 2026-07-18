%{
#include "fb1-5.tab.h"

int token_val;

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

/*
int
main(int argc, char **argv)
{
yylex();  // invoke the scanner
}
*/