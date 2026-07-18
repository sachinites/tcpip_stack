/* simplest version of calculator */
%{
#include <stdio.h>
#include <stdlib.h>
void yyerror(const char *msg);
int yylex();
%}

/* declare tokens */

%token NUMBER
%token ADD SUB MUL DIV ABS
%token EOL

%%
calclist:
| calclist EOL 
| calclist exp EOL { printf("= %d\n", $1); } 
;
exp: factor
| exp ADD factor { $$ = $1 + $3; }
| exp SUB factor { $$ = $1 - $3; }
;
factor: term
| factor MUL term { $$ = $1 * $3; }
| factor DIV term { $$ = $1 / $3; }
;
term: NUMBER
| ABS term ABS { $$ = $2 >= 0 ? $2 : $2 * -1; }
;
%%

int
main(int argc, char **argv)
{
yyparse();
return 0;
}

void yyerror(const char *s)
{
fprintf(stderr, "error: %s\n", s);
}