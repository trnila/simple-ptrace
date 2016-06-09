%{
#include "y.tab.h"
#include "parser.h"
extern int yylval;

%}

digit [0-9]
letter [A-Za-z]
identifier {letter}({letter}|{digit})*

%%
"int" {yylval = INT; return TYPE;}
"double" {yylval = DOUBLE; return TYPE;}
"char" {yylval = CHAR; return TYPE;}

{identifier} {yylval = strdup(yytext); return IDENTIFIER;}
"(" {return '(';}
")" {return ')';}
";" {return ';';}
"," {return ',';}
[ \t\n]+ ;
. printf("Unknown character %s (%d)\n", yytext, yytext[0]);
%%
//int yywrap(void){return 1;}

