%{
#include <stdio.h>
#include "parser.h"
%}

%debug
%error-verbose

%token TYPE
%token IDENTIFIER


/*
%type <Function*> start
%type <Variable> args*/

%%
start: TYPE IDENTIFIER '(' args ')' ';'
	{
		Function *func = malloc(sizeof(Function));
		func->ret = $1;
		func->name = $2;
		func->arg = $4;

		$$ = func;
		return $$;
	}

args: TYPE IDENTIFIER args1
	{
		Variable *var = malloc(sizeof(Variable));
		var->name = $2;
		var->type = $1;
		var->next = $3;
		$$ = var;
	}

args1:
	',' TYPE IDENTIFIER args1
		{
			Variable *var = malloc(sizeof(Variable));
			var->name = $3;
			var->type = $2;
			var->next = $4;
			$$ = var;
		}
	| {
		$$ = 0;
	}

%%
void yyerror(const char *msg) {
	printf("%s\n", msg);
}