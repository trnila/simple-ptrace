#include <stdio.h>
#include "parser/parser.h"

int main(int argc, char** argv) {
	//yydebug= 1;
 	Function *func = yyparse();
 	printf("Function: %s returning %s\n", func->name, typeToStr(func->ret));

	Variable *var = func->arg;
	while(var != NULL) {
		printf("\targument %s with type %s\n", var->name, typeToStr(var->type));
		var = var->next;
	}

 	return 0;
}