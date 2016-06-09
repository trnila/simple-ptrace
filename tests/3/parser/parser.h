#pragma once

typedef enum {
	INT,
	DOUBLE,
	CHAR
} Type;

int yylex(void);
void yyerror(const char *);
const char* typeToStr(Type type);

typedef struct _variable {
	Type type;
	const char* name;
	struct _variable *next;
} Variable;

typedef struct {
	Type ret;
	const char* name;
	Variable *arg;
} Function;