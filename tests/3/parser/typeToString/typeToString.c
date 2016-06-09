#include "../parser.h"

const char* typeToStr(Type type) {
	switch(type) {
		case INT:
			return "integer";
		case DOUBLE:
			return "double";
		case CHAR:
			return "character";
	}
}