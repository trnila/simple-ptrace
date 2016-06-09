CFLAGS=-g -DYYDEBUG=1

all: libparser.a

libparser.a: lex.yy.o y.tab.o typeToString/typeToString.o
	make -C typeToString
	$(AR) $(ARFLAGS) $@ $^

y.tab.c y.tab.h: declarations.y
	yacc -t -d $^ -Dparse.trace

lex.yy.c: declarations.l y.tab.h
	flex  $^

clean:
	make -C typeToString clean
	rm -f *.o lex.yy.c y.tab.{c,h} libparser.a