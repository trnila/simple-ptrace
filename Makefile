CXXFLAGS=-g
CC=g++

all: change
change: change.o arch.o

.PHONY: tests
tests:
	make -C tests

clean:
	rm -f change simple *.o
	make -C tests clean