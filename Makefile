CXXFLAGS=-g

all: change


.PHONY: tests
tests:
	make -C tests

clean:
	rm -f change simple
	make -C tests clean