CC=g++

all: test

test: test.o syscalls.o
	$(CC) $(LDFLAGS) $(CXXFLAGS) $^ -o $@

syscalls.c: 
	echo "const char* syscalls[] = {" >> syscalls.c
	cat /usr/include/asm/unistd_64.h | sed -nr 's/.+(__NR_[^ ]+) ([0-9]+)/[\2] = "\1",/p' >> syscalls.c
	echo "};" >> syscalls.c

.PHONY: clean
clean:
	rm -f test syscalls.c *.o
