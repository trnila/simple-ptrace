BINS=threads doublefork asm-execve

all: $(BINS)

threads: threads.o
	g++ $^ -o $@ -lpthread

asm-execve: asm-execve.o
	ld $^ -o $@

asm-execve.o: asm-execve.S
	nasm -f elf64 $^


clean:
	rm -f *.o $(BINS)