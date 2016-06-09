all: threads doublefork

threads: threads.o
	g++ $^ -o $@ -lpthread

clean:
	rm -f *.o threads doublefork
