CXXFLAGS=-fpic
LDFLAGS=-ldl
CC=g++

all: preload.so

preload.so: preload.o
	$(CC) $^ -shared -o $@ $(LDFLAGS)

clean:
	rm -f preload.so *.o