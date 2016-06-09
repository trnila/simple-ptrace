LDFLAGS=-lfl

all: main.o
	make -C parser
	$(CC) -o $@ $^ $(LDFLAGS) parser/libparser.a

clean:
	rm -f *.o
	make -C parser clean