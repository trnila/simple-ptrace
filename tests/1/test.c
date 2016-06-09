#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern const char* syscalls[];

int main() {
	srand(time(NULL));
	printf("%s\n", syscalls[rand() % 100]);
	return 0;
}
