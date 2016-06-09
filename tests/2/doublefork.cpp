#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
	if(fork() == 0) {
		if(fork() == 0) {
			execl("/usr/bin/ls", "ls", "/", nullptr);
		}
	}
}