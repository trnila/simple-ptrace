#include <unistd.h>

int main() {
	execl("/usr/bin/who", "who", 0);
}