#include <thread>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void* run(void* data) {
	printf("Hello from thread %d\n", data);
	fflush(stdout);
}

int main() {
	pthread_t t1;

	pthread_create(&t1, nullptr, run, (void*) 1);
	pthread_detach(t1);
	printf("detached\n");fflush(stdout);

	pthread_create(&t1, nullptr, run, (void*) 2);
	pthread_join(t1, nullptr);
	printf("joined\n");fflush(stdout);

	std::thread t([] () -> void {
		printf("Hello from std::thread\n");
		fflush(stdout);
	});

	t.join();
	printf("exit\n");
}