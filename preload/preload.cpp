#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <gnu/lib-names.h>
#include <string.h>

#define LOG(...) fprintf(stderr, __VA_ARGS__)
//#define LOG(...)

#define REPLACE "/usr/bin/who"
//#define REPLACE "/usr/bin/g++"
#define REPLACE_WITH "/usr/bin/ls"
//#define REPLACE_WITH "/usr/bin/c++"

ssize_t (*origWrite)(int fd, const void *buf, size_t count);
int (*origExecve)(const char *filename, char *const argv[], char *const envp[]);

// function is executed, when module is loaded
void init(void) __attribute__((constructor));
void init(void) {
	LOG("[%d] preload loaded\n", getpid());
	origWrite = (ssize_t (*)(int fd, const void *buf, size_t count)) dlsym(RTLD_NEXT, "write");
	origExecve = (int (*)(const char *filename, char *const argv[], char *const envp[])) dlsym(RTLD_NEXT, "execve");

}

ssize_t write(int fd, const void *buf, size_t count) {
	LOG("[%d] write(%d, %.30s ..., %d)\n", getpid(), fd, buf, count);
	return origWrite(fd, buf, count);
}

int execve(const char *filename, char *const argv[], char *const envp[]) {
	LOG("[%d] execve(%s, [", getpid(), filename);
	int i = 0;
	while(argv[i]) {
		LOG("%s, ", argv[i]);

		i++;
	}
	LOG("], ...env..)\n");

	if(strcmp(filename, REPLACE) == 0) {
		LOG("[%d] execve %s replaced with %s!\n", getpid(), REPLACE, REPLACE_WITH);
		return origExecve(REPLACE_WITH, argv, envp);
	}

	return origExecve(filename, argv, envp);
}

int execl(const char *path, const char *arg0, ... /*, (char *)0 */) {
	LOG("not implemented: execl\n");
	return -1;
}

int execle(const char *path, const char *arg0, ... /*, (char *)0, char *const envp[]*/) {
	LOG("not implemented: execle\n");
	return -1;
}
int execlp(const char *file, const char *arg0, ... /*, (char *)0 */) {
	LOG("not implemented: execlp\n");
	return -1;
}

int execv(const char *path, char *const argv[]) {
	return execve(path, argv, environ);
}


int execvp(const char *file, char *const argv[]) {
	if(file[0] == '/') {
		return execve(file, argv, environ);
	}

	char newFile[100];
	sprintf(newFile, "/usr/bin/%s", file);

	return execve(newFile, argv, environ);
}

int fexecve(int fd, char *const argv[], char *const envp[]) {
	LOG("not implemented: fexecve\n");
	return -1;
}

