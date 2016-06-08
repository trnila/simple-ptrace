#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <vector>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unordered_map>
#include <string.h>
#include <libgen.h>
#include "arch.h"

#define LOG(...) fprintf(stderr, __VA_ARGS__)
//#define LOG(...)

typedef struct _Process {
	int pid;
	std::string executable;
	std::vector<std::string> args;
	std::vector<_Process*> childs;
	bool syscall;
	int start;
	int stop;
	_Process *parent;
	int stdin, stdout;

	_Process(int pid) {
		this->pid = pid;
		this->syscall = 0;

		char filename[128];
		sprintf(filename, "out/%d.in", pid);
		stdin = open(filename, O_WRONLY | O_CREAT, 0600);
		sprintf(filename, "out/%d.out", pid);
		stdout = open(filename, O_WRONLY | O_CREAT, 0600);
	}
} Process;

void generate(int out, Process *p) {
	char str[1024];
	sprintf(str, "%d [label=\"%s\"]\n", p->pid, p->executable.c_str());
	write(out, str, strlen(str));

	for(Process* c: p->childs) {
		sprintf(str, "%d -> %d;\n", p->pid, c->pid);
		write(out, str, strlen(str));
		generate(out, c);
	}
}

char str[100000];

void handle_execve(Register &reg, Process *process, int pargc, char **pargv, int start);

void getStr(int p, word_t addr, word_t count) {
	str[count] = 0;
	for(int i = 0; i < count; i++) {
		str[i] = ptrace(PTRACE_PEEKDATA, p, addr + i, NULL);
		if(str[i] == '\n') {
	//		str[i] = '#';
		}
	}
}

void getString(int p, word_t addr) {
	int i = 0;
	while(1) {
		str[i] = ptrace(PTRACE_PEEKDATA, p, addr + i, NULL);
		if(str[i] == '\n') {
			str[i] = '#';
		}

		if(str[i] == 0) {
			return;
		}
		i++;
	}
}

long putString(int p, long addr, const char* str) {
	//TODO: optimize all writes with words!
	int i = -1;
	do {
		i++;
		ptrace(PTRACE_POKEDATA, p, addr + i, str[i]);
	} while(str[i] != '\0');
	return addr + i;
}


int main(int argc, char **argv) {
	if(argc <= 3) {
		printf("Usage: %s /program/to/run hisparams -- /path/to/replace /path/to/replace/with arguments to add\n", argv[0]);
		exit(1);
	}

	int stop = 1;
	for(int i = 2; i < argc; i++) {
		if(strcmp(argv[i], "--") == 0) {
			stop = i;
		}
	}

	int mainPid = fork();
	if(mainPid == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {printf("FAILED!");exit(1);}

		int newOut = open("/dev/null", O_WRONLY);
		//dup2(newOut, 1);
		//dup2(newOut, 2);

		char** args = new char*[stop + 1];
		args[0] = basename(argv[1]);
		args[stop] = 0;

		for(int i = 2; i < stop; i++) {
			args[i - 1] = argv[i];
		}

		execv(argv[1], args);
		perror("execv");
		exit(1);
	} else {
		int pid;
		int status;
		int attached = 0;
		int time = 0;

		LOG("Main tracked process is %d\n", mainPid);

		std::unordered_map<int, Process*> processes;

		while((pid = waitpid(-1, &status, __WALL)) > 0) {
			Process *process = processes[pid];
			if (!process) {
				process = new Process(pid);
				process->parent = nullptr;
				process->start = time++;
				processes[pid] = process;
			}

			// stop and trace all childs of traced process
			if (!attached && pid == mainPid) {
				if (ptrace(PTRACE_SETOPTIONS, mainPid, NULL,
				           PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) != 0) {
					perror("setopts");
					exit(1);
				}
				attached = 1;
			} else {
				// new process is created
				bool forked = status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8));
				bool vforked = status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8));
				bool cloned = status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
				if (forked || vforked || cloned) {
					int childPid;
					ptrace(PTRACE_GETEVENTMSG, pid, NULL, &childPid);

					Process *parent = processes[pid];
					Process *child = processes[childPid];
					if (!child) {
						child = new Process(childPid);
					}
					child->start = time++;
					parent->childs.push_back(child);

					const char *msg;
					static const char *msgs[] = {"forked", "vforked", "cloned"};

					if (forked) {
						msg = msgs[0];
					}
					if (vforked) {
						msg = msgs[1];
					}
					if (cloned) {
						msg = msgs[2];
					}

					LOG("[%d] %s %d\n", pid, msg, childPid);
				} else if(WIFEXITED(status)) {
					LOG("[%d] exit\n", pid);
					process->stop = time++;
				} else {
					Register reg;
					loadRegisters(pid, reg);

					if (reg.syscall == SYS_execve) {
						handle_execve(reg, process, argc, argv, stop + 1);
					} else if(reg.syscall == SYS_write) {
						if(process->syscall == 0) {
							process->syscall = 1;

							if(reg.arguments[0] == 1) {
								getStr(process->pid, reg.arguments[1], reg.arguments[2]);
								printf("[%d] write(%d, %s, %d)\n", process->pid, reg.arguments[0], str, reg.arguments[2]);

								write(process->stdout, str, reg.arguments[2]);
							}
						} else {
							process->syscall = 0;
						}
					} else if(reg.syscall == SYS_read) {
						struct user_regs_struct regs;
						ptrace(PTRACE_GETREGS, process->pid, NULL, &regs);
						if(process->syscall == 0) {
							process->syscall = 1;
						} else {
							process->syscall = 0;

							if(regs.rdi == 0) {
								getStr(process->pid, reg.arguments[1], reg.arguments[2]);
								printf("[%d] read(%d, %s, %d)\n", process->pid, reg.arguments[0], str, reg.arguments[2]);

								write(process->stdin, str, reg.arguments[2]);
							}
						}
					} else {
						//printf("[%d] syscall %d\n", process->pid, reg.syscall);
					}
				}
			}
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
		}

		FILE* out = fopen("data.js", "w+");
		fprintf(out, "var items = [\n");
		for(auto i: processes) {
			Process *p = i.second;
			fprintf(out, "\t{id: %d, content: \"%s\", start: %d, end: %d, group: %d, args: [",  p->pid, p->executable.c_str(), p->start, p->stop, p->parent ? p->parent->pid : 0);

			for(std::string arg: p->args) {
				std::string str(arg);

				std::string to("\\\"");
				size_t start_pos = 0;
    			while((start_pos = str.find("\"", start_pos)) != std::string::npos) {
        			str.replace(start_pos, 1, to);
        			start_pos += to.length();
    			}

				fprintf(out, "\"%s\", ", str.c_str());
			}
			fprintf(out, "]},\n");
		}
		fprintf(out, "];\n");
		fclose(out);
	}

	return 0;
}

void handle_execve(Register &reg, Process *process, int pargc, char **pargv, int start) {
	char *replace = pargv[start];
	char *replaceWith = pargv[start + 1];

	if(process->syscall == 0) {
		if(reg.arguments[0] > 0) {
			retry:
			loadRegisters(process->pid, reg);

			process->syscall = 1;
			getString(process->pid, reg.arguments[0]);

			process->executable = str;

			LOG("[%d] execve(%s, {", process->pid, process->executable.c_str());

			int i = 0;
			process->args.clear();
			while(1) {
				long addr = ptrace(PTRACE_PEEKDATA, process->pid, reg.arguments[1] + sizeof(word_t) * i, NULL);
				if(addr == 0) break;
				getString(process->pid, addr);

				process->args.push_back(str);

				LOG("%s, ", process->args.back().c_str());
				i++;
			}

			LOG("})\n");

			if(process->executable == replace) {
				const char *str = replaceWith;
				int argc = process->args.size() + (pargc - start - 2) + 1;
				char **args = new char*[argc];
				args[argc - 1] = nullptr;

				args[0] = strrchr(replaceWith, '/');
				if(!args[0]) {
					args[0] = replaceWith;
				} else {
					args[0]++; //TODO: fix
				}

				int i;
				for(i = 1; i < process->args.size(); i++) {
					args[i] = (char*)process->args.at(i).c_str();
				}

				for(int j = start + 2; j < pargc; j++) {
					args[i] = pargv[j];
					i++;
				}

				// write new executable path
				putString(process->pid, reg.stack, str);
				reg.arguments[0] = reg.stack;

				saveRegisters(process->pid, reg);

				long start = reg.stack + strlen(str)+1;
				long end = start + sizeof(word_t) * argc;

				// write args pointers
				for(int i = 0; i < argc; i++) {
					if(args[i] == nullptr) {
						end = 0;
					}

					ptrace(PTRACE_POKEDATA, process->pid, start + sizeof(word_t) * i, end);

					if(args[i]) {
						end = 1 + putString(process->pid, end, args[i]);
					}
				}

				reg.arguments[1] = start;
				saveRegisters(process->pid, reg);
				goto retry;
			}
		}
	} else {
		process->syscall = 0;
		LOG("[%d] ... returned %ld %s\n", process->pid, reg.ret, strerror(-reg.ret));
	}
}