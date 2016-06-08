#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/reg.h>
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
//#include "syscall_names.h"

typedef uint64_t word_t;

typedef struct _Process {
	int pid;
	std::string executable;
	std::vector<std::string> args;
	std::vector<_Process*> childs;
	bool syscall;

	_Process(int pid) {
		this->pid = pid;
		this->syscall = 0;
	}
} Process;

Process* find(int pid, Process *proc) {
	if(proc->pid == pid) {
		return proc;
	}

	for(Process* p: proc->childs) {
		Process* r = find(pid, p);
		if(r) {
			return r;
		}
	}

	return nullptr;
}

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

char str[10000];

void handle_execve(Process *process);

void getStr(int p, word_t addr, word_t count) {
	str[count] = 0;
	for(int i = 0; i < count; i++) {
		str[i] = ptrace(PTRACE_PEEKDATA, p, addr + i, NULL);
		if(str[i] == '\n') {
			str[i] = '#';
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


int main() {
	int mainPid = fork();
	if(mainPid == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {printf("FAILED!");exit(1);}

		int newOut = open("/dev/null", O_WRONLY);
		dup2(newOut, 1);
		dup2(newOut, 2);

		execl("/usr/bin/make", "make", "clean", "all", NULL);
	} else {
		int pid;
		int status;
		int attached = 0;

		printf("Main tracked process is %d\n", mainPid);

		Process* mainProcess = new Process(mainPid);
		std::unordered_map<int, Process*> processes;

		while((pid = wait(&status)) > 0) {
			Process *process = processes[pid];
			if(!process) {
				process = new Process(pid);
				processes[pid] = process;
			}

			// stop and trace all childs of traced process
			if(!attached && pid == mainPid) {
				if(ptrace(PTRACE_SETOPTIONS, mainPid, NULL,  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) !=0) {
					perror("setopts");
					exit(1);
				}
				attached = 1;
			}

			// new process is created
			bool forked = status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8));
			bool vforked = status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8));
			bool cloned =  status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8));
			if(forked || vforked || cloned) {
				int childPid;
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &childPid);

				Process* parent = find(pid, mainProcess);
				Process* child = processes[childPid];
				if(!child) {
					child = new Process(childPid);
				}
				parent->childs.push_back(child);

				const char *msg;
				static const char *msgs[] = {"forked", "vforked", "cloned"};

				if(forked) {
					msg = msgs[0];
				}
				if(vforked) {
					msg = msgs[1];
				}
				if(cloned) {
					msg = msgs[2];
				}

				printf("[%d] %s %d\n", pid, msg, childPid);
			}

			if(WIFEXITED(status)) {
				printf("[%d] exit\n", pid);
			}

			long orig_rax = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
			if(orig_rax == SYS_execve) {
				handle_execve(process);
			} else {
				//printf("[%d] syscall %d %s\n", p, orig_rax, syscall_name[orig_rax]);
			}

			ptrace(PTRACE_SYSCALL, pid, 0, 0);
		}
	}

	return 0;
}

void handle_execve(Process *process) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, process->pid, NULL, &regs);
	if(process->syscall == 0) {
		if(regs.rdi > 0) {
			process->syscall = 1;
			getString(process->pid, regs.rdi);

			process->executable = str;

			printf("[%d] execve(%s, {", process->pid, process->executable.c_str());

			int i = 0;
			while(1) {
				long addr = ptrace(PTRACE_PEEKDATA, process->pid, regs.rsi + 8 * i, NULL);
				if(addr == 0) break;
				getString(process->pid, addr);

				process->args.push_back(str);

				printf("%s, ", process->args.back().c_str());
				i++;
			}

			printf("})\n");
		}
	} else {
		process->syscall = 0;
		long rax = ptrace(PTRACE_PEEKUSER, process->pid, 8 * RAX, NULL);
		printf("[%d] ... returned %ld %s\n", process->pid, rax, strerror(-regs.rax));
	}
}