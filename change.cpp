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
	char cmd[5000];
	std::vector<_Process*> childs;
	bool syscall;

	_Process(int pid) {
		this->pid = pid;
		this->cmd[0] = 0;
		this->childs.clear();
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
	sprintf(str, "%d [label=\"%s\"]\n", p->pid, p->cmd);
	write(out, str, strlen(str));

	for(Process* c: p->childs) {
		sprintf(str, "%d -> %d;\n", p->pid, c->pid);
		write(out, str, strlen(str));
		generate(out, c);
	}
}

char str[10000];
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
	int pid = fork();
	if(pid == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {printf("FAILED!");exit(1);}

		int newOut = open("/dev/null", O_WRONLY);
		dup2(newOut, 1);
		dup2(newOut, 2);

		execl("/usr/bin/make", "make", "clean", "all", NULL);
	} else {
		int lock = 0;
		int p;
		int s;

		int attached = 0;
		printf("Main tracked process is %d\n", pid);

		Process* mainProcess = new Process(pid);
		std::unordered_map<int, Process*> processes;

		int i = 0;
		bool created = false;

		while((p = wait(&s)) > 0) {
			Process *process = processes[p];
			if(!process) {
				process = new Process(p);
				processes[p] = process;
			}

			// stop and trace all childs of traced process
			if(!attached && p == pid) {
				if(ptrace(PTRACE_SETOPTIONS, pid, NULL,  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) !=0) {
					perror("setopts");
					exit(1);
				}
				printf("installed\n");
				attached = 1;
			}

			// new process is forked
			bool forked = s>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8));
			bool vforked = s>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8));
			bool cloned =  s>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8));
			if(forked || vforked || cloned) {
				int newpid;
				ptrace(PTRACE_GETEVENTMSG, p, NULL, &newpid);

				Process* parent = find(p, mainProcess);

				Process* child = processes[newpid];
				if(!child) {
					child = new Process(newpid);
				}
				parent->childs.push_back(child);

				char *msg;
				static char *msgs[] = {"forked", "vforked", "cloned"};

				if(forked) {
					msg = msgs[0];
				}
				if(vforked) {
					msg = msgs[1];
				}
				if(cloned) {
					msg = msgs[2];
				}


				printf("[%d] %s %d\n", p, msg, newpid);
				created = true;
			}

			if(WIFEXITED(s)) {
				printf("[%d] exit\n", p);
			}


			long orig_rax = ptrace(PTRACE_PEEKUSER, p, 8 * ORIG_RAX, NULL);

			if(orig_rax == SYS_execve) {
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, p, NULL, &regs);
				if(process->syscall == 0) {
					if(regs.rdi > 0) {
						process->syscall = 1;
						getString(p, regs.rdi);

						process->cmd[0] = 0;
						strcat(process->cmd, str);
						strcat(process->cmd, " ");

						printf("[%d] execve(%s, {", p, str);

						int i = 0;
						while(1) {
							long addr = ptrace(PTRACE_PEEKDATA, p, regs.rsi + 8*i, NULL);
							if(addr == 0) break;
							getString(p, addr);

							strcat(process->cmd, str);
							strcat(process->cmd, " ");

							printf("%s, ", str);
							i++;
						}

						printf("})\n");
						created = true;
					}
				} else {
					process->syscall = 0;
					long rax = ptrace(PTRACE_PEEKUSER, p, 8 * RAX, NULL);
					printf("[%d] ... returned %ld %s\n", p, rax, strerror(-regs.rax));
				}
			} else {
				//printf("[%d] syscall %d %s\n", p, orig_rax, syscall_name[orig_rax]);
			}

			ptrace(PTRACE_SYSCALL, p, 0, 0);
			created = false;
		}
	}

	return 0;
}