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

#define LOG(...) fprintf(stderr, __VA_ARGS__)
//#define LOG(...)

#if __x86_64__
	typedef uint64_t word_t;
	typedef struct user_regs_struct NativeRegs;
#elif __i386__
	typedef int32_t word_t;
	typedef struct user_regs_struct NativeRegs;
#elif __arm__
	typedef int32_t word_t;
	typedef struct user_regs NativeRegs;
#endif

typedef struct {
	word_t syscall;
	word_t arguments[6];
	word_t ret;
	word_t stack;
} Register;

void mapRegisters(const NativeRegs &, Register &reg);
void mapRegisters(const Register reg, NativeRegs &orig);

#if __x86_64__
void mapRegisters(const NativeRegs &orig, Register &reg) {
	reg.syscall = orig.orig_rax;
	reg.arguments[0] = orig.rdi;
	reg.arguments[1] = orig.rsi;
	reg.arguments[2] = orig.rdx;
	reg.arguments[3] = orig.r10;
	reg.arguments[4] = orig.r8;
	reg.arguments[5] = orig.r9;
	reg.ret = orig.rax;
	reg.stack = orig.rsp;
}

void mapRegisters(const Register reg, NativeRegs &orig) {
	orig.orig_rax = reg.syscall;
	orig.rdi = reg.arguments[0];
	orig.rsi = reg.arguments[1];
	orig.rdx = reg.arguments[2];
	orig.r10 = reg.arguments[3];
	orig.r8 = reg.arguments[4];
	orig.r9 = reg.arguments[5];
	orig.rax = reg.ret;
	orig.rsp = reg.stack;
}
#elif __i386__
void mapRegisters(const NativeRegs &orig, Register &reg) {
	reg.syscall = orig.orig_eax;
	reg.arguments[0] = orig.ebx;
	reg.arguments[1] = orig.ecx;
	reg.arguments[2] = orig.edx;
	reg.arguments[3] = orig.esi;
	reg.arguments[4] = orig.edi;
	reg.arguments[5] = orig.ebp;
	reg.ret = orig.eax;
	reg.stack = orig.esp;
}

void mapRegisters(const Register reg, NativeRegs &orig) {
	orig.orig_eax = reg.syscall;
	orig.ebx = reg.arguments[0];
	orig.ecx = reg.arguments[1];
	orig.edx = reg.arguments[2];
	orig.esi = reg.arguments[3];
	orig.edi = reg.arguments[4];
	orig.ebp = reg.arguments[5];
	orig.eax = reg.ret;
	orig.esp = reg.stack;
}
#elif __arm__
void mapRegisters(const NativeRegs &orig, Register &reg) {
	reg.syscall = orig.uregs[7];
	for(int i = 0; i < 6; i++) {
		reg.arguments[i] = orig.uregs[i];
	}

	reg.ret = orig.uregs[0];
	reg.stack = orig.uregs[13];
}

void mapRegisters(const Register reg, NativeRegs &orig) {
	orig.uregs[7] = reg.syscall;
	for(int i = 0; i < 6; i++) {
		orig.uregs[i] = reg.arguments[i];
	}

	orig.uregs[0] = reg.ret;
	orig.uregs[13] = reg.stack;
}
#else
#error unsupported architecture
#endif

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

void handle_execve(Register &reg, Process *process, int pargc, char **pargv);

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
	if(argc <= 2) {
		printf("Usage: %s /path/to/replace /path/to/replace/with arguments to add\n", argv[0]);
		exit(1);
	}

	int mainPid = fork();
	if(mainPid == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {printf("FAILED!");exit(1);}

		int newOut = open("/dev/null", O_WRONLY);
		//dup2(newOut, 1);
		//dup2(newOut, 2);

		//execl("/usr/bin/make", "make", "clean", "all", NULL);
		//execl("/usr/bin/make", "make", "-C", "tests/3", "clean", "all", NULL);
		execl("./simple", "simple", 0);
	} else {
		int pid;
		int status;
		int attached = 0;

		LOG("Main tracked process is %d\n", mainPid);

		std::unordered_map<int, Process*> processes;

		while((pid = waitpid(-1, &status, __WALL)) > 0) {
			Process *process = processes[pid];
			if (!process) {
				process = new Process(pid);
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
				} else {
					NativeRegs archRegs;
					ptrace(PTRACE_GETREGS, process->pid, NULL, &archRegs);
					Register reg;
					mapRegisters(archRegs, reg);

					if (reg.syscall == SYS_execve) {
						handle_execve(reg, process, argc, argv);
					} else {
						//printf("[%d] syscall %d\n", process->pid, reg.syscall);
					}
				}
			}
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
		}
	}

	return 0;
}

void handle_execve(Register &reg, Process *process, int pargc, char **pargv) {
	char *replace = pargv[1];
	char *replaceWith = pargv[2];

	if(process->syscall == 0) {

		if(reg.arguments[0] > 0) {
			retry:
			NativeRegs archRegs;
			ptrace(PTRACE_GETREGS, process->pid, NULL, &archRegs);
			mapRegisters(archRegs, reg);


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
				NativeRegs archRegs;

				const char *str = replaceWith;
				int argc = process->args.size() + (pargc - 3) + 1;
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

				for(int j = 3; j < pargc; j++) {
					args[i] = pargv[j];
					i++;
				}

				// write new executable path
				putString(process->pid, reg.stack, str);
				reg.arguments[0] = reg.stack;

				mapRegisters(reg, archRegs);
				ptrace(PTRACE_SETREGS, process->pid, NULL, &archRegs);
				ptrace(PTRACE_POKEUSER, process->pid, sizeof(word_t) * 0, reg.arguments[0]);

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
				mapRegisters(reg, archRegs);
				ptrace(PTRACE_SETREGS, process->pid, NULL, &archRegs);

				goto retry;
			}
		}
	} else {
		process->syscall = 0;
		LOG("[%d] ... returned %ld %s\n", process->pid, reg.ret, strerror(-reg.ret));
	}
}