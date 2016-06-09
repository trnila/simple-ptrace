#include <sys/user.h>
#include <sys/ptrace.h>
#include "arch.h"

#if __x86_64__
void loadRegisters(int pid, Register &reg) {
	struct user_regs_struct orig;
	ptrace(PTRACE_GETREGS, pid, 0, &orig);

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

void saveRegisters(int pid, const Register reg) {
	struct user_regs_struct orig;

	orig.orig_rax = reg.syscall;
	orig.rdi = reg.arguments[0];
	orig.rsi = reg.arguments[1];
	orig.rdx = reg.arguments[2];
	orig.r10 = reg.arguments[3];
	orig.r8 = reg.arguments[4];
	orig.r9 = reg.arguments[5];
	orig.rax = reg.ret;
	orig.rsp = reg.stack;

	ptrace(PTRACE_SETREGS, pid, 0, &orig);
}
#elif __i386__
void loadRegisters(int pid, Register &reg) {
	struct user_regs_struct orig;
	ptrace(PTRACE_GETREGS, pid, 0, &orig);

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

void saveRegisters(int pid, const Register reg) {
	struct user_regs_struct orig;

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
//TODO: why PTRACE_SETREGS not working for arm? ptrace returns invalid argument
void loadRegisters(int pid, Register &reg) {
	struct user_regs orig;
	ptrace(PTRACE_GETREGS, pid, 0, &orig);

	reg.syscall = orig.uregs[7];
	for(int i = 0; i < 6; i++) {
		reg.arguments[i] = orig.uregs[i];
	}

	reg.ret = orig.uregs[0];
	reg.stack = orig.uregs[13];
}

void saveRegisters(int pid, const Register reg) {
	struct user_regs orig;
	orig.uregs[7] = reg.syscall;
	for(int i = 0; i < 6; i++) {
		orig.uregs[i] = reg.arguments[i];
	}

	orig.uregs[0] = reg.ret;
	orig.uregs[13] = reg.stack;

	for(int i = 0; i < 8; i++) {
		ptrace(PTRACE_POKEUSER, pid, sizeof(word_t) * i, reg.arguments[i]);
	}

	//todo: 13 is not needed
}
#else
	#error unsupported architecture
#endif