#pragma once
#include <stdint.h>

#if __x86_64__
	typedef int64_t word_t;
#elif __i386__
	typedef int32_t word_t;
#elif __arm__
	typedef int32_t word_t;
#endif

typedef struct {
	word_t syscall;
	word_t arguments[6];
	word_t ret;
	word_t stack;
} Register;

void loadRegisters(int pid, Register &reg);
void saveRegisters(int pid, const Register reg);