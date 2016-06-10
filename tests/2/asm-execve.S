global _start

section .data
	exe: db "/usr/bin/who", 0
	arg0: db "who", 0
	arg: dq arg0, 0

_start:
	mov rax, 59
	mov rdi, exe
	mov rsi, arg
	syscall

	mov rax, 60
	mov rdi, 0
	syscall
