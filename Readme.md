# ptrace - replace execle
* architecture dependent - each architecture needs function that stores and loads registers and maps them to structure
    * syscall
    * syscall result
    * parameters registers
* currently supported x86, x86_64 and arm eabi (tested on raspberry pi)
* slow, because on each syscall process is paused and waits untill it is resumed
* every execve is tracked, it is not possible to evade (?)

## Build
```sh
$ make all tests
```

## Examples
## replace `who` with `ls -l` in `xterm`
```sh
$ ./change /usr/bin/xterm /usr/bin/who /usr/bin/ls -l
```

## replace `cc` with `gcc` while building project
```sh
$ ./change /usr/bin/make -C tests/3 clean all -- /usr/bin/cc /usr/bin/gcc
```