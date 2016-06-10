# LD_PRELOAD
* architecture independent
* could evade
    - by replacing LD_PRELOAD
```sh
LD_PRELOAD=$PWD/preload.so sh -c 'unset LD_PRELOAD; sh -c who '
```
    - not using execve() directly, eg calling syscall or maybe static lib?
```sh
LD_PRELOAD=$PWD/preload.so sh -c '../tests/2/asm-execve'
```

## Build
```sh
$ make && make -C .. tests
```

## Examples
## replace `who` with `ls`
```sh
$ LD_PRELOAD=$PWD/preload.so sh -c 'who'
[22128] preload loaded
[22128] execve(/usr/bin/who, [who, ], ...env..)
[22128] execve /usr/bin/who replaced with /usr/bin/ls!
[22128] preload loaded
a.out  Makefile  preload.cpp  preload.o  preload.so  Readme.md
```

## replace `cc` with `gcc`
Set 
```cpp
#define REPLACE "/usr/bin/g++"
#define REPLACE_WITH "/usr/bin/c++"
```
in preload.cpp and execute

```sh
$ LD_PRELOAD=$PWD/preload.so sh -c 'make -C ../tests/3/ clean all'
```

