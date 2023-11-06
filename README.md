# mini-gdbstub-ck804

`mini-gdbstub-ck804` is an implementation of the
[GDB Remote Serial Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html)
that gives your emulators debugging capabilities.

For the user whose cpu is csky ck804, the code can be debugged without the real debugger (CK LINK).
There's a catch, of course, which is that you need to export the current stack register and the memory region, which I call ramdump.

## Usage

First, launch mini-gdbstub-ck804 with `gdbstub_ck804 <elf_file> <ramdump_file> [port]`, for example:
```
./gdbstub_ck804 ./project.elf ./project.ramdump 6688
```

Second, run the gdb program, for example:

```cpp
csky-elfabiv2-gdb ./project.elf
```

Third, connect the gdb stub, for example:

```cpp
target remote :6688
```

If the connection fails, it's probably due to a firewall, so close or add the rule.

When the connection is successful, you can debug normally, you can use such as bt, p, set $pc, etc.

At present, only the functions related to register reading and writing and memory reading are implemented, and other functions are not supported.

This is actually very similar to gdb+corefile. For example, part of the csky cpu toolchain is not open source, and the corefile format is not known, so the gdb stub method is more general and not limited to the corefile issue.

## Compile

This project supports linux and windows use, compile command:

```cpp
make
```

After successful compilation, the executable will be in the `build` directory.

The core of gdbstub is mini-gdbstub. Currently, it also provides the function of generating lib:

```cpp
make lib
```

For debugging and learning, log information can be added to compile:

```cpp
make debug
```

Tip: On windows, you can use cygwin or mingw to compile.

## Reference
### Project
* [RinHizakura/mini-gdbstub](https://github.com/RinHizakura/mini-gdbstub)
### Article
* [GDB Remote Serial Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html)
