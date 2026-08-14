# Walk through

Let's start by inspecting \_IO_FILE and \_IO_FILE_plus structs. This is the struct returned by fopen to deal with file streams.

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

\_IO_FILE_plus is just a FILE with a vtable. A vtable is always an oportunity to hijack the control flow. By controlling the vtable pointer we can decide where to jump in an indirect function call.

Let's explore this vtable by inspecting a FILE pointer returned by fopen.

```c
pwndbg> x/a ((struct _IO_FILE_plus *)0x87b8010)->vtable
0x7f91cc001030 <_IO_file_jumps>:        0x0
```

It is targetting \_IO_file_jumps symbol.

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

This is a set of 21 function pointers that are dispatched through the vtable on file stream operations depending on the exection flow.

I'll be focusing on `fwrite` flow for this run. Let's place a breakpoint on each of these functions and call fwrite to see what is called first.

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
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffdc1b9bcd8 —▸ 0x7f91cbe7d63b (fwrite+219) ◂— mov edx, dword ptr [rbx]
01:0008│-050 0x7ffdc1b9bce0 —▸ 0x7ffdc1b9bd00 ◂— 1
02:0010│-048 0x7ffdc1b9bce8 —▸ 0x7f91cbf1832e (read+30) ◂— leave
03:0018│-040 0x7ffdc1b9bcf0 ◂— 0
04:0020│-038 0x7ffdc1b9bcf8 ◂— 1
... ↓        2 skipped
07:0038│-020 0x7ffdc1b9bd10 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0 0x7f91cbe8b400 _IO_file_xsputn
   1 0x7f91cbe7d63b fwrite+219
   2 0x401863       op_fwrite+151
   3 0x401b57       main+347
   4 0x7f91cbe1a601 __libc_start_call_main+129
   5 0x7f91cbe1a718 __libc_start_main+136
   6 0x401185       _start+37

```

The first one is \_IO_file_xsputn, through fwrite+216. It can be confirmed [here](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/iofwrite.c#L44), as \_IO_sputn is a macro that dispatches to \_IO_file_xsputn through the vtable.

```asm
   0x00007f91cbe7d62a <+202>:   mov    rdx,rcx
   0x00007f91cbe7d62d <+205>:   mov    rdi,rbx
   0x00007f91cbe7d630 <+208>:   mov    QWORD PTR [rbp-0x30],r8
   0x00007f91cbe7d634 <+212>:   mov    QWORD PTR [rbp-0x28],rcx
   0x00007f91cbe7d638 <+216>:   call   QWORD PTR [rax+0x38]
```

Let's try to use this in a new run to overwrite the vtable with `desired_func - 0x38` and breakpoint at fwrite+216.

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

Oops, we didn't even get to the breakpoint. the output message suggests that the base pointer is being validated before the indirect call. We need to inspect this closer to understand what is happening. I wish I had ran this with `record full` to go backwards and inspect. let's inspect the backtrace.

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

At some point in fwrite, \_IO_vtable_check is being called and detecting our invalid vtable pointer.

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

Looks like there's a flag to allow foreign vtables, that is out of our control. Let's better see this from source [here](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/vtables.c#L504).

Wait, I thought this was going to perform the check on whether the vtable pointer is valid or not, but it looks like at this point we're already doomed, except for some very specific cases that are out of our control. I missed the call to `IO_validate_vtable` in the backtrace. Let's inspect this function.

```c
pwndbg> disass IO_validate_vtable
❌️ No symbol "IO_validate_vtable" in current context.
```

Looks like there is no symbol for this function, it might be inlined in fwrite. Actually, [it is](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/libioP.h#L1033).

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

Then, a valid pointer should be between \_\_io_tables and \_\_io_tables+0x92f. This means that we can not use an arbitrary function pointer, but there is a lot of space to explore.

All the valid range

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
119:08c8│     0x7f641fe217a8 ◂— 0
... ↓     11 skipped
```

## House of Apple 2

Now we have a good understanding of the mechanism and constraints. There is a well-documented technique to deal with this, House of Apple 2. Let's explore this live in gdb instead of reading it from an inert paper.

There is a `_wide_data` field in our previous `_IO_FILE` structure, which is a pointer to a `_IO_wide_data` structure.
