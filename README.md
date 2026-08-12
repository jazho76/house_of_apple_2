# House of Apple 2

**FSOP: File Stream Oriented Programming**. General idea: abuse the vtable dispatch of \_IO_FILE_PLUS structs to achieve arbitrary function calls. Still valid in latest glibc versions.

Let's start with the \_IO_FILE_plus struct, this is a FILE struct with an additional vtable pointer.

```c
type = struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}

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
    int _flags2;
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
    size_t __pad5;
    int _mode;
    char _unused2[20];
}
```

The vtable is used to dispatch various operations on the file stream, such as reading, writing, and flushing. Closer look at [fwrite](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/iofwrite.c#L30).

```c
size_t _IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  size_t request = size * count;
  size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

\_IO_sputn in line 39 is a macro that dispatches `vtable[__xsputn]` function.

In gdb while walking through `fwrite`, there is an indirect call to `vtable + 0x38`.

```
b► 0x7f9a65ab8ae2 <fwrite+194>    mov    rax, qword ptr [rbp - 0x38]     RAX, [0x7ffff86a2a08] => 0x7f9a65c34030 (_IO_file_jumps) ◂— 0
   0x7f9a65ab8ae6 <fwrite+198>    mov    rdx, r13                        RDX => 1
   0x7f9a65ab8ae9 <fwrite+201>    mov    rsi, r15                        RSI => 0x13f12480 ◂— 0x41 /* 'A' */
   0x7f9a65ab8aec <fwrite+204>    mov    rdi, rbx                        RDI => 0x13f122a0 ◂— 0xfbad2480
   0x7f9a65ab8aef <fwrite+207>    call   qword ptr [rax + 0x38]      <_IO_file_xsputn>

   0x7f9a65ab8af2 <fwrite+210>    cmp    rax, -1
   0x7f9a65ab8af6 <fwrite+214>    sete   r15b
   0x7f9a65ab8afa <fwrite+218>    test   dword ptr [rbx], 0x8000
   0x7f9a65ab8b00 <fwrite+224>  ? je     fwrite+293                  <fwrite+293>

   0x7f9a65ab8b02 <fwrite+226>    cmp    r13, rax
   0x7f9a65ab8b05 <fwrite+229>  ? je     fwrite+240                  <fwrite+240>
```

inspecting `_IO_file_jumps` symbol in gdb:

```
pwndbg> x/20a &_IO_file_jumps
0x7f9a65c34030 <_IO_file_jumps>:        0x0     0x0
0x7f9a65c34040 <_IO_file_jumps+16>:     0x7f9a65ac3b20 <_IO_new_file_finish>    0x7f9a65ac4ed0 <_IO_new_file_overflow>
0x7f9a65c34050 <_IO_file_jumps+32>:     0x7f9a65ac4720 <_IO_new_file_underflow> 0x7f9a65ac7680 <__GI__IO_default_uflow>
0x7f9a65c34060 <_IO_file_jumps+48>:     0x7f9a65ac8ec0 <__GI__IO_default_pbackfail>     0x7f9a65ac5ac0 <_IO_new_file_xsputn>
0x7f9a65c34070 <_IO_file_jumps+64>:     0x7f9a65ac5e00 <__GI__IO_file_xsgetn>   0x7f9a65ac5240 <_IO_new_file_seekoff>
0x7f9a65c34080 <_IO_file_jumps+80>:     0x7f9a65ac7da0 <_IO_default_seekpos>    0x7f9a65ac44e0 <_IO_new_file_setbuf>
0x7f9a65c34090 <_IO_file_jumps+96>:     0x7f9a65ac50f0 <_IO_new_file_sync>      0x7f9a65ab7200 <__GI__IO_file_doallocate>
0x7f9a65c340a0 <_IO_file_jumps+112>:    0x7f9a65ac5990 <__GI__IO_file_read>     0x7f9a65ac5a20 <_IO_new_file_write>
0x7f9a65c340b0 <_IO_file_jumps+128>:    0x7f9a65ac59b0 <__GI__IO_file_seek>     0x7f9a65ac5a10 <__GI__IO_file_close>
0x7f9a65c340c0 <_IO_file_jumps+144>:    0x7f9a65ac59c0 <__GI__IO_file_stat>     0x7f9a65ac9070 <_IO_default_showmanyc>
```

The expected execution flow is `vtable + 0x38` -> `_IO_new_file_xsputn`. The obvious target is to set the vtable pointer to `desired_func - 0x38`, but this won't work by its own. By inspecting some previous instructions we can see that the vtable pointer is validated before the call:

```
   0x7f51d381fab7 <fwrite+151>    mov    dword ptr [rbx + 0xc0], 0xffffffff     [0x3a788360] <= 0xffffffff
   0x7f51d381fac1 <fwrite+161>    mov    rax, qword ptr [rbx + 0xd8]            RAX, [0x3a788378] => 0x7f51d399b030 (_IO_file_jumps) ◂— 0
   0x7f51d381fac8 <fwrite+168>    lea    rdx, [rip + 0x17b411]                  RDX => 0x7f51d399aee0 (__io_vtables) ◂— 0
   0x7f51d381facf <fwrite+175>    mov    qword ptr [rbp - 0x38], rax            [0x7fffb1999368] <= 0x7f51d399b030 (_IO_file_jumps) ◂— 0
   0x7f51d381fad3 <fwrite+179>    sub    rax, rdx                               RAX => 0x150 (0x7f51d399b030 - 0x7f51d399aee0)
 ► 0x7f51d381fad6 <fwrite+182>    cmp    rax, 0x92f                             0xa00 - 0x92f     EFLAGS => 0x216 [ cf PF AF zf sf IF df of iopl:00 ac ]
   0x7f51d381fadc <fwrite+188>  ✔ ja     fwrite+472                  <fwrite+472>
    ↓
   0x7f51d381fbf8 <fwrite+472>    call   _IO_vtable_check            <_IO_vtable_check>

   0x7f51d381fbfd <fwrite+477>    jmp    fwrite+194                  <fwrite+194>
    ↓
   0x7f51d381fae2 <fwrite+194>    mov    rax, qword ptr [rbp - 0x38]
   0x7f51d381fae6 <fwrite+198>    mov    rdx, r13

```

This means there is a range within which we can manipulate our vtable pointer, but we can't place it anywhere. To bypass this constraint we target [\_IO_wfile_overflow](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/wfileops.c#L406), a different function that is withing the valid range. Based on some conditions that are easy to satisfy, this will call `_IO_wdoallocbuf` on line 421.

This function will perform another indirect call to a different vtable, this time on the `_wide_data` struct. This indirect call is not validated and can be used to hijack the control flow.

```
pwndbg> disass
Dump of assembler code for function __GI__IO_wdoallocbuf:
=> 0x00007faf7818ef50 <+0>:     endbr64
   0x00007faf7818ef54 <+4>:     mov    rax,QWORD PTR [rdi+0xa0]
   0x00007faf7818ef5b <+11>:    cmp    QWORD PTR [rax+0x30],0x0
   0x00007faf7818ef60 <+16>:    je     0x7faf7818ef68 <__GI__IO_wdoallocbuf+24>
   0x00007faf7818ef62 <+18>:    ret
   0x00007faf7818ef63 <+19>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x00007faf7818ef68 <+24>:    push   rbp
   0x00007faf7818ef69 <+25>:    mov    rbp,rsp
   0x00007faf7818ef6c <+28>:    push   r13
   0x00007faf7818ef6e <+30>:    push   r12
   0x00007faf7818ef70 <+32>:    push   rbx
   0x00007faf7818ef71 <+33>:    mov    rbx,rdi
   0x00007faf7818ef74 <+36>:    sub    rsp,0x8
   0x00007faf7818ef78 <+40>:    test   BYTE PTR [rdi],0x2
   0x00007faf7818ef7b <+43>:    jne    0x7faf7818efe8 <__GI__IO_wdoallocbuf+152>
   0x00007faf7818ef7d <+45>:    mov    rax,QWORD PTR [rax+0xe0]
   0x00007faf7818ef84 <+52>:    call   QWORD PTR [rax+0x68]

```

Any invocation to `fwrite/fread/fclose` can be redirected in a similar way to a `_IO_wdoallocbuf` call for control flow hijacking through the `_wide_data` vtable.

...

## Start sandbox

```
./build.sh
./run.sh
```

## Memory layout

A full `_IO_FILE_plus` + a full `_IO_wide_data`, each with its own vtable, would require a large buffer. Instead, we overlap both structures and the `_wide_data` vtable.

## Controlling the first argument

`_IO_wdoallocbuf` always calls `_wide_vtable + 0x68` with a pointer to the file struct as the first argument. So, rdi = pointer to memory we control. If the target function dereferences this pointer, we can place the pointed data at offset 0x0 of the file struct.

There are some constraints on that data:

1. Don't clobber `_lock` (offset `0x88`): `_lock` must point to a writable, zeroed qword so the lock can be acquired.
2. Offset `0` is `_flags` (4 bytes). The normal `_IO_MAGIC` high bytes are not checked, so we can use them, but two bits in the low byte can be checked depending on the path we're exploiting.
