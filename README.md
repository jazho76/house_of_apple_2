# House of Apple 2

FSOP: File Stream Oriented Programming. General idea, abuse the vtable dispatch of \_IO_FILE_PLUS structs to achieve arbitrary function calls.

## Start sandbox

```
./build.sh
./run.sh
```

## fwrite payload path

1. Corrupt the vtable of \_IO_FILE_plus struct so an `fwrite`/`fputs` dispatch (`vtable + 0x38`, `__xsputn`) lands where we want. This alone would be an arbitrary call, except libc validates the vtable pointer (https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L935).
   The check is only a range check against the `__libc_IO_vtables` section, with no alignment requirement. So we keep the pointer inside that section but shift it to call `_IO_wfile_overflow` instead of the intended function.
2. `_IO_wfile_overflow` calls `_IO_wdoallocbuf`.
3. `_IO_wdoallocbuf` reads the `_wide_data` field of the file struct and dispatches through \_wide_data->\_wide_vtable. (https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libio.h#L144)
4. It calls `_wide_vtable + 0x68` with no pointer validation. This is the hole!
5. We forge `_wide_vtable` so that `_wide_vtable + 0x68` holds a pointer to the function we want to call.

## Memory layout

A full `_IO_FILE_plus` + a full `_IO_wide_data`, each with its own vtable, would require a large buffer. Instead, we overlap both structures and the `_wide_data` vtable.

## Controlling the first argument

`_IO_wdoallocbuf` always calls `_wide_vtable + 0x68` with a pointer to the file struct as the first argument. So, rdi = pointer to memory we control. If the target function dereferences this pointer, we can place the pointed data at offset 0x0 of the file struct.

There are some constraints on that data:

1. Don't clobber `_lock` (offset `0x88`): `_lock` must point to a writable, zeroed qword so the lock can be acquired.
2. Offset `0` is `_flags` (4 bytes). The normal `_IO_MAGIC` high bytes are not checked, so we can use them, but two bits in the low byte can be checked depending on the path we're exploiting.
