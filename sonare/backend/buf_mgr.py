import os
from operator import attrgetter
from collections import namedtuple
from mmap import mmap
from sortedcontainers import SortedListWithKey
from struct import unpack_from


MappedBuffer = namedtuple("MappedBuffer", "start map_obj")


class BufferManager:
    ENDIANNESS = "="

    def __init__(self, buf_dir):
        self.buf_dir = buf_dir

        if not self.running_from_memory and not os.path.isdir(self.buf_dir):
            os.makedirs(self.buf_dir)

        self.buffers = SortedListWithKey(key=attrgetter("start"))

    def clear(self):
        self.buffers.clear()

    @property
    def running_from_memory(self):
        return self.buf_dir is None

    def _get_buf_path(self, start):
        return os.path.join(self.buf_dir, f"buf_{start:x}")

    def load(self, start):
        """load buffer that starts at `start` from disk"""

        if self.running_from_memory:
            raise Exception("running from memory, can't load buffer from disk")

        filename = self._get_buf_path(start)
        f = open(filename, "r+b")
        map_obj = mmap(f.fileno(), 0)
        self.buffers.add(MappedBuffer(start, map_obj))

    def add(self, start, data):
        if self.running_from_memory:
            map_obj = mmap(-1, len(data))
            map_obj[:] = data
            self.buffers.add(MappedBuffer(start, map_obj))
            return

        filename = self._get_buf_path(start)

        with open(filename, "wb") as f:
            f.write(data)

        self.load(start)

    def get_mapped_buf(self, addr):
        i = self.buffers.bisect_key_left(addr)
        if i < len(self.buffers):
            if addr == self.buffers[i].start:
                return self.buffers[i]
            elif i > 0:
                mapped_buf = self.buffers[i - 1]
                assert addr >= mapped_buf.start

                end = mapped_buf.start + len(mapped_buf.map_obj)
                if addr < end:
                    return mapped_buf

        raise KeyError(f"address {addr:#x} not found in loaded buffers")

    def get_buf_ofs(self, addr):
        mapped_buf = self.get_mapped_buf(addr)
        return (mapped_buf, addr - mapped_buf.start)

    def get_struct(self, fmt, addr):
        mapped_buf, ofs = self.get_buf_ofs(addr)
        return unpack_from(self.ENDIANNESS + fmt, mapped_buf.map_obj, ofs)

    def get_bytes(self, addr, size):
        mapped_buf, ofs = self.get_buf_ofs(addr)
        result = mapped_buf.map_obj[ofs:ofs + size]

        if len(result) < size:
            raise KeyError(
                f"only found {len(result):#x} bytes @ {addr:#x},"
                f" instead of {size:#x}")

        return result

    def get_byte(self, addr):
        return self.get_struct("B", addr)[0]

    def get_short(self, addr):
        return self.get_struct("H", addr)[0]

    def get_long(self, addr):
        return self.get_struct("L", addr)[0]
