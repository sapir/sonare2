import sqlite3
import json
import os
from operator import attrgetter
from collections import namedtuple
from mmap import mmap
from sortedcontainers import SortedListWithKey
from struct import unpack_from


sqlite3.register_adapter(dict, json.dumps)
sqlite3.register_converter("json", json.loads)


class Symbol:
    def __init__(self, name, addr, size=1):
        self.name = name
        self.addr = addr
        self.size = size

    def __repr__(self):
        return f"Symbol({self.name!r})"


class Range:
    """
    A [start address, end address] range, possibly with extra attributes.

    Ranges include the start address but not the end address.
    """

    def __init__(self, start, end=None, name=None, attrs=None, size=None):
        self.start = start
        self.attrs = {} if attrs is None else attrs

        if end is None:
            if size is None:
                self.end = start + 1
            else:
                self.end = start + size
        else:
            assert size is None, "Please specify size or end but not both."
            self.end = end

        self.name = name

    def __repr__(self):
        return f"Range({self.start:#x}, {self.end:#x}, name={self.name!r})"

    @property
    def size(self):
        return self.end - self.start

    def __contains__(self, addr):
        return self.start <= addr < self.end


class RangeTable:
    """
    An indexed list of Range objects, stored in the database.
    """

    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.autocreate()

    def __repr__(self):
        return f"<RangeTable {self.name!r}>"

    def autocreate(self):
        self.db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.name} (
                start int,
                end int,
                name text,
                attrs json,
                PRIMARY KEY (start)
            )
            """)

        self.db.execute(f"""
            CREATE UNIQUE INDEX IF NOT EXISTS {self.name}_end_idx
            ON {self.name} (end)
            """)

        self.db.execute(f"""
            CREATE UNIQUE INDEX IF NOT EXISTS {self.name}_name_idx
            ON {self.name} (name)
            """)

    def _query_first(self, *args):
        cur = self.db.cursor()
        cur.execute(*args)
        return cur.fetchone()

    def _row_to_obj(self, row):
        return Range(*row)

    def _query_first_obj(self, *args):
        row = self._query_first(*args)
        if row is None:
            return None
        else:
            return self._row_to_obj(row)

    def get_at(self, addr):
        return self._query_first_obj(
            f"""
            SELECT * FROM {self.name}
            WHERE {addr} BETWEEN start AND end - 1
            """)

    def get_first_after(self, addr):
        """does not include any range including addr"""

        return self._query_first_obj(
            f"""
            SELECT * FROM {self.name}
            WHERE start > {addr}
            ORDER BY start
            LIMIT 1
            """)

    def get_last_before(self, addr):
        """does not include any range including addr"""

        return self._query_first_obj(
            f"""
            SELECT * FROM {self.name}
            WHERE end <= {addr}
            ORDER BY end DESC
            LIMIT 1
            """)

    def get_by_name(self, name):
        return self._query_first_obj(
            f"SELECT * FROM {self.name} WHERE name = ? LIMIT 1",
            (name, ))

    def add(self, start, end=None, name=None, **kwargs):
        if end is None:
            end = start + 1

        cur = self.db.cursor()
        cur.execute(
            f"""
            INSERT INTO {self.name}(start, end, name, attrs)
            VALUES(?, ?, ?, json(?))
            """,
            (start, end, name, kwargs))

    def add_obj(self, range_obj):
        return self.add(
            range_obj.start,
            range_obj.end,
            range_obj.name,
            **range_obj.attrs)

    def __len__(self):
        return self._query_first(f"SELECT COUNT(*) FROM {self.name}")[0]

    def iter_by_addr(self):
        cur = self.db.cursor()
        cur.execute(f"SELECT * FROM {self.name} ORDER BY start")
        return map(self._row_to_obj, cur)

    def iter_by_name(self):
        cur = self.db.cursor()
        cur.execute(f"SELECT * FROM {self.name} ORDER BY name")
        return map(self._row_to_obj, cur)

    def iter_where_overlaps(self, start, end):
        cur = self.db.cursor()
        cur.execute(
            f"""
            SELECT * FROM {self.name}
            WHERE ? BETWEEN start AND end - 1
               OR start BETWEEN ? AND ? - 1
            ORDER BY start
            """,
            (start, start, end))

        return map(self._row_to_obj, cur)


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

    def get_byte(self, addr):
        return self.get_struct("B", addr)[0]

    def get_short(self, addr):
        return self.get_struct("H", addr)[0]

    def get_long(self, addr):
        return self.get_struct("L", addr)[0]


class SectionTable(RangeTable):
    def __init__(self, db, buf_mgr):
        super().__init__(db, "sections")

        self.db = db
        self.buf_mgr = buf_mgr
        self._load()

    def _load(self):
        with self.db:
            self.buf_mgr.clear()

            for section in self.iter_by_addr():
                self.buf_mgr.load(section.start)

    def add(self, start, data, **kwargs):
        with self.db:
            end = start + len(data)

            overlaps = list(self.iter_where_overlaps(start, end))
            if overlaps:
                raise Exception(
                    f"{start:#x}-{end:#x} overlaps with: {overlaps!r}")

            self.buf_mgr.add(start, data)

            super().add(start, end, **kwargs)


class Backend:
    def __init__(self, filename=None):
        self.filename = filename

        self.db = sqlite3.connect(
            self._sqlite_path,
            detect_types=sqlite3.PARSE_DECLTYPES)

        self.buf_mgr = BufferManager(self.buf_dir)

        self.sections = SectionTable(self.db, self.buf_mgr)
        self.symbols = RangeTable(self.db, "symbols")

    @property
    def _sqlite_path(self):
        return ":memory:" if self.filename is None else self.filename

    @property
    def buf_dir(self):
        if self.filename is None:
            return None
        else:
            return f"{self.filename}.buffers"
