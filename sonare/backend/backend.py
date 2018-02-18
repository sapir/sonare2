import sqlite3
import json
from threading import RLock
from .buf_mgr import BufferManager
from .arch import BaseArch, ArmArch, AvrArch


sqlite3.register_adapter(dict, json.dumps)
sqlite3.register_converter("json", json.loads)


class Range:
    """
    A [start address, end address] range, possibly with extra attributes.

    Ranges include the start address but not the end address.
    """

    def __init__(self, start, end=None, name=None, attrs=None, size=None,
                 id_=None):

        self.id_ = id_
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

    def copy_new(self):
        """makes a copy without the id_."""
        return Range(self.start, self.end, self.name, self.attrs)


class RangeTable:
    """
    An indexed list of Range objects, stored in the database.
    """

    def __init__(self, db, name, allow_overlaps=True):
        self.db = db
        self.write_lock = RLock()

        self.name = name

        self.allow_overlaps = allow_overlaps

        self.autocreate()

    def __repr__(self):
        return f"<RangeTable {self.name!r}>"

    def autocreate(self):
        with self.write_lock:
            self.db.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.name} (
                    id integer,
                    start integer,
                    end integer,
                    name text,
                    attrs json,
                    PRIMARY KEY (id)
                )
                """)

            unique_str = "" if self.allow_overlaps else "UNIQUE"

            self.db.execute(f"""
                CREATE {unique_str} INDEX IF NOT EXISTS {self.name}_start_idx
                ON {self.name} (start)
                """)

            self.db.execute(f"""
                CREATE {unique_str} INDEX IF NOT EXISTS {self.name}_end_idx
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

    def _query_all(self, *args):
        cur = self.db.cursor()
        cur.execute(*args)
        return cur.fetchall()

    def _row_to_obj(self, row):
        return Range(*row[1:], id_=row[0])

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

    def get_at_many(self, addrs):
        # TODO: use DB to do this better
        return list(filter(None, (self.get_at(addr) for addr in addrs)))

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

    def _add(self, start, end, name, kwargs):
        with self.write_lock:
            cur = self.db.cursor()
            cur.execute(
                f"""
                INSERT INTO {self.name}(start, end, name, attrs)
                VALUES(?, ?, ?, json(?))
                """,
                (start, end, name, kwargs))

            return cur.lastrowid

    def add(self, start, end=None, name=None, **kwargs):
        if end is None:
            end = start + 1

        if not self.allow_overlaps:
            overlaps = list(self.iter_where_overlaps(start, end))
            if overlaps:
                raise Exception(
                    f"{start:#x}-{end:#x} (name={name!r})"
                    f" overlaps with: {overlaps!r}")

        return self._add(start, end, name, kwargs)

    def upsert(self, start, end=None, name=None, **kwargs):
        if end is None:
            end = start + 1

        with self.write_lock:
            existing = self.get_at(start)
            if existing:
                assert existing.end == end

                cur = self.db.cursor()
                cur.execute(
                    f"""
                    UPDATE {self.name}
                    SET name=?, attrs=json_patch(attrs, ?)
                    WHERE id=?
                    """,
                    (name, kwargs, existing.id_))

                return existing.id_
            else:
                return self._add(start, end, name, kwargs)

    def add_obj(self, range_obj):
        """adds object to DB and fills in range_obj.id_."""

        assert range_obj.id_ is None

        id_ = self.add(
            range_obj.start,
            range_obj.end,
            range_obj.name,
            **range_obj.attrs)

        range_obj.id_ = id_

        return id_

    def update_obj(self, range_obj):
        assert range_obj.id_ is not None

        with self.write_lock:
            cur = self.db.cursor()
            cur.execute(
                f"""
                UPDATE {self.name}
                SET start=?, end=?, name=?, attrs=json(?)
                WHERE id=?
                """,
                (range_obj.start, range_obj.end, range_obj.name,
                    range_obj.attrs, range_obj.id_))

    def __len__(self):
        return self._query_first(f"SELECT COUNT(*) FROM {self.name}")[0]

    def iter_by_addr(self):
        cur = self.db.cursor()
        cur.execute(f"SELECT * FROM {self.name} ORDER BY start")
        return map(self._row_to_obj, cur)

    def iter_by_name(self, only_named=True):
        cur = self.db.cursor()
        where_clause = "WHERE name IS NOT NULL" if only_named else ""
        cur.execute(f"SELECT * FROM {self.name} {where_clause} ORDER BY name")
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


class SectionTable(RangeTable):
    def __init__(self, db, buf_mgr):
        super().__init__(db, "sections", allow_overlaps=False)

        self.db = db
        self.buf_mgr = buf_mgr
        self._load()

    def _load(self):
        with self.db:
            self.buf_mgr.clear()

            for section in self.iter_by_addr():
                self.buf_mgr.load(section.start)

    def add(self, start, data, **kwargs):
        with self.write_lock, self.db:
            end = start + len(data)

            super().add(start, end, **kwargs)

            self.buf_mgr.add(start, data)


class AssemblyLinesTable(RangeTable):
    def __init__(self, db):
        super().__init__(db, "lines", allow_overlaps=False)


class ConfigTable:
    def __init__(self, db):
        self.db = db
        self.write_lock = RLock()

        self.name = "config"

        self.autocreate()

    def autocreate(self):
        with self.write_lock:
            self.db.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.name} (
                    key text,
                    value text,
                    PRIMARY KEY (key)
                )
                """)

    def __getitem__(self, k):
        cur = self.db.execute(
            f"SELECT value FROM {self.name} WHERE key = ?",
            (k, ))
        row = cur.fetchone()
        if row is None:
            raise KeyError(k)

        return row[0]

    def __setitem__(self, k, v):
        with self.write_lock:
            self.db.execute(
                f"INSERT OR REPLACE INTO {self.name}(key, value)"
                f" VALUES (?, ?)",
                (k, v))

    def __delitem__(self, k):
        with self.write_lock:
            cur = self.db.cursor()
            cur.execute(
                f"DELETE FROM {self.name} WHERE key = ?",
                (k, ))
            if cur.rowcount == 0:
                raise KeyError(k)

    def get(self, k, default=None):
        try:
            return self[k]
        except KeyError:
            return default


class Backend:
    def __init__(self, filename=None, userdb_filename=None):
        self.filename = filename

        self.userdb_filename = (
            userdb_filename if userdb_filename
            else filename + ".userdb" if filename
            else None)

        self.db = self._connect_to_sqlite(filename)
        self.userdb = self._connect_to_sqlite(userdb_filename)

        self.buf_mgr = BufferManager(self.buf_dir)

        self.config = ConfigTable(self.db)
        self.sections = SectionTable(self.db, self.buf_mgr)
        self.names = RangeTable(self.db, "names")
        self.functions = RangeTable(self.db, "functions", allow_overlaps=False)
        self.asm_lines = AssemblyLinesTable(self.db)

        self.user_lines = AssemblyLinesTable(self.userdb)

    @staticmethod
    def _connect_to_sqlite(filename):
        sqlite_path = ":memory:" if filename is None else filename

        return sqlite3.connect(
            sqlite_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False)

    @property
    def buf_dir(self):
        if self.filename is None:
            return None
        else:
            return f"{self.filename}.buffers"

    def get_arch(self):
        arch_name = self.config.get("arch")

        if arch_name == "Arm":
            cls = ArmArch
        elif arch_name == "Avr":
            cls = AvrArch
        elif arch_name is None:
            cls = BaseArch
        else:
            raise NotImplementedError(arch_name)

        if arch_name is not None:
            assert cls.__name__.startswith(arch_name)

        return cls(self)
