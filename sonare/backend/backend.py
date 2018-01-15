import sqlite3
import json


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


class Backend:
    def __init__(self, filename=":memory:"):
        self.db = sqlite3.connect(
            filename, detect_types=sqlite3.PARSE_DECLTYPES)

        self.sections = RangeTable(self.db, "sections")
        self.symbols = RangeTable(self.db, "symbols")
