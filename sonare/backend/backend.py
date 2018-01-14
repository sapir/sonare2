from sortedcontainers import SortedDict, SortedListWithKey


class Symbol:
    def __init__(self, name, addr):
        self.name = name
        self.addr = addr

    def __repr__(self):
        return f"Symbol({self.name!r})"


class SymbolTable:
    def __init__(self):
        self.by_name = SortedDict()
        self.by_addr = SortedDict()

    def __repr__(self):
        return f"<SymbolTable, {len(self.by_name)} symbols>"

    def add(self, sym):
        self.by_name[sym.name] = sym.addr
        self.by_addr[sym.addr] = sym.name


class Section:
    def __init__(self, addr, buf, name=None):
        self.name = name
        self.addr = addr
        self.buf = buf

    def __repr__(self):
        return f"<Section {self.name!r} @ {self.addr:#x}>"

    @property
    def size(self):
        return len(self.buf)

    @property
    def start(self):
        return self.addr

    @property
    def end(self):
        return self.start + self.size

    def contains(self, addr):
        return self.start <= addr < self.end


class SectionTable:
    def __init__(self):
        self.by_addr = SortedListWithKey(key=lambda section: section.addr)

    def add(self, section):
        self.by_addr.add(section)

    def get_at(self, addr):
        i = self.by_addr.bisect_key_left(addr)

        try:
            # if addr == section start
            section = self.by_addr[i]
            if section.contains(addr):
                return section

            # usual case
            if i > 0:
                section = self.by_addr[i - 1]
                if section.contains(addr):
                    return section

            return None

        except IndexError:
            # if we got an invalid index, then address definitely isn't
            # included in a section
            return None


class Backend:
    def __init__(self):
        self.sections = SectionTable()
        self.symbols = SymbolTable()
