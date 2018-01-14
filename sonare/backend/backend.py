from sortedcontainers import SortedDict


class Symbol(object):
    def __init__(self, name, addr):
        self.name = name
        self.addr = addr

    def __repr__(self):
        return f"Symbol({self.name!r})"


class SymbolTable(object):
    def __init__(self):
        self.by_name = SortedDict()
        self.by_addr = SortedDict()

    def __repr__(self):
        return f"<SymbolTable, {len(self.by_name)} symbols>"

    def add(self, sym):
        self.by_name[sym.name] = sym.addr
        self.by_addr[sym.addr] = sym.name


class Backend(object):
    def __init__(self):
        self.symbols = SymbolTable()
