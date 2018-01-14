from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from .backend import Symbol


class Elf(object):
    def __init__(self, filename):
        self.fileobj = open(filename, "rb")
        self.elffile = ELFFile(self.fileobj)

    def update_backend(self, backend):
        for sym in self.iter_symbols():
            backend.symbols.add(sym)

    def iter_symbols(self):
        for section in self.elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    yield Symbol(sym.name, sym["st_value"])


def load_elf(backend, filename):
    elf = Elf(filename)
    elf.update_backend(backend)
