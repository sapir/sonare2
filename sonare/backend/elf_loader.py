from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.constants import SH_FLAGS
from .backend import Symbol, Section


class Elf:
    def __init__(self, filename):
        self.fileobj = open(filename, "rb")
        self.elffile = ELFFile(self.fileobj)

    def update_backend(self, backend):
        for sym in self.iter_symbols():
            backend.symbols.add(sym)

        # TODO: use segments if no sections
        for section in self.elffile.iter_sections():
            if section["sh_flags"] & SH_FLAGS.SHF_ALLOC:
                name = section.name
                addr = section["sh_addr"]
                data = section.data()

                backend.sections.add(Section(addr, data, name=name))

    def iter_symbols(self):
        for section in self.elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    yield Symbol(sym.name, sym["st_value"])


def load_elf(backend, filename):
    elf = Elf(filename)
    elf.update_backend(backend)
