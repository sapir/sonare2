from .backend import Backend
from .elf_loader import load_elf


if __name__ == '__main__':
    b = Backend()
    load_elf(b, "test.so")

    print(repr(b.symbols))

    for sec in b.sections.by_addr:
        print(sec)
