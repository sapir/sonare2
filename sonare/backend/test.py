from .backend import Backend
from .elf_loader import load_elf


if __name__ == '__main__':
    b = Backend()

    load_elf(b, "test.so")

    print(f"found {len(b.symbols)} symbols")

    for sec in b.sections.iter_by_addr():
        print(sec)
