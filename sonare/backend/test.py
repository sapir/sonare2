import os
from .backend import Backend
from .elf_loader import load_elf


if __name__ == '__main__':
    if 1:
        filename = "test.sonare"

        existed_before = os.path.isfile(filename)

        b = Backend("test.sonare")

        if not existed_before:
            load_elf(b, "test.so")
    else:
        b = Backend()
        load_elf(b, "test.so")

    print(f"found {len(b.symbols)} symbols")
    print(f"found {len(b.functions)} functions")

    for sec in b.sections.iter_by_addr():
        print(sec)
