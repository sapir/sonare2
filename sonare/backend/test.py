import os
from .backend import Backend
from .loaders import load_elf
from .analysis import analyze_all


if __name__ == '__main__':
    if 1:
        filename = "test.sonare"

        existed_before = os.path.isfile(filename)

        b = Backend("test.sonare")

        if not existed_before:
            load_elf(b, "test.so")
            analyze_all(b)
    else:
        b = Backend()
        load_elf(b, "test.so")

        analyze_all(b)

    print(f"found {len(b.aliases)} aliases")
    print(f"found {len(b.functions)} functions")

    for sec in b.sections.iter_by_addr():
        print(sec)
