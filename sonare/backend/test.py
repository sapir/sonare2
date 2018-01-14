from .backend import Backend
from .elf_loader import load_elf


if __name__ == '__main__':
    b = Backend()
    load_elf(b, "test.so")
