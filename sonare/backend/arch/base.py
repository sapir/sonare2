import capstone


class BaseArch:
    def hook_load_symbol(self, sym):
        pass

    def make_disasm(self, mode=None):
        return capstone.Cs(capstone.CS_ARCH_ALL, 0)
