import capstone
from .base import BaseArch


class ArmArch(BaseArch):
    def hook_load_symbol(self, sym):
        # thumb
        if sym.start & 1:
            sym.start -= 1
            sym.end -= 1
            sym.attrs["mode"] = "thumb"

    def make_disasm(self, mode=None):
        cs_mode = capstone.CS_MODE_LITTLE_ENDIAN
        if mode == "thumb":
            cs_mode |= capstone.CS_MODE_THUMB

        cs = capstone.Cs(capstone.CS_ARCH_ARM, cs_mode)
        cs.detail = True
        return cs
