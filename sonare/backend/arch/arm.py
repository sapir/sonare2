from .base import BaseArch


class ArmArch(BaseArch):
    def hook_load_symbol(self, sym):
        # thumb
        if sym.start & 1:
            sym.start -= 1
            sym.end -= 1
            sym.attrs["mode"] = "thumb"
